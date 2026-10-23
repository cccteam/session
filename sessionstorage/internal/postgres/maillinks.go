package postgres

import (
	"context"
	"fmt"
	"time"

	"github.com/cccteam/ccc"
	"github.com/cccteam/ccc/tracer"
	"github.com/cccteam/httpio"
	"github.com/cccteam/session/internal/dbtype"
	"github.com/georgysavva/scany/v2/pgxscan"
	"github.com/go-playground/errors/v5"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
)

// mailLinkColumns are the mail links table's columns, in mailLinkRow's order.
const mailLinkColumns = `"Id", "TokenHash", "Kind", "Email", "UserId", "Tenant", "RoleNames", "InvitedBy", "CreatedAt", "ExpiresAt", "ConsumedAt"`

// mailLinkRow is a mail link as the table holds it.
type mailLinkRow struct {
	ID         ccc.UUID   `db:"Id"`
	TokenHash  []byte     `db:"TokenHash"`
	Kind       string     `db:"Kind"`
	Email      string     `db:"Email"`
	UserID     *ccc.UUID  `db:"UserId"`
	Tenant     *string    `db:"Tenant"`
	RoleNames  []string   `db:"RoleNames"`
	InvitedBy  *ccc.UUID  `db:"InvitedBy"`
	CreatedAt  time.Time  `db:"CreatedAt"`
	ExpiresAt  time.Time  `db:"ExpiresAt"`
	ConsumedAt *time.Time `db:"ConsumedAt"`
}

func (r *mailLinkRow) link() *dbtype.MailLink {
	l := &dbtype.MailLink{
		ID: r.ID, TokenHash: r.TokenHash, Kind: dbtype.MailLinkKind(r.Kind), Email: r.Email, RoleNames: r.RoleNames,
		CreatedAt: r.CreatedAt, ExpiresAt: r.ExpiresAt, ConsumedAt: r.ConsumedAt,
	}
	if r.UserID != nil {
		l.UserID = ccc.NullUUIDFromUUID(*r.UserID)
	}
	if r.Tenant != nil {
		l.Tenant = *r.Tenant
	}
	if r.InvitedBy != nil {
		l.InvitedBy = ccc.NullUUIDFromUUID(*r.InvitedBy)
	}

	return l
}

func (s *SessionStorageDriver) mailLinksTable() string {
	return pgx.Identifier{s.mailLinksTableName}.Sanitize()
}

// InsertMailLink inserts l, created at the database's time and not consumed, whatever l
// carries.
func (s *SessionStorageDriver) InsertMailLink(ctx context.Context, l *dbtype.MailLink) error {
	ctx, span := tracer.Start(ctx)
	defer span.End()

	if err := l.Kind.Validate(); err != nil {
		return errors.Wrap(err, "dbtype.MailLinkKind.Validate()")
	}
	var userID, invitedBy *ccc.UUID
	if l.UserID.Valid {
		userID = &l.UserID.UUID
	}
	if l.InvitedBy.Valid {
		invitedBy = &l.InvitedBy.UUID
	}
	query := fmt.Sprintf(`INSERT INTO %s (%s) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, now(), $9, NULL)`, s.mailLinksTable(), mailLinkColumns)
	if _, err := s.conn.Exec(ctx, query, l.ID, l.TokenHash, string(l.Kind), l.Email, userID, dbtype.OptionalString(l.Tenant), l.RoleNames, invitedBy, l.ExpiresAt); err != nil {
		return errors.Wrap(err, "Queryer.Exec()")
	}

	return nil
}

// queryMailLinks runs query and renders its rows.
func (s *SessionStorageDriver) queryMailLinks(ctx context.Context, query string, args ...any) ([]*dbtype.MailLink, error) {
	var rows []*mailLinkRow
	if err := pgxscan.Select(ctx, s.conn, &rows, query, args...); err != nil {
		return nil, errors.Wrap(err, "pgxscan.Select()")
	}
	links := make([]*dbtype.MailLink, len(rows))
	for i, r := range rows {
		links[i] = r.link()
	}

	return links, nil
}

// MailLinkByToken returns the mail link holding tokenHash that is live at now: not
// consumed and not expired. Any other is NotFound.
func (s *SessionStorageDriver) MailLinkByToken(ctx context.Context, tokenHash []byte, now time.Time) (*dbtype.MailLink, error) {
	ctx, span := tracer.Start(ctx)
	defer span.End()

	query := fmt.Sprintf(`SELECT %s FROM %s WHERE "TokenHash" = $1 AND "ConsumedAt" IS NULL AND "ExpiresAt" > $2`, mailLinkColumns, s.mailLinksTable())
	links, err := s.queryMailLinks(ctx, query, tokenHash, now)
	if err != nil {
		return nil, err
	}
	if len(links) == 0 {
		return nil, httpio.NewNotFoundMessage("no live mail link")
	}

	return links[0], nil
}

// LiveMailLinks lists the links of kind that are live at now, oldest first.
func (s *SessionStorageDriver) LiveMailLinks(ctx context.Context, kind dbtype.MailLinkKind, now time.Time) ([]*dbtype.MailLink, error) {
	ctx, span := tracer.Start(ctx)
	defer span.End()

	query := fmt.Sprintf(`SELECT %s FROM %s WHERE "Kind" = $1 AND "ConsumedAt" IS NULL AND "ExpiresAt" > $2 ORDER BY "CreatedAt", "Id"`, mailLinkColumns, s.mailLinksTable())

	return s.queryMailLinks(ctx, query, string(kind), now)
}

// ConsumeMailLink marks the mail link holding tokenHash consumed, at the database's
// time, when it is live at now. A link that is not live, because it was consumed, has
// expired or does not exist, is NotFound: the update is conditional, so a link is
// consumed once.
func (s *SessionStorageDriver) ConsumeMailLink(ctx context.Context, tokenHash []byte, now time.Time) error {
	ctx, span := tracer.Start(ctx)
	defer span.End()

	return s.consumeMailLink(ctx, s.conn, `"TokenHash"`, tokenHash, now)
}

// RevokeMailLink marks the live mail link id consumed, as ConsumeMailLink does by the
// token: an invitation withdrawn by hand. A link that is not live is NotFound.
func (s *SessionStorageDriver) RevokeMailLink(ctx context.Context, id ccc.UUID, now time.Time) error {
	ctx, span := tracer.Start(ctx)
	defer span.End()

	return s.consumeMailLink(ctx, s.conn, `"Id"`, id, now)
}

// ConsumeMailLinkIn consumes the live mail link id inside tx, at the transaction's
// time. A link that is not live is NotFound, and the transaction may go on.
func (s *SessionStorageDriver) ConsumeMailLinkIn(ctx context.Context, tx pgx.Tx, id ccc.UUID, now time.Time) error {
	return s.consumeMailLink(ctx, tx, `"Id"`, id, now)
}

// execer runs one statement: the pool, or a transaction.
type execer interface {
	Exec(ctx context.Context, sql string, arguments ...any) (pgconn.CommandTag, error)
}

func (s *SessionStorageDriver) consumeMailLink(ctx context.Context, q execer, column string, value any, now time.Time) error {
	query := fmt.Sprintf(`UPDATE %s SET "ConsumedAt" = now() WHERE %s = $1 AND "ConsumedAt" IS NULL AND "ExpiresAt" > $2`, s.mailLinksTable(), column)
	tag, err := q.Exec(ctx, query, value, now)
	if err != nil {
		return errors.Wrap(err, "Exec()")
	}
	if tag.RowsAffected() == 0 {
		return httpio.NewNotFoundMessage("no live mail link")
	}

	return nil
}
