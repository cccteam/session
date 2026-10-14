package postgres

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	"github.com/cccteam/ccc"
	"github.com/cccteam/ccc/tracer"
	"github.com/cccteam/httpio"
	"github.com/cccteam/session/internal/dbtype"
	"github.com/cccteam/session/sessioninfo"
	"github.com/georgysavva/scany/v2/pgxscan"
	"github.com/go-playground/errors/v5"
	"github.com/jackc/pgx/v5"
)

// pendingColumns are the pending sign-ins table's columns, in pendingRow's order.
const pendingColumns = `"Id", "TokenHash", "Step", "Registration", "Method", "Connection", "Subject", "Email", "EmailVerified", "IdpAmr", "Claims", ` +
	`"UserId", "Username", "Tenant", "Events", "RoleNames", "Factors", "ReturnUrl", "ProviderSessionId", "ProviderSessionIssuer", "CreatedAt", "ExpiresAt", "ConsumedAt"`

// pendingRow is a pending sign-in as the table holds it.
type pendingRow struct {
	ID                    ccc.UUID   `db:"Id"`
	TokenHash             []byte     `db:"TokenHash"`
	Step                  string     `db:"Step"`
	Registration          string     `db:"Registration"`
	Method                string     `db:"Method"`
	Connection            string     `db:"Connection"`
	Subject               string     `db:"Subject"`
	Email                 string     `db:"Email"`
	EmailVerified         bool       `db:"EmailVerified"`
	IdpAmr                []string   `db:"IdpAmr"`
	Claims                []byte     `db:"Claims"`
	UserID                *ccc.UUID  `db:"UserId"`
	Username              string     `db:"Username"`
	Tenant                string     `db:"Tenant"`
	Events                []byte     `db:"Events"`
	RoleNames             []string   `db:"RoleNames"`
	Factors               []string   `db:"Factors"`
	ReturnURL             string     `db:"ReturnUrl"`
	ProviderSessionID     *string    `db:"ProviderSessionId"`
	ProviderSessionIssuer *string    `db:"ProviderSessionIssuer"`
	CreatedAt             time.Time  `db:"CreatedAt"`
	ExpiresAt             time.Time  `db:"ExpiresAt"`
	ConsumedAt            *time.Time `db:"ConsumedAt"`
}

func (r *pendingRow) pending() (*dbtype.PendingSignIn, error) {
	var events []sessioninfo.AuthEvent
	if err := json.Unmarshal(r.Events, &events); err != nil {
		return nil, errors.Wrap(err, "json.Unmarshal()")
	}
	p := &dbtype.PendingSignIn{
		ID: r.ID, TokenHash: r.TokenHash, Step: sessioninfo.PendingReason(r.Step), Registration: r.Registration,
		Identity: sessioninfo.Identity{
			Method: sessioninfo.AuthMethod(r.Method), Connection: r.Connection, Subject: r.Subject, Email: r.Email, EmailVerified: r.EmailVerified,
			Claims: r.Claims, IDPAMR: r.IdpAmr,
		},
		Username: r.Username, Tenant: r.Tenant, Events: events, RoleNames: r.RoleNames, Factors: dbtype.AuthMethods(r.Factors),
		ReturnURL: r.ReturnURL, CreatedAt: r.CreatedAt, ExpiresAt: r.ExpiresAt, ConsumedAt: r.ConsumedAt,
	}
	if r.UserID != nil {
		p.UserID = ccc.NullUUIDFromUUID(*r.UserID)
	}
	if r.ProviderSessionID != nil {
		p.ProviderSessionID = *r.ProviderSessionID
	}
	if r.ProviderSessionIssuer != nil {
		p.ProviderSessionIssuer = *r.ProviderSessionIssuer
	}

	return p, nil
}

func (s *SessionStorageDriver) pendingTable() string {
	return pgx.Identifier{s.pendingTableName}.Sanitize()
}

// InsertPendingSignIn inserts p, created at the database's time and not consumed,
// whatever p carries.
func (s *SessionStorageDriver) InsertPendingSignIn(ctx context.Context, p *dbtype.PendingSignIn) error {
	ctx, span := tracer.Start(ctx)
	defer span.End()

	events, err := json.Marshal(p.Events)
	if err != nil {
		return errors.Wrap(err, "json.Marshal()")
	}
	var userID *ccc.UUID
	if p.UserID.Valid {
		userID = &p.UserID.UUID
	}

	query := fmt.Sprintf(`INSERT INTO %s (%s) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15, $16, $17, $18, $19, $20, now(), $21, NULL)`,
		s.pendingTable(), pendingColumns)
	if _, err := s.conn.Exec(ctx, query,
		p.ID, p.TokenHash, string(p.Step), p.Registration, string(p.Identity.Method), p.Identity.Connection, p.Identity.Subject,
		p.Identity.Email, p.Identity.EmailVerified, p.Identity.IDPAMR, []byte(p.Identity.Claims), userID, p.Username, p.Tenant,
		events, p.RoleNames, dbtype.MethodNames(p.Factors), p.ReturnURL, dbtype.OptionalString(p.ProviderSessionID), dbtype.OptionalString(p.ProviderSessionIssuer), p.ExpiresAt,
	); err != nil {
		return errors.Wrap(err, "Queryer.Exec()")
	}

	return nil
}

// PendingSignInByToken returns the pending sign-in holding tokenHash that is live at
// now: not consumed and not expired. Any other is NotFound.
func (s *SessionStorageDriver) PendingSignInByToken(ctx context.Context, tokenHash []byte, now time.Time) (*dbtype.PendingSignIn, error) {
	ctx, span := tracer.Start(ctx)
	defer span.End()

	query := fmt.Sprintf(`SELECT %s FROM %s WHERE "TokenHash" = $1 AND "ConsumedAt" IS NULL AND "ExpiresAt" > $2`, pendingColumns, s.pendingTable())

	var rows []*pendingRow
	if err := pgxscan.Select(ctx, s.conn, &rows, query, tokenHash, now); err != nil {
		return nil, errors.Wrap(err, "pgxscan.Select()")
	}
	if len(rows) == 0 {
		return nil, httpio.NewNotFoundMessage("no live pending sign-in")
	}

	return rows[0].pending()
}

// ConsumePendingSignIn marks the pending sign-in holding tokenHash consumed, at the
// database's time, when it is live at now. A pending sign-in that is not live, because
// it was consumed, has expired or does not exist, is NotFound: the update is
// conditional, so a pending sign-in is consumed once.
func (s *SessionStorageDriver) ConsumePendingSignIn(ctx context.Context, tokenHash []byte, now time.Time) error {
	ctx, span := tracer.Start(ctx)
	defer span.End()

	query := fmt.Sprintf(`UPDATE %s SET "ConsumedAt" = now() WHERE "TokenHash" = $1 AND "ConsumedAt" IS NULL AND "ExpiresAt" > $2`, s.pendingTable())
	tag, err := s.conn.Exec(ctx, query, tokenHash, now)
	if err != nil {
		return errors.Wrap(err, "Queryer.Exec()")
	}
	if tag.RowsAffected() == 0 {
		return httpio.NewNotFoundMessage("no live pending sign-in")
	}

	return nil
}
