package spanner

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	"cloud.google.com/go/spanner"
	"github.com/cccteam/ccc"
	"github.com/cccteam/ccc/tracer"
	"github.com/cccteam/httpio"
	"github.com/cccteam/session/internal/dbtype"
	"github.com/cccteam/session/sessioninfo"
	"github.com/go-playground/errors/v5"
	"google.golang.org/api/iterator"
)

// pendingColumns are the pending sign-ins table's columns.
const pendingColumns = `Id, TokenHash, Step, Registration, Method, Connection, Subject, Email, EmailVerified, IdpAmr, Claims, SignInName, Guest, ` +
	`UserId, Username, Tenant, Events, RoleNames, Factors, ReturnUrl, ProviderSessionId, ProviderSessionIssuer, CreatedAt, ExpiresAt, ConsumedAt`

// pendingRow is a pending sign-in as the table holds it.
type pendingRow struct {
	ID                    string             `spanner:"Id"`
	TokenHash             []byte             `spanner:"TokenHash"`
	Step                  string             `spanner:"Step"`
	Registration          string             `spanner:"Registration"`
	Method                string             `spanner:"Method"`
	Connection            string             `spanner:"Connection"`
	Subject               string             `spanner:"Subject"`
	Email                 string             `spanner:"Email"`
	EmailVerified         bool               `spanner:"EmailVerified"`
	IdpAmr                []string           `spanner:"IdpAmr"`
	Claims                []byte             `spanner:"Claims"`
	SignInName            string             `spanner:"SignInName"`
	Guest                 bool               `spanner:"Guest"`
	UserID                spanner.NullString `spanner:"UserId"`
	Username              string             `spanner:"Username"`
	Tenant                string             `spanner:"Tenant"`
	Events                []byte             `spanner:"Events"`
	RoleNames             []string           `spanner:"RoleNames"`
	Factors               []string           `spanner:"Factors"`
	ReturnURL             string             `spanner:"ReturnUrl"`
	ProviderSessionID     spanner.NullString `spanner:"ProviderSessionId"`
	ProviderSessionIssuer spanner.NullString `spanner:"ProviderSessionIssuer"`
	CreatedAt             time.Time          `spanner:"CreatedAt"`
	ExpiresAt             time.Time          `spanner:"ExpiresAt"`
	ConsumedAt            spanner.NullTime   `spanner:"ConsumedAt"`
}

// newPendingRow renders p as the table holds it: created at the commit time and not
// consumed, whatever p carries.
func newPendingRow(p *dbtype.PendingSignIn) (*pendingRow, error) {
	events, err := json.Marshal(p.Events)
	if err != nil {
		return nil, errors.Wrap(err, "json.Marshal()")
	}
	r := &pendingRow{
		ID: p.ID.String(), TokenHash: p.TokenHash, Step: string(p.Step), Registration: p.Registration,
		Method: string(p.Identity.Method), Connection: p.Identity.Connection, Subject: p.Identity.Subject, Email: p.Identity.Email,
		EmailVerified: p.Identity.EmailVerified, IdpAmr: p.Identity.IDPAMR, Claims: []byte(p.Identity.Claims), SignInName: p.Identity.SignInName, Guest: p.Identity.Guest,
		Username: p.Username, Tenant: p.Tenant, Events: events, RoleNames: p.RoleNames, Factors: dbtype.MethodNames(p.Factors),
		ReturnURL: p.ReturnURL, CreatedAt: spanner.CommitTimestamp, ExpiresAt: p.ExpiresAt,
	}
	if p.UserID.Valid {
		r.UserID = spanner.NullString{StringVal: p.UserID.String(), Valid: true}
	}
	if p.ProviderSessionID != "" {
		r.ProviderSessionID = spanner.NullString{StringVal: p.ProviderSessionID, Valid: true}
	}
	if p.ProviderSessionIssuer != "" {
		r.ProviderSessionIssuer = spanner.NullString{StringVal: p.ProviderSessionIssuer, Valid: true}
	}

	return r, nil
}

func (r *pendingRow) pending() (*dbtype.PendingSignIn, error) {
	id, err := ccc.UUIDFromString(r.ID)
	if err != nil {
		return nil, errors.Wrap(err, "ccc.UUIDFromString()")
	}
	var events []sessioninfo.AuthEvent
	if err := json.Unmarshal(r.Events, &events); err != nil {
		return nil, errors.Wrap(err, "json.Unmarshal()")
	}
	p := &dbtype.PendingSignIn{
		ID: id, TokenHash: r.TokenHash, Step: sessioninfo.PendingReason(r.Step), Registration: r.Registration,
		Identity: sessioninfo.Identity{
			Method: sessioninfo.AuthMethod(r.Method), Connection: r.Connection, Subject: r.Subject, Email: r.Email, EmailVerified: r.EmailVerified,
			Claims: r.Claims, IDPAMR: r.IdpAmr, SignInName: r.SignInName, Guest: r.Guest,
		},
		Username: r.Username, Tenant: r.Tenant, Events: events, RoleNames: r.RoleNames, Factors: dbtype.AuthMethods(r.Factors),
		ReturnURL: r.ReturnURL, CreatedAt: r.CreatedAt, ExpiresAt: r.ExpiresAt,
	}
	if r.UserID.Valid {
		userID, err := ccc.UUIDFromString(r.UserID.StringVal)
		if err != nil {
			return nil, errors.Wrap(err, "ccc.UUIDFromString()")
		}
		p.UserID = ccc.NullUUIDFromUUID(userID)
	}
	if r.ProviderSessionID.Valid {
		p.ProviderSessionID = r.ProviderSessionID.StringVal
	}
	if r.ProviderSessionIssuer.Valid {
		p.ProviderSessionIssuer = r.ProviderSessionIssuer.StringVal
	}
	if r.ConsumedAt.Valid {
		consumedAt := r.ConsumedAt.Time
		p.ConsumedAt = &consumedAt
	}

	return p, nil
}

// InsertPendingSignIn inserts p.
func (s *SessionStorageDriver) InsertPendingSignIn(ctx context.Context, p *dbtype.PendingSignIn) error {
	ctx, span := tracer.Start(ctx)
	defer span.End()

	row, err := newPendingRow(p)
	if err != nil {
		return err
	}
	m, err := spanner.InsertStruct(s.pendingTableName, row)
	if err != nil {
		return errors.Wrap(err, "spanner.InsertStruct()")
	}
	if _, err := s.spanner.Apply(ctx, []*spanner.Mutation{m}); err != nil {
		return errors.Wrap(err, "spanner.Client.Apply()")
	}

	return nil
}

// PendingSignInByToken returns the pending sign-in holding tokenHash that is live at
// now: not consumed and not expired. Any other is NotFound.
func (s *SessionStorageDriver) PendingSignInByToken(ctx context.Context, tokenHash []byte, now time.Time) (*dbtype.PendingSignIn, error) {
	ctx, span := tracer.Start(ctx)
	defer span.End()

	stmt := spanner.NewStatement(fmt.Sprintf(`SELECT %s FROM %s WHERE TokenHash = @tokenHash AND ConsumedAt IS NULL AND ExpiresAt > @now`, pendingColumns, s.pendingTableName))
	stmt.Params["tokenHash"] = tokenHash
	stmt.Params["now"] = now

	iter := s.spanner.Single().Query(ctx, stmt)
	defer iter.Stop()

	row, err := iter.Next()
	if err != nil {
		if errors.Is(err, iterator.Done) {
			return nil, httpio.NewNotFoundMessage("no live pending sign-in")
		}

		return nil, errors.Wrap(err, "spanner.RowIterator.Next()")
	}
	var r pendingRow
	if err := row.ToStruct(&r); err != nil {
		return nil, errors.Wrap(err, "spanner.Row.ToStruct()")
	}

	return r.pending()
}

// errPendingNotLive is the transaction's signal that the conditional update changed no
// row.
var errPendingNotLive = errors.New("no live pending sign-in")

// ConsumePendingSignIn marks the pending sign-in holding tokenHash consumed, at the
// commit time, when it is live at now. A pending sign-in that is not live, because it
// was consumed, has expired or does not exist, is NotFound: the update is conditional,
// so a pending sign-in is consumed once.
func (s *SessionStorageDriver) ConsumePendingSignIn(ctx context.Context, tokenHash []byte, now time.Time) error {
	ctx, span := tracer.Start(ctx)
	defer span.End()

	stmt := spanner.NewStatement(fmt.Sprintf(`UPDATE %s SET ConsumedAt = PENDING_COMMIT_TIMESTAMP() WHERE TokenHash = @tokenHash AND ConsumedAt IS NULL AND ExpiresAt > @now`, s.pendingTableName))
	stmt.Params["tokenHash"] = tokenHash
	stmt.Params["now"] = now

	_, err := s.spanner.ReadWriteTransaction(ctx, func(ctx context.Context, txn *spanner.ReadWriteTransaction) error {
		n, err := txn.Update(ctx, stmt)
		if err != nil {
			return errors.Wrap(err, "spanner.ReadWriteTransaction.Update()")
		}
		if n == 0 {
			return errPendingNotLive
		}

		return nil
	})
	if errors.Is(err, errPendingNotLive) {
		return httpio.NewNotFoundMessage("no live pending sign-in")
	}
	if err != nil {
		return errors.Wrap(err, "spanner.Client.ReadWriteTransaction()")
	}

	return nil
}
