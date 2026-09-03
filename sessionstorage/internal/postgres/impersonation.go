package postgres

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/cccteam/ccc"
	"github.com/cccteam/ccc/tracer"
	"github.com/cccteam/session/internal/dbtype"
	"github.com/cccteam/session/sessioninfo"
	"github.com/go-playground/errors/v5"
	"github.com/jackc/pgx/v5"
)

// ImpersonationConfig configures the impersonation record table for the
// PostgreSQL driver. It is populated by the public sessionstorage package from a
// validated unit; the driver performs no validation of its own.
type ImpersonationConfig struct {
	// TableName is the name of the impersonation record table.
	TableName string
}

// SetImpersonation attaches the impersonation configuration to the driver.
func (s *SessionStorageDriver) SetImpersonation(config *ImpersonationConfig) {
	s.impersonation = config
}

// ImpersonationEnabled reports whether an impersonation record table is configured.
func (s *SessionStorageDriver) ImpersonationEnabled() bool {
	return s.impersonation != nil
}

// impersonationColumns are the record's columns after the SessionId marker, in
// the order the session query selects and Session scans them.
var impersonationColumns = []string{
	"ActorUsername", "ActorRealm", "SourceSessionId", "PrincipalKind", "PrincipalUser", "PrincipalRole",
	"Mask", "Reason", "StartedAt", "ExpiresAt", "EndedAt", "EndReason",
}

// impersonationSelect renders the impersonation columns for the session query:
// i.SessionId first as the LEFT JOIN row-presence marker, then the record.
func impersonationSelect() string {
	var columns strings.Builder
	fmt.Fprintf(&columns, `, i.%s`, pgx.Identifier{dbtype.SessionIDColumn}.Sanitize())
	for _, col := range impersonationColumns {
		fmt.Fprintf(&columns, `, i.%s`, pgx.Identifier{col}.Sanitize())
	}

	return columns.String()
}

// impersonationJoin renders the LEFT JOIN of the impersonation table onto the
// session table alias s.
func (s *SessionStorageDriver) impersonationJoin() string {
	return fmt.Sprintf(`LEFT JOIN %s i ON s."Id" = i.%s`, pgx.Identifier{s.impersonation.TableName}.Sanitize(), pgx.Identifier{dbtype.SessionIDColumn}.Sanitize())
}

// impersonationScan holds the typed scan destinations for an impersonation
// record; SourceSessionId is scanned as text and parsed afterwards.
type impersonationScan struct {
	imp             *dbtype.Impersonation
	sourceSessionID *string
}

func newImpersonationScan(sessionID ccc.UUID) *impersonationScan {
	return &impersonationScan{imp: &dbtype.Impersonation{SessionID: sessionID}}
}

// dests returns the scan destinations in impersonationColumns order.
func (p *impersonationScan) dests() []any {
	return []any{
		&p.imp.ActorUsername, &p.imp.ActorRealm, &p.sourceSessionID, &p.imp.PrincipalKind, &p.imp.PrincipalUser, &p.imp.PrincipalRole,
		&p.imp.Mask, &p.imp.Reason, &p.imp.StartedAt, &p.imp.ExpiresAt, &p.imp.EndedAt, &p.imp.EndReason,
	}
}

// row returns the scanned record.
func (p *impersonationScan) row() (*dbtype.Impersonation, error) {
	if p.sourceSessionID != nil {
		id, err := ccc.UUIDFromString(*p.sourceSessionID)
		if err != nil {
			return nil, errors.Wrap(err, "ccc.UUIDFromString()")
		}
		p.imp.SourceSessionID = &id
	}

	return p.imp, nil
}

// throwaways returns NULL-safe scan destinations covering one joined row.
func throwaways(n int) []any {
	dests := make([]any, n)
	for i := range dests {
		dests[i] = new(any)
	}

	return dests
}

// InsertImpersonatedSession inserts a session row and its impersonation record
// atomically, honoring the request's custom session data semantics exactly as
// InsertSession does (per-call data, configured resolver, or neither).
func (s *SessionStorageDriver) InsertImpersonatedSession(
	ctx context.Context, insertSession *dbtype.InsertSession, req *sessioninfo.NewSessionRequest, imp *dbtype.InsertImpersonation,
) (ccc.UUID, error) {
	ctx, span := tracer.Start(ctx)
	defer span.End()

	if s.impersonation == nil {
		return ccc.NilUUID, errors.New("impersonation is not configured on the storage")
	}

	id, err := ccc.NewUUID()
	if err != nil {
		return ccc.NilUUID, errors.Wrap(err, "ccc.NewUUID()")
	}

	query := fmt.Sprintf(`
		INSERT INTO "%s"
			("Id", "Username", "CreatedAt", "UpdatedAt", "Expired")
		VALUES
			($1, $2, $3, $4, $5)
		`, s.sessionTableName)
	args := []any{id, insertSession.Username, insertSession.CreatedAt, insertSession.UpdatedAt, insertSession.Expired}

	insertRecord := func(ctx context.Context, txn pgx.Tx) error {
		return s.insertImpersonation(ctx, txn, id, imp)
	}
	if err := s.execSessionInsert(ctx, id, query, args, req, insertRecord); err != nil {
		return ccc.NilUUID, err
	}

	return id, nil
}

// insertImpersonation writes the impersonation record for a new session inside txn.
func (s *SessionStorageDriver) insertImpersonation(ctx context.Context, txn pgx.Tx, id ccc.UUID, imp *dbtype.InsertImpersonation) error {
	var sourceSessionID *string
	if imp.SourceSessionID != nil {
		v := imp.SourceSessionID.String()
		sourceSessionID = &v
	}

	query := fmt.Sprintf(`
		INSERT INTO %s
			("SessionId", "ActorUsername", "ActorRealm", "SourceSessionId", "PrincipalKind", "PrincipalUser", "PrincipalRole", "Mask", "Reason", "StartedAt", "ExpiresAt")
		VALUES
			($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11)
		`, pgx.Identifier{s.impersonation.TableName}.Sanitize())
	args := []any{
		id, imp.ActorUsername, imp.ActorRealm, sourceSessionID, imp.PrincipalKind, imp.PrincipalUser, imp.PrincipalRole,
		imp.Mask, imp.Reason, time.Now(), imp.ExpiresAt,
	}

	if _, err := txn.Exec(ctx, query, args...); err != nil {
		return errors.Wrap(err, "pgx.Tx.Exec()")
	}

	return nil
}

// EndImpersonation sets EndedAt and EndReason on the session's impersonation
// record when it exists and has not already ended; otherwise it is a no-op.
func (s *SessionStorageDriver) EndImpersonation(ctx context.Context, sessionID ccc.UUID, reason string) error {
	ctx, span := tracer.Start(ctx)
	defer span.End()

	if s.impersonation == nil {
		return errors.New("impersonation is not configured on the storage")
	}

	query := fmt.Sprintf(`
		UPDATE %s
		SET "EndedAt" = $2, "EndReason" = $3
		WHERE "SessionId" = $1 AND "EndedAt" IS NULL`, pgx.Identifier{s.impersonation.TableName}.Sanitize())

	if _, err := s.conn.Exec(ctx, query, sessionID, time.Now(), reason); err != nil {
		return errors.Wrap(err, "Queryer.Exec()")
	}

	return nil
}

// DestroyImpersonatedSessions expires every live impersonated session
// established by actor and ends their records with reason Revoked, in one
// transaction.
func (s *SessionStorageDriver) DestroyImpersonatedSessions(ctx context.Context, actor string) error {
	ctx, span := tracer.Start(ctx)
	defer span.End()

	if s.impersonation == nil {
		return errors.New("impersonation is not configured on the storage")
	}

	impTable := pgx.Identifier{s.impersonation.TableName}.Sanitize()
	expireSessions := fmt.Sprintf(`
		UPDATE "%s" s
		SET "Expired" = TRUE, "UpdatedAt" = $2
		FROM %s i
		WHERE i."SessionId" = s."Id" AND i."ActorUsername" = $1 AND i."EndedAt" IS NULL`, s.sessionTableName, impTable)
	endRecords := fmt.Sprintf(`
		UPDATE %s
		SET "EndedAt" = $2, "EndReason" = $3
		WHERE "ActorUsername" = $1 AND "EndedAt" IS NULL`, impTable)

	txn, err := s.conn.Begin(ctx)
	if err != nil {
		return errors.Wrap(err, "Queryer.Begin()")
	}
	defer func() {
		_ = txn.Rollback(ctx)
	}()

	now := time.Now()
	if _, err := txn.Exec(ctx, expireSessions, actor, now); err != nil {
		return errors.Wrap(err, "pgx.Tx.Exec()")
	}
	if _, err := txn.Exec(ctx, endRecords, actor, now, string(sessioninfo.ImpersonationEndedByRevocation)); err != nil {
		return errors.Wrap(err, "pgx.Tx.Exec()")
	}

	if err := txn.Commit(ctx); err != nil {
		return errors.Wrap(err, "pgx.Tx.Commit()")
	}

	return nil
}

// endImpersonationIfConfigured ends the session's impersonation record with
// reason when an impersonation table is configured; it is a no-op otherwise and
// for sessions that are not impersonated.
func (s *SessionStorageDriver) endImpersonationIfConfigured(ctx context.Context, sessionID ccc.UUID, reason sessioninfo.ImpersonationEndReason) error {
	if s.impersonation == nil {
		return nil
	}

	return s.EndImpersonation(ctx, sessionID, string(reason))
}
