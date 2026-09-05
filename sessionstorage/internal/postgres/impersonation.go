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

// InsertImpersonatedSessionOIDC inserts an OIDC session row (OidcSid included) and its
// impersonation record atomically, with the same custom session data semantics as
// InsertImpersonatedSession. The OIDC user anchor is not touched: an impersonated
// session authenticates no claims, so there is nothing to upsert.
func (s *SessionStorageDriver) InsertImpersonatedSessionOIDC(
	ctx context.Context, insertSession *dbtype.InsertOIDCSession, req *sessioninfo.NewSessionRequest, imp *dbtype.InsertImpersonation,
) (ccc.UUID, error) {
	ctx, span := tracer.Start(ctx)
	defer span.End()

	if s.googleOIDC {
		return ccc.NilUUID, errors.New("InsertImpersonatedSessionOIDC called on a Google OIDC storage driver")
	}
	if s.impersonation == nil {
		return ccc.NilUUID, errors.New("impersonation is not configured on the storage")
	}

	id, err := ccc.NewUUID()
	if err != nil {
		return ccc.NilUUID, errors.Wrap(err, "ccc.NewUUID()")
	}

	query := fmt.Sprintf(`
		INSERT INTO "%s"
			("Id", "OidcSid", "Username", "CreatedAt", "UpdatedAt", "Expired")
		VALUES
			($1, $2, $3, $4, $5, $6)
		`, s.sessionTableName)
	args := []any{id, insertSession.OidcSID, insertSession.Username, insertSession.CreatedAt, insertSession.UpdatedAt, insertSession.Expired}

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
		imp.Mask, imp.Reason, imp.StartedAt, imp.ExpiresAt,
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

// DestroyImpersonatedSession expires one live impersonated session and ends its
// record with reason, in one transaction. A session with no live record (not
// impersonated, or already ended) is left untouched.
func (s *SessionStorageDriver) DestroyImpersonatedSession(ctx context.Context, sessionID ccc.UUID, reason string) error {
	ctx, span := tracer.Start(ctx)
	defer span.End()

	if s.impersonation == nil {
		return errors.New("impersonation is not configured on the storage")
	}

	impTable := pgx.Identifier{s.impersonation.TableName}.Sanitize()
	expireSession := fmt.Sprintf(`
		UPDATE "%s" s
		SET "Expired" = TRUE, "UpdatedAt" = $2
		FROM %s i
		WHERE i."SessionId" = s."Id" AND s."Id" = $1 AND i."EndedAt" IS NULL`, s.sessionTableName, impTable)
	endRecord := fmt.Sprintf(`
		UPDATE %s
		SET "EndedAt" = $2, "EndReason" = $3
		WHERE "SessionId" = $1 AND "EndedAt" IS NULL`, impTable)

	txn, err := s.conn.Begin(ctx)
	if err != nil {
		return errors.Wrap(err, "Queryer.Begin()")
	}
	defer func() {
		_ = txn.Rollback(ctx)
	}()

	now := time.Now()
	if _, err := txn.Exec(ctx, expireSession, sessionID, now); err != nil {
		return errors.Wrap(err, "pgx.Tx.Exec()")
	}
	if _, err := txn.Exec(ctx, endRecord, sessionID, now, reason); err != nil {
		return errors.Wrap(err, "pgx.Tx.Exec()")
	}

	if err := txn.Commit(ctx); err != nil {
		return errors.Wrap(err, "pgx.Tx.Commit()")
	}

	return nil
}

// ActiveImpersonations lists live impersonation records joined to their session
// rows, newest first: record not ended, hard cap not passed, session not expired,
// and session UpdatedAt after activeSince; q narrows by actor and/or principal.
func (s *SessionStorageDriver) ActiveImpersonations(ctx context.Context, activeSince time.Time, q *sessioninfo.ImpersonationQuery) ([]*dbtype.Impersonation, error) {
	ctx, span := tracer.Start(ctx)
	defer span.End()

	if s.impersonation == nil {
		return nil, errors.New("impersonation is not configured on the storage")
	}
	if q == nil {
		q = &sessioninfo.ImpersonationQuery{}
	}

	var columns strings.Builder
	fmt.Fprintf(&columns, `i.%s`, pgx.Identifier{dbtype.SessionIDColumn}.Sanitize())
	for _, col := range impersonationColumns {
		fmt.Fprintf(&columns, `, i.%s`, pgx.Identifier{col}.Sanitize())
	}

	args := []any{time.Now(), activeSince}
	var filters strings.Builder
	if q.Actor != "" {
		args = append(args, q.Actor)
		fmt.Fprintf(&filters, ` AND i."ActorUsername" = $%d`, len(args))
	}
	if role, ok := q.Principal.Role(); ok {
		args = append(args, dbtype.PrincipalKindRole, string(role))
		fmt.Fprintf(&filters, ` AND i."PrincipalKind" = $%d AND i."PrincipalRole" = $%d`, len(args)-1, len(args))
	} else if user, _ := q.Principal.User(); user != "" {
		args = append(args, dbtype.PrincipalKindUser, string(user))
		fmt.Fprintf(&filters, ` AND i."PrincipalKind" = $%d AND i."PrincipalUser" = $%d`, len(args)-1, len(args))
	}

	query := fmt.Sprintf(`
		SELECT %s
		FROM %s i
		JOIN "%s" s ON s."Id" = i."SessionId"
		WHERE i."EndedAt" IS NULL AND i."ExpiresAt" > $1 AND s."Expired" = FALSE AND s."UpdatedAt" > $2%s
		ORDER BY i."StartedAt" DESC`, columns.String(), pgx.Identifier{s.impersonation.TableName}.Sanitize(), s.sessionTableName, filters.String())

	rows, err := s.conn.Query(ctx, query, args...)
	if err != nil {
		return nil, errors.Wrap(err, "Queryer.Query()")
	}
	defer rows.Close()

	imps := []*dbtype.Impersonation{}
	for rows.Next() {
		scan := newImpersonationScan(ccc.NilUUID)
		dests := append([]any{&scan.imp.SessionID}, scan.dests()...)
		if err := rows.Scan(dests...); err != nil {
			return nil, errors.Wrap(err, "rows.Scan()")
		}
		imp, err := scan.row()
		if err != nil {
			return nil, err
		}
		imps = append(imps, imp)
	}
	if err := rows.Err(); err != nil {
		return nil, errors.Wrap(err, "rows.Err()")
	}

	return imps, nil
}

// liveRolePrincipalRecord renders an EXISTS predicate, over the session alias s, that is
// true when the session carries a live role-principal impersonation record. FALSE when
// no impersonation table is configured, so username-keyed statements can embed it
// unconditionally.
// foreignRolePrincipalRecord is a predicate over session alias s: the session carries a
// live role-principal record whose actor was authenticated by another application. Its
// username is that actor's, borrowed, not an account of this application's.
func (s *SessionStorageDriver) foreignRolePrincipalRecord() string {
	if s.impersonation == nil {
		return "FALSE"
	}

	return fmt.Sprintf(`EXISTS (SELECT 1 FROM %s r WHERE r."SessionId" = s."Id" AND r."PrincipalKind" = '%s' AND r."ActorRealm" IS NOT NULL AND r."EndedAt" IS NULL)`,
		pgx.Identifier{s.impersonation.TableName}.Sanitize(), dbtype.PrincipalKindRole)
}

// heldByLocalActor is a predicate over session alias s with the username bound to $1:
// the session carries a live record established by that name as a local actor.
func (s *SessionStorageDriver) heldByLocalActor() string {
	if s.impersonation == nil {
		return "FALSE"
	}

	return fmt.Sprintf(`EXISTS (SELECT 1 FROM %s r WHERE r."SessionId" = s."Id" AND r."ActorUsername" = $1 AND r."ActorRealm" IS NULL AND r."EndedAt" IS NULL)`,
		pgx.Identifier{s.impersonation.TableName}.Sanitize())
}
