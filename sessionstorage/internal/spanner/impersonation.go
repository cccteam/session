package spanner

import (
	"context"
	"fmt"
	"strings"
	"time"

	"cloud.google.com/go/spanner"
	"github.com/cccteam/ccc"
	"github.com/cccteam/ccc/tracer"
	"github.com/cccteam/session/internal/dbtype"
	"github.com/cccteam/session/sessioninfo"
	"github.com/go-playground/errors/v5"
)

// ImpersonationConfig configures the impersonation record table for the Spanner
// driver. It is populated by the public sessionstorage package from a validated
// unit; the driver performs no validation of its own.
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

// The impersonation record's end columns, written by EndImpersonation and its callers.
const (
	endedAtColumn   = "EndedAt"
	endReasonColumn = "EndReason"
)

// impersonationColumns are the record's columns after the SessionId marker, in
// the order the session query selects and Session reads them.
var impersonationColumns = []string{
	"ActorUsername", "ActorRealm", "SourceSessionId", "PrincipalKind", "PrincipalUser", "PrincipalRole",
	"Mask", "Reason", "StartedAt", "ExpiresAt", endedAtColumn, endReasonColumn,
}

// impersonationSelect renders the impersonation columns for the session query:
// i.SessionId first as the LEFT JOIN row-presence marker, then the record.
func impersonationSelect() string {
	var columns strings.Builder
	fmt.Fprintf(&columns, ", i.%s", dbtype.SessionIDColumn)
	for _, col := range impersonationColumns {
		fmt.Fprintf(&columns, ", i.%s", col)
	}

	return columns.String()
}

// impersonationJoin renders the LEFT JOIN of the impersonation table onto the
// session table alias s.
func (s *SessionStorageDriver) impersonationJoin() string {
	return fmt.Sprintf("LEFT JOIN `%s` i ON s.Id = i.%s", s.impersonation.TableName, dbtype.SessionIDColumn)
}

// readImpersonation reads the impersonation record from row positionally,
// starting at the marker column idx. It returns nil when the LEFT JOIN found
// no record.
func readImpersonation(row *spanner.Row, idx int, sessionID ccc.UUID) (*dbtype.Impersonation, error) {
	var marker spanner.NullString
	if err := row.Column(idx, &marker); err != nil {
		return nil, errors.Wrapf(err, "row.Column(%d/%s)", idx, dbtype.SessionIDColumn)
	}
	idx++

	if !marker.Valid {
		return nil, nil
	}

	var (
		actorRealm, sourceSessionID, principalUser, principalRole, mask, reason, endReason spanner.NullString
		endedAt                                                                            spanner.NullTime
	)
	imp := &dbtype.Impersonation{SessionID: sessionID}
	dests := []any{
		&imp.ActorUsername, &actorRealm, &sourceSessionID, &imp.PrincipalKind, &principalUser, &principalRole,
		&mask, &reason, &imp.StartedAt, &imp.ExpiresAt, &endedAt, &endReason,
	}
	for i, dest := range dests {
		if err := row.Column(idx, dest); err != nil {
			return nil, errors.Wrapf(err, "row.Column(%d/%s)", idx, impersonationColumns[i])
		}
		idx++
	}

	imp.ActorRealm = nullStringPtr(actorRealm)
	imp.PrincipalUser = nullStringPtr(principalUser)
	imp.PrincipalRole = nullStringPtr(principalRole)
	imp.Mask = nullStringPtr(mask)
	imp.Reason = nullStringPtr(reason)
	imp.EndReason = nullStringPtr(endReason)
	if sourceSessionID.Valid {
		id, err := ccc.UUIDFromString(sourceSessionID.StringVal)
		if err != nil {
			return nil, errors.Wrap(err, "ccc.UUIDFromString()")
		}
		imp.SourceSessionID = &id
	}
	if endedAt.Valid {
		t := endedAt.Time
		imp.EndedAt = &t
	}

	return imp, nil
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

	session := &struct {
		ID ccc.UUID
		*dbtype.InsertSession
	}{
		ID:            id,
		InsertSession: insertSession,
	}

	sessionMutation, err := spanner.InsertStruct(s.sessionTableName, session)
	if err != nil {
		return ccc.NilUUID, errors.Wrap(err, "spanner.InsertStruct()")
	}

	impMutation := spanner.InsertMap(s.impersonation.TableName, impersonationRow(id, imp))

	if err := s.applySessionInsert(ctx, id, []*spanner.Mutation{sessionMutation, impMutation}, req); err != nil {
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

	session := &struct {
		ID ccc.UUID
		*dbtype.InsertOIDCSession
	}{
		ID:                id,
		InsertOIDCSession: insertSession,
	}

	sessionMutation, err := spanner.InsertStruct(s.sessionTableName, session)
	if err != nil {
		return ccc.NilUUID, errors.Wrap(err, "spanner.InsertStruct()")
	}

	impMutation := spanner.InsertMap(s.impersonation.TableName, impersonationRow(id, imp))

	if err := s.applySessionInsert(ctx, id, []*spanner.Mutation{sessionMutation, impMutation}, req); err != nil {
		return ccc.NilUUID, err
	}

	return id, nil
}

// impersonationRow renders the full impersonation record row for a new session.
func impersonationRow(id ccc.UUID, imp *dbtype.InsertImpersonation) map[string]any {
	var sourceSessionID spanner.NullString
	if imp.SourceSessionID != nil {
		sourceSessionID = spanner.NullString{StringVal: imp.SourceSessionID.String(), Valid: true}
	}

	return map[string]any{
		dbtype.SessionIDColumn: id,
		"ActorUsername":        imp.ActorUsername,
		"ActorRealm":           nullString(imp.ActorRealm),
		"SourceSessionId":      sourceSessionID,
		"PrincipalKind":        imp.PrincipalKind,
		"PrincipalUser":        nullString(imp.PrincipalUser),
		"PrincipalRole":        nullString(imp.PrincipalRole),
		"Mask":                 nullString(imp.Mask),
		"Reason":               nullString(imp.Reason),
		"StartedAt":            time.Now(),
		"ExpiresAt":            imp.ExpiresAt,
		endedAtColumn:          spanner.NullTime{},
		endReasonColumn:        spanner.NullString{},
	}
}

// EndImpersonation sets EndedAt and EndReason on the session's impersonation
// record when it exists and has not already ended; otherwise it is a no-op.
func (s *SessionStorageDriver) EndImpersonation(ctx context.Context, sessionID ccc.UUID, reason string) error {
	ctx, span := tracer.Start(ctx)
	defer span.End()

	if s.impersonation == nil {
		return errors.New("impersonation is not configured on the storage")
	}

	stmt := spanner.NewStatement(fmt.Sprintf(`
			UPDATE %s
			SET EndedAt = @endedAt, EndReason = @reason
			WHERE SessionId = @id AND EndedAt IS NULL
	`, s.impersonation.TableName))
	stmt.Params["id"] = sessionID
	stmt.Params["endedAt"] = time.Now()
	stmt.Params["reason"] = reason

	_, err := s.spanner.ReadWriteTransaction(ctx, func(ctx context.Context, txn *spanner.ReadWriteTransaction) error {
		if _, err := txn.Update(ctx, stmt); err != nil {
			return errors.Wrap(err, "spanner.ReadWriteTransaction.Update()")
		}

		return nil
	})
	if err != nil {
		return errors.Wrap(err, "spanner.Client.ReadWriteTransaction()")
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

	now := time.Now()

	expireSessions := spanner.NewStatement(fmt.Sprintf(`
			UPDATE %s
			SET Expired = TRUE, UpdatedAt = @now
			WHERE Id IN (
				SELECT SessionId FROM %s WHERE ActorUsername = @actor AND EndedAt IS NULL
			)
	`, s.sessionTableName, s.impersonation.TableName))
	expireSessions.Params["actor"] = actor
	expireSessions.Params["now"] = now

	endRecords := spanner.NewStatement(fmt.Sprintf(`
			UPDATE %s
			SET EndedAt = @now, EndReason = @reason
			WHERE ActorUsername = @actor AND EndedAt IS NULL
	`, s.impersonation.TableName))
	endRecords.Params["actor"] = actor
	endRecords.Params["now"] = now
	endRecords.Params["reason"] = string(sessioninfo.ImpersonationEndedByRevocation)

	_, err := s.spanner.ReadWriteTransaction(ctx, func(ctx context.Context, txn *spanner.ReadWriteTransaction) error {
		if _, err := txn.BatchUpdate(ctx, []spanner.Statement{expireSessions, endRecords}); err != nil {
			return errors.Wrap(err, "spanner.ReadWriteTransaction.BatchUpdate()")
		}

		return nil
	})
	if err != nil {
		return errors.Wrap(err, "spanner.Client.ReadWriteTransaction()")
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

	now := time.Now()

	expireSession := spanner.NewStatement(fmt.Sprintf(`
			UPDATE %s
			SET Expired = TRUE, UpdatedAt = @now
			WHERE Id = @id AND Id IN (
				SELECT SessionId FROM %s WHERE SessionId = @id AND EndedAt IS NULL
			)
	`, s.sessionTableName, s.impersonation.TableName))
	expireSession.Params["id"] = sessionID
	expireSession.Params["now"] = now

	endRecord := spanner.NewStatement(fmt.Sprintf(`
			UPDATE %s
			SET EndedAt = @now, EndReason = @reason
			WHERE SessionId = @id AND EndedAt IS NULL
	`, s.impersonation.TableName))
	endRecord.Params["id"] = sessionID
	endRecord.Params["now"] = now
	endRecord.Params["reason"] = reason

	_, err := s.spanner.ReadWriteTransaction(ctx, func(ctx context.Context, txn *spanner.ReadWriteTransaction) error {
		if _, err := txn.BatchUpdate(ctx, []spanner.Statement{expireSession, endRecord}); err != nil {
			return errors.Wrap(err, "spanner.ReadWriteTransaction.BatchUpdate()")
		}

		return nil
	})
	if err != nil {
		return errors.Wrap(err, "spanner.Client.ReadWriteTransaction()")
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

func nullString(s *string) spanner.NullString {
	if s == nil {
		return spanner.NullString{}
	}

	return spanner.NullString{StringVal: *s, Valid: true}
}

func nullStringPtr(s spanner.NullString) *string {
	if !s.Valid {
		return nil
	}
	v := s.StringVal

	return &v
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
	fmt.Fprintf(&columns, "i.%s", dbtype.SessionIDColumn)
	for _, col := range impersonationColumns {
		fmt.Fprintf(&columns, ", i.%s", col)
	}

	params := map[string]any{"now": time.Now(), "activeSince": activeSince}
	var filters strings.Builder
	if q.Actor != "" {
		params["actor"] = q.Actor
		filters.WriteString(" AND i.ActorUsername = @actor")
	}
	if role, ok := q.Principal.Role(); ok {
		params["kind"], params["principal"] = dbtype.PrincipalKindRole, string(role)
		filters.WriteString(" AND i.PrincipalKind = @kind AND i.PrincipalRole = @principal")
	} else if user, _ := q.Principal.User(); user != "" {
		params["kind"], params["principal"] = dbtype.PrincipalKindUser, string(user)
		filters.WriteString(" AND i.PrincipalKind = @kind AND i.PrincipalUser = @principal")
	}

	stmt := spanner.NewStatement(fmt.Sprintf(`
			SELECT %s
			FROM %s i
			JOIN %s s ON s.Id = i.SessionId
			WHERE i.EndedAt IS NULL AND i.ExpiresAt > @now AND s.Expired = FALSE AND s.UpdatedAt > @activeSince%s
			ORDER BY i.StartedAt DESC
	`, columns.String(), s.impersonation.TableName, s.sessionTableName, filters.String()))
	stmt.Params = params

	imps := []*dbtype.Impersonation{}
	err := s.spanner.Single().Query(ctx, stmt).Do(func(row *spanner.Row) error {
		var sessionID string
		if err := row.Column(0, &sessionID); err != nil {
			return errors.Wrapf(err, "row.Column(0/%s)", dbtype.SessionIDColumn)
		}
		id, err := ccc.UUIDFromString(sessionID)
		if err != nil {
			return errors.Wrap(err, "ccc.UUIDFromString()")
		}
		imp, err := readImpersonation(row, 0, id)
		if err != nil {
			return err
		}
		imps = append(imps, imp)

		return nil
	})
	if err != nil {
		return nil, errors.Wrap(err, "spanner.RowIterator.Do()")
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

	return fmt.Sprintf("EXISTS (SELECT 1 FROM %s r WHERE r.SessionId = s.Id AND r.PrincipalKind = '%s' AND r.ActorRealm IS NOT NULL AND r.EndedAt IS NULL)",
		s.impersonation.TableName, dbtype.PrincipalKindRole)
}

// heldByLocalActor is a predicate over session alias s with the username bound to
// @username: the session carries a live record established by that name as a local actor.
func (s *SessionStorageDriver) heldByLocalActor() string {
	if s.impersonation == nil {
		return "FALSE"
	}

	return fmt.Sprintf("EXISTS (SELECT 1 FROM %s r WHERE r.SessionId = s.Id AND r.ActorUsername = @username AND r.ActorRealm IS NULL AND r.EndedAt IS NULL)",
		s.impersonation.TableName)
}
