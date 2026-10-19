package spanner

import (
	"context"
	"fmt"
	"time"

	"cloud.google.com/go/spanner"
	"github.com/cccteam/ccc"
	"github.com/cccteam/ccc/tracer"
	"github.com/cccteam/session/internal/dbtype"
	"github.com/cccteam/session/sessioninfo"
	"github.com/go-playground/errors/v5"
)

// AuthEventsConfig configures the auth events table for the Spanner driver. It is
// populated by the public sessionstorage package from a validated unit; the driver
// performs no validation of its own.
type AuthEventsConfig struct {
	// TableName is the name of the auth events table.
	TableName string
}

// EnableAuth enables the auth schema's session columns, UserId and
// AuthenticatedAt. Non-OIDC session inserts write them and session reads return them.
// Without it the driver never names those columns, so a legacy session table keeps
// working.
func (s *SessionStorageDriver) EnableAuth() {
	s.users = true
}

// AuthEnabled reports whether the auth schema's session columns are enabled.
func (s *SessionStorageDriver) AuthEnabled() bool {
	return s.users
}

// SetAuthEvents attaches the auth events table. New sessions record their auth events,
// and session reads return them oldest first.
func (s *SessionStorageDriver) SetAuthEvents(config *AuthEventsConfig) {
	s.authEvents = config
}

// AuthEventsEnabled reports whether an auth events table is configured.
func (s *SessionStorageDriver) AuthEventsEnabled() bool {
	return s.authEvents != nil
}

// The session row's "when" columns are commit timestamps: every write sets them to
// spanner.CommitTimestamp (a mutation) or PENDING_COMMIT_TIMESTAMP() (DML), and Spanner
// stamps the row with the commit time. The application clock never reaches them, so a
// clock that runs ahead of Spanner's cannot be refused as a timestamp in the future.
// The columns must carry allow_commit_timestamp = true (schema/spanner).

// commitTime renders a "when" value: t as given, or the commit timestamp when t is
// zero, so the database stamps the row with its own time.
func commitTime(t time.Time) time.Time {
	if t.IsZero() {
		return spanner.CommitTimestamp
	}

	return t
}

// sessionInsertMutation renders the insert of a non-OIDC session row, created and
// updated at the commit time. With the user columns enabled it also writes UserId,
// AuthenticatedAt (the commit time, or null for a preauth session) and
// ProviderSessionId.
func (s *SessionStorageDriver) sessionInsertMutation(id ccc.UUID, insertSession *dbtype.InsertSession, req *sessioninfo.NewSessionRequest) (*spanner.Mutation, error) {
	if !s.users {
		mutation, err := spanner.InsertStruct(s.sessionTableName, &struct {
			ID ccc.UUID
			*dbtype.InsertSession
			CreatedAt time.Time `spanner:"CreatedAt"`
			UpdatedAt time.Time `spanner:"UpdatedAt"`
		}{ID: id, InsertSession: insertSession, CreatedAt: spanner.CommitTimestamp, UpdatedAt: spanner.CommitTimestamp})
		if err != nil {
			return nil, errors.Wrap(err, "spanner.InsertStruct()")
		}

		return mutation, nil
	}

	user := dbtype.NewSessionUserColumns(req)
	var authenticatedAt spanner.NullTime
	if user.Authenticated {
		authenticatedAt = spanner.NullTime{Time: spanner.CommitTimestamp, Valid: true}
	}

	var providerSessionID, providerSessionIssuer spanner.NullString
	if user.ProviderSessionID != nil {
		providerSessionID = spanner.NullString{StringVal: *user.ProviderSessionID, Valid: true}
	}
	if user.ProviderSessionIssuer != nil {
		providerSessionIssuer = spanner.NullString{StringVal: *user.ProviderSessionIssuer, Valid: true}
	}

	mutation, err := spanner.InsertStruct(s.sessionTableName, &struct {
		ID ccc.UUID
		*dbtype.InsertSession
		CreatedAt             time.Time          `spanner:"CreatedAt"`
		UpdatedAt             time.Time          `spanner:"UpdatedAt"`
		UserID                ccc.NullUUID       `spanner:"UserId"`
		AuthenticatedAt       spanner.NullTime   `spanner:"AuthenticatedAt"`
		ProviderSessionID     spanner.NullString `spanner:"ProviderSessionId"`
		ProviderSessionIssuer spanner.NullString `spanner:"ProviderSessionIssuer"`
	}{
		ID: id, InsertSession: insertSession, CreatedAt: spanner.CommitTimestamp, UpdatedAt: spanner.CommitTimestamp,
		UserID: user.UserID, AuthenticatedAt: authenticatedAt,
		ProviderSessionID: providerSessionID, ProviderSessionIssuer: providerSessionIssuer,
	})
	if err != nil {
		return nil, errors.Wrap(err, "spanner.InsertStruct()")
	}

	return mutation, nil
}

// initialAuthEventMutations renders the inserts of the new session's auth events
// (dbtype.InitialAuthEvents), numbered from 1. Without an auth events table it renders
// none.
func (s *SessionStorageDriver) initialAuthEventMutations(id ccc.UUID, req *sessioninfo.NewSessionRequest, imp *dbtype.InsertImpersonation) []*spanner.Mutation {
	if s.authEvents == nil {
		return nil
	}
	events := dbtype.InitialAuthEvents(req, imp)

	mutations := make([]*spanner.Mutation, 0, len(events))
	for i := range events {
		mutations = append(mutations, s.authEventMutation(id, int64(i+1), &events[i]))
	}

	return mutations
}

// authEventMutation renders the insert of one auth event row. An event with a zero At
// occurred at the commit time.
func (s *SessionStorageDriver) authEventMutation(sessionID ccc.UUID, seq int64, event *sessioninfo.AuthEvent) *spanner.Mutation {
	var connection spanner.NullString
	if event.Connection != "" {
		connection = spanner.NullString{StringVal: event.Connection, Valid: true}
	}

	return spanner.InsertMap(s.authEvents.TableName, map[string]any{
		dbtype.SessionIDColumn: sessionID,
		"Seq":                  seq,
		"Method":               string(event.Method),
		"Connection":           connection,
		"IdpAmr":               event.IDPAMR,
		"OccurredAt":           commitTime(event.At),
	})
}

// userColumns renders the user columns that follow the base columns in the
// session query.
func (s *SessionStorageDriver) userColumns() string {
	if !s.users {
		return ""
	}

	return ", s.UserId, s.AuthenticatedAt, s.ProviderSessionId, s.ProviderSessionIssuer"
}

// readUser reads the user columns from row, starting at column idx, and returns
// the index of the next column.
func readUser(row *spanner.Row, idx int, sessData *dbtype.SessionData) (int, error) {
	var userID spanner.NullString
	if err := row.Column(idx, &userID); err != nil {
		return idx, errors.Wrapf(err, "row.Column(%d/UserId)", idx)
	}
	var authenticatedAt spanner.NullTime
	if err := row.Column(idx+1, &authenticatedAt); err != nil {
		return idx, errors.Wrapf(err, "row.Column(%d/AuthenticatedAt)", idx+1)
	}
	var providerSessionID, providerSessionIssuer spanner.NullString
	if err := row.Column(idx+2, &providerSessionID); err != nil {
		return idx, errors.Wrapf(err, "row.Column(%d/ProviderSessionId)", idx+2)
	}
	if err := row.Column(idx+3, &providerSessionIssuer); err != nil {
		return idx, errors.Wrapf(err, "row.Column(%d/ProviderSessionIssuer)", idx+3)
	}

	if userID.Valid {
		id, err := ccc.NullUUIDFromString(userID.StringVal)
		if err != nil {
			return idx, errors.Wrap(err, "ccc.NullUUIDFromString()")
		}
		sessData.UserID = id
	}
	if authenticatedAt.Valid {
		t := authenticatedAt.Time
		sessData.AuthenticatedAt = &t
	}
	if providerSessionID.Valid {
		sessData.ProviderSessionID = providerSessionID.StringVal
	}
	if providerSessionIssuer.Valid {
		sessData.ProviderSessionIssuer = providerSessionIssuer.StringVal
	}

	return idx + 4, nil
}

// DestroySessionsByProviderSessionID expires every live session whose sign-in carried
// the provider's session id under issuer, as a provider-initiated logout asks; an
// impersonated session's record ends Logout. Both columns match, so a session recorded
// without an issuer never does. It needs the auth schema.
func (s *SessionStorageDriver) DestroySessionsByProviderSessionID(ctx context.Context, issuer, providerSessionID string) error {
	ctx, span := tracer.Start(ctx)
	defer span.End()

	if !s.users {
		return errors.New("DestroySessionsByProviderSessionID needs the auth schema: use Auth storage")
	}

	_, err := s.spanner.ReadWriteTransaction(ctx, func(ctx context.Context, txn *spanner.ReadWriteTransaction) error {
		// The records end first: their statement reads the session table, which the
		// expiry then writes with the commit timestamp.
		if s.impersonation != nil {
			endRecords := spanner.NewStatement(fmt.Sprintf(`
				UPDATE %s
				SET EndedAt = PENDING_COMMIT_TIMESTAMP(), EndReason = @reason
				WHERE EndedAt IS NULL AND SessionId IN (SELECT Id FROM %s WHERE Expired = FALSE AND ProviderSessionId = @sid AND ProviderSessionIssuer = @iss)`,
				s.impersonation.TableName, s.sessionTableName))
			endRecords.Params["sid"] = providerSessionID
			endRecords.Params["iss"] = issuer
			endRecords.Params["reason"] = string(sessioninfo.ImpersonationEndedByLogout)
			if _, err := txn.Update(ctx, endRecords); err != nil {
				return errors.Wrap(err, "spanner.ReadWriteTransaction.Update()")
			}
		}
		expire := spanner.NewStatement(fmt.Sprintf(`UPDATE %s SET Expired = TRUE, UpdatedAt = PENDING_COMMIT_TIMESTAMP()
			WHERE Expired = FALSE AND ProviderSessionId = @sid AND ProviderSessionIssuer = @iss`, s.sessionTableName))
		expire.Params["sid"] = providerSessionID
		expire.Params["iss"] = issuer
		if _, err := txn.Update(ctx, expire); err != nil {
			return errors.Wrap(err, "spanner.ReadWriteTransaction.Update()")
		}

		return nil
	})
	if err != nil {
		return errors.Wrap(err, "spanner.Client.ReadWriteTransaction()")
	}

	return nil
}

// authEventRow is one auth event row as the events query returns it.
type authEventRow struct {
	Method     string             `spanner:"Method"`
	Connection spanner.NullString `spanner:"Connection"`
	IDPAMR     []string           `spanner:"IdpAmr"`
	OccurredAt time.Time          `spanner:"OccurredAt"`
}

// readAuthEvents reads a session's auth events, oldest first, through txn.
func (s *SessionStorageDriver) readAuthEvents(ctx context.Context, txn interface {
	Query(ctx context.Context, statement spanner.Statement) *spanner.RowIterator
}, sessionID ccc.UUID,
) ([]sessioninfo.AuthEvent, error) {
	ctx, span := tracer.Start(ctx)
	defer span.End()

	stmt := spanner.NewStatement(fmt.Sprintf(`
		SELECT Method, Connection, IdpAmr, OccurredAt
		FROM %s
		WHERE SessionId = @id
		ORDER BY Seq`, s.authEvents.TableName))
	stmt.Params["id"] = sessionID

	var events []sessioninfo.AuthEvent
	err := txn.Query(ctx, stmt).Do(func(row *spanner.Row) error {
		var r authEventRow
		if err := row.ToStruct(&r); err != nil {
			return errors.Wrap(err, "spanner.Row.ToStruct()")
		}
		events = append(events, sessioninfo.AuthEvent{
			Method:     sessioninfo.AuthMethod(r.Method),
			Connection: r.Connection.StringVal,
			IDPAMR:     r.IDPAMR,
			At:         r.OccurredAt,
		})

		return nil
	})
	if err != nil {
		return nil, errors.Wrap(err, "spanner.RowIterator.Do()")
	}

	return events, nil
}
