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

// EnableAccounts enables the accounts schema's session columns: every non-OIDC session
// insert writes UserId and AuthenticatedAt, and every session read returns them.
// Without it the driver never names those columns, so a session table without them
// keeps working.
func (s *SessionStorageDriver) EnableAccounts() {
	s.accounts = true
}

// AccountsEnabled reports whether the accounts schema's session columns are enabled.
func (s *SessionStorageDriver) AccountsEnabled() bool {
	return s.accounts
}

// SetAuthEvents attaches the auth events table: new sessions record their first auth
// event and every session read returns the session's events, oldest first.
func (s *SessionStorageDriver) SetAuthEvents(config *AuthEventsConfig) {
	s.authEvents = config
}

// AuthEventsEnabled reports whether an auth events table is configured.
func (s *SessionStorageDriver) AuthEventsEnabled() bool {
	return s.authEvents != nil
}

// sessionInsertMutation renders the insert of a non-OIDC session row: the base columns
// and, when the accounts columns are enabled, the account's UserId and AuthenticatedAt.
func (s *SessionStorageDriver) sessionInsertMutation(id ccc.UUID, insertSession *dbtype.InsertSession, req *sessioninfo.NewSessionRequest) (*spanner.Mutation, error) {
	if !s.accounts {
		mutation, err := spanner.InsertStruct(s.sessionTableName, &struct {
			ID ccc.UUID
			*dbtype.InsertSession
		}{ID: id, InsertSession: insertSession})
		if err != nil {
			return nil, errors.Wrap(err, "spanner.InsertStruct()")
		}

		return mutation, nil
	}

	account := dbtype.SessionAccount(req, insertSession.CreatedAt)
	var authenticatedAt spanner.NullTime
	if account.AuthenticatedAt != nil {
		authenticatedAt = spanner.NullTime{Time: *account.AuthenticatedAt, Valid: true}
	}

	mutation, err := spanner.InsertStruct(s.sessionTableName, &struct {
		ID ccc.UUID
		*dbtype.InsertSession
		UserID          ccc.NullUUID     `spanner:"UserId"`
		AuthenticatedAt spanner.NullTime `spanner:"AuthenticatedAt"`
	}{ID: id, InsertSession: insertSession, UserID: account.UserID, AuthenticatedAt: authenticatedAt})
	if err != nil {
		return nil, errors.Wrap(err, "spanner.InsertStruct()")
	}

	return mutation, nil
}

// initialAuthEventMutations renders the new session's first auth event (see
// dbtype.InitialAuthEvent) when an auth events table is configured, and nothing
// otherwise.
func (s *SessionStorageDriver) initialAuthEventMutations(id ccc.UUID, req *sessioninfo.NewSessionRequest, imp *dbtype.InsertImpersonation, at time.Time) []*spanner.Mutation {
	if s.authEvents == nil {
		return nil
	}
	event := dbtype.InitialAuthEvent(req, imp, at)
	if event == nil {
		return nil
	}

	return []*spanner.Mutation{s.authEventMutation(id, 1, event)}
}

// authEventMutation renders the insert of one auth event row.
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
		"IdpAmr":               event.IdPAMR,
		"OccurredAt":           event.At,
	})
}

// accountColumns renders the accounts columns of the session query, after the base
// columns.
func (s *SessionStorageDriver) accountColumns() string {
	if !s.accounts {
		return ""
	}

	return ", s.UserId, s.AuthenticatedAt"
}

// readAccount reads the accounts columns from row positionally at idx and returns the
// index of the next unread column.
func readAccount(row *spanner.Row, idx int, sessData *dbtype.SessionData) (int, error) {
	var userID spanner.NullString
	if err := row.Column(idx, &userID); err != nil {
		return idx, errors.Wrapf(err, "row.Column(%d/UserId)", idx)
	}
	var authenticatedAt spanner.NullTime
	if err := row.Column(idx+1, &authenticatedAt); err != nil {
		return idx, errors.Wrapf(err, "row.Column(%d/AuthenticatedAt)", idx+1)
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

	return idx + 2, nil
}

// authEventRow is one auth event row as the events query returns it.
type authEventRow struct {
	Method     string             `spanner:"Method"`
	Connection spanner.NullString `spanner:"Connection"`
	IdpAmr     []string           `spanner:"IdpAmr"`
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
			IdPAMR:     r.IdpAmr,
			At:         r.OccurredAt,
		})

		return nil
	})
	if err != nil {
		return nil, errors.Wrap(err, "spanner.RowIterator.Do()")
	}

	return events, nil
}
