package postgres

import (
	"context"
	"fmt"
	"time"

	"github.com/cccteam/ccc"
	"github.com/cccteam/ccc/tracer"
	"github.com/cccteam/session/internal/dbtype"
	"github.com/cccteam/session/sessioninfo"
	"github.com/go-playground/errors/v5"
	"github.com/jackc/pgx/v5"
)

// AuthEventsConfig configures the auth events table for the PostgreSQL driver. It is
// populated by the public sessionstorage package from a validated unit; the driver
// performs no validation of its own.
type AuthEventsConfig struct {
	// TableName is the name of the auth events table.
	TableName string
}

// EnableAccounts enables the accounts schema's session columns, UserId and
// AuthenticatedAt. Non-OIDC session inserts write them and session reads return them.
// Without it the driver never names those columns, so a legacy session table keeps
// working.
func (s *SessionStorageDriver) EnableAccounts() {
	s.accounts = true
}

// AccountsEnabled reports whether the accounts schema's session columns are enabled.
func (s *SessionStorageDriver) AccountsEnabled() bool {
	return s.accounts
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

// sessionInsertStatement renders the insert of a non-OIDC session row. With the
// accounts columns enabled it also writes UserId and AuthenticatedAt.
func (s *SessionStorageDriver) sessionInsertStatement(id ccc.UUID, insertSession *dbtype.InsertSession, req *sessioninfo.NewSessionRequest) (query string, args []any) {
	args = make([]any, 0, 7)
	args = append(args, id, insertSession.Username, insertSession.CreatedAt, insertSession.UpdatedAt, insertSession.Expired)
	if !s.accounts {
		return fmt.Sprintf(`
		INSERT INTO "%s"
			("Id", "Username", "CreatedAt", "UpdatedAt", "Expired")
		VALUES
			($1, $2, $3, $4, $5)
		`, s.sessionTableName), args
	}

	account := dbtype.SessionAccount(req, insertSession.CreatedAt)
	var userID *ccc.UUID
	if account.UserID.Valid {
		userID = &account.UserID.UUID
	}

	return fmt.Sprintf(`
		INSERT INTO "%s"
			("Id", "Username", "CreatedAt", "UpdatedAt", "Expired", "UserId", "AuthenticatedAt")
		VALUES
			($1, $2, $3, $4, $5, $6, $7)
		`, s.sessionTableName), append(args, userID, account.AuthenticatedAt)
}

// initialAuthEvent chains the insert of the new session's auth events
// (dbtype.InitialAuthEvents), numbered from 1, after next, which may be nil. Without an
// auth events table it returns next.
func (s *SessionStorageDriver) initialAuthEvent(
	id ccc.UUID, req *sessioninfo.NewSessionRequest, imp *dbtype.InsertImpersonation, at time.Time, next func(ctx context.Context, txn pgx.Tx) error,
) func(ctx context.Context, txn pgx.Tx) error {
	if s.authEvents == nil {
		return next
	}
	events := dbtype.InitialAuthEvents(req, imp, at)
	if len(events) == 0 {
		return next
	}

	return func(ctx context.Context, txn pgx.Tx) error {
		if next != nil {
			if err := next(ctx, txn); err != nil {
				return err
			}
		}
		for i := range events {
			if err := s.insertAuthEvent(ctx, txn, id, int64(i+1), &events[i]); err != nil {
				return err
			}
		}

		return nil
	}
}

// insertAuthEvent writes one auth event row inside txn.
func (s *SessionStorageDriver) insertAuthEvent(ctx context.Context, txn pgx.Tx, sessionID ccc.UUID, seq int64, event *sessioninfo.AuthEvent) error {
	query := fmt.Sprintf(`
		INSERT INTO %s
			("SessionId", "Seq", "Method", "Connection", "IdpAmr", "OccurredAt")
		VALUES
			($1, $2, $3, $4, $5, $6)`, pgx.Identifier{s.authEvents.TableName}.Sanitize())

	if _, err := txn.Exec(ctx, query, sessionID, seq, string(event.Method), dbtype.OptionalString(event.Connection), event.IDPAMR, event.At); err != nil {
		return errors.Wrap(err, "pgx.Tx.Exec()")
	}

	return nil
}

// accountColumns renders the accounts columns that follow the base columns in the
// session query.
func (s *SessionStorageDriver) accountColumns() string {
	if !s.accounts {
		return ""
	}

	return `, s."UserId", s."AuthenticatedAt"`
}

// accountScan holds the scan destinations of the accounts columns.
type accountScan struct {
	userID          *ccc.UUID
	authenticatedAt *time.Time
}

func (a *accountScan) dests() []any {
	return []any{&a.userID, &a.authenticatedAt}
}

func (a *accountScan) apply(sessData *dbtype.SessionData) {
	if a.userID != nil {
		sessData.UserID = ccc.NullUUIDFromUUID(*a.userID)
	}
	sessData.AuthenticatedAt = a.authenticatedAt
}

// readAuthEvents reads a session's auth events, oldest first.
func (s *SessionStorageDriver) readAuthEvents(ctx context.Context, sessionID ccc.UUID) ([]sessioninfo.AuthEvent, error) {
	ctx, span := tracer.Start(ctx)
	defer span.End()

	query := fmt.Sprintf(`
		SELECT "Method", "Connection", "IdpAmr", "OccurredAt"
		FROM %s
		WHERE "SessionId" = $1
		ORDER BY "Seq"`, pgx.Identifier{s.authEvents.TableName}.Sanitize())

	rows, err := s.conn.Query(ctx, query, sessionID)
	if err != nil {
		return nil, errors.Wrap(err, "Queryer.Query()")
	}
	defer rows.Close()

	var events []sessioninfo.AuthEvent
	for rows.Next() {
		var (
			method     string
			connection *string
			amr        []string
			at         time.Time
		)
		if err := rows.Scan(&method, &connection, &amr, &at); err != nil {
			return nil, errors.Wrap(err, "pgx.Rows.Scan()")
		}
		event := sessioninfo.AuthEvent{Method: sessioninfo.AuthMethod(method), IDPAMR: amr, At: at}
		if connection != nil {
			event.Connection = *connection
		}
		events = append(events, event)
	}
	if err := rows.Err(); err != nil {
		return nil, errors.Wrap(err, "pgx.Rows.Err()")
	}

	return events, nil
}
