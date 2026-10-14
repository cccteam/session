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

// The "when" columns take the database's time: every write sets them to now(), the
// transaction's start time, so the rows a transaction writes share one time and the
// application clock reaches none of them. A caller-supplied time (an auth event's At)
// is written as given, through COALESCE($n, now()) with NULL for the zero time.

// optionalTime returns nil for the zero time, so a column written as COALESCE($n, now())
// takes the database's time.
func optionalTime(t time.Time) *time.Time {
	if t.IsZero() {
		return nil
	}

	return &t
}

// sessionInsertStatement renders the insert of a non-OIDC session row, created and
// updated at the database's time. With the user columns enabled it also writes UserId,
// AuthenticatedAt (the same time, or NULL for a preauth session) and
// ProviderSessionId.
func (s *SessionStorageDriver) sessionInsertStatement(id ccc.UUID, insertSession *dbtype.InsertSession, req *sessioninfo.NewSessionRequest) (query string, args []any) {
	args = make([]any, 0, 5)
	args = append(args, id, insertSession.Username, insertSession.Expired)
	if !s.users {
		return fmt.Sprintf(`
		INSERT INTO %s
			("Id", "Username", "CreatedAt", "UpdatedAt", "Expired")
		VALUES
			($1, $2, now(), now(), $3)
		`, s.sessionTable()), args
	}

	user := dbtype.NewSessionUserColumns(req)
	var userID *ccc.UUID
	if user.UserID.Valid {
		userID = &user.UserID.UUID
	}
	authenticatedAt := "NULL"
	if user.Authenticated {
		authenticatedAt = "now()"
	}

	return fmt.Sprintf(`
		INSERT INTO %s
			("Id", "Username", "CreatedAt", "UpdatedAt", "Expired", "UserId", "AuthenticatedAt", "ProviderSessionId")
		VALUES
			($1, $2, now(), now(), $3, $4, %s, $5)
		`, s.sessionTable(), authenticatedAt), append(args, userID, user.ProviderSessionID)
}

// initialAuthEvent chains the insert of the new session's auth events
// (dbtype.InitialAuthEvents), numbered from 1, after next, which may be nil. Without an
// auth events table it returns next.
func (s *SessionStorageDriver) initialAuthEvent(
	id ccc.UUID, req *sessioninfo.NewSessionRequest, imp *dbtype.InsertImpersonation, next func(ctx context.Context, txn pgx.Tx) error,
) func(ctx context.Context, txn pgx.Tx) error {
	if s.authEvents == nil {
		return next
	}
	events := dbtype.InitialAuthEvents(req, imp)
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

// insertAuthEvent writes one auth event row inside txn. An event with a zero At
// occurred at the database's time.
func (s *SessionStorageDriver) insertAuthEvent(ctx context.Context, txn pgx.Tx, sessionID ccc.UUID, seq int64, event *sessioninfo.AuthEvent) error {
	query := fmt.Sprintf(`
		INSERT INTO %s
			("SessionId", "Seq", "Method", "Connection", "IdpAmr", "OccurredAt")
		VALUES
			($1, $2, $3, $4, $5, COALESCE($6, now()))`, pgx.Identifier{s.authEvents.TableName}.Sanitize())

	if _, err := txn.Exec(ctx, query, sessionID, seq, string(event.Method), dbtype.OptionalString(event.Connection), event.IDPAMR, optionalTime(event.At)); err != nil {
		return errors.Wrap(err, "pgx.Tx.Exec()")
	}

	return nil
}

// userColumns renders the user columns that follow the base columns in the
// session query.
func (s *SessionStorageDriver) userColumns() string {
	if !s.users {
		return ""
	}

	return `, s."UserId", s."AuthenticatedAt", s."ProviderSessionId"`
}

// userScan holds the scan destinations of the user columns.
type userScan struct {
	userID            *ccc.UUID
	authenticatedAt   *time.Time
	providerSessionID *string
}

func (a *userScan) dests() []any {
	return []any{&a.userID, &a.authenticatedAt, &a.providerSessionID}
}

func (a *userScan) apply(sessData *dbtype.SessionData) {
	if a.userID != nil {
		sessData.UserID = ccc.NullUUIDFromUUID(*a.userID)
	}
	sessData.AuthenticatedAt = a.authenticatedAt
	if a.providerSessionID != nil {
		sessData.ProviderSessionID = *a.providerSessionID
	}
}

// DestroySessionsByProviderSessionID expires every live session whose sign-in carried
// the provider's session id, as a provider-initiated logout asks; an impersonated
// session's record ends Logout. It needs the auth schema.
func (s *SessionStorageDriver) DestroySessionsByProviderSessionID(ctx context.Context, providerSessionID string) error {
	ctx, span := tracer.Start(ctx)
	defer span.End()

	if !s.users {
		return errors.New("DestroySessionsByProviderSessionID needs the auth schema: use Auth storage")
	}

	txn, err := s.conn.Begin(ctx)
	if err != nil {
		return errors.Wrap(err, "Queryer.Begin()")
	}
	defer func() {
		_ = txn.Rollback(ctx)
	}()

	if s.impersonation != nil {
		endRecords := fmt.Sprintf(`
			UPDATE %s i SET "EndedAt" = now(), "EndReason" = $2
			WHERE i."EndedAt" IS NULL AND EXISTS (
				SELECT 1 FROM %s s WHERE s."Id" = i."SessionId" AND s."Expired" = FALSE AND s."ProviderSessionId" = $1)`,
			pgx.Identifier{s.impersonation.TableName}.Sanitize(), s.sessionTable())
		if _, err := txn.Exec(ctx, endRecords, providerSessionID, string(sessioninfo.ImpersonationEndedByLogout)); err != nil {
			return errors.Wrap(err, "pgx.Tx.Exec()")
		}
	}
	expire := fmt.Sprintf(`UPDATE %s SET "Expired" = TRUE, "UpdatedAt" = now() WHERE "Expired" = FALSE AND "ProviderSessionId" = $1`, s.sessionTable())
	if _, err := txn.Exec(ctx, expire, providerSessionID); err != nil {
		return errors.Wrap(err, "pgx.Tx.Exec()")
	}

	if err := txn.Commit(ctx); err != nil {
		return errors.Wrap(err, "pgx.Tx.Commit()")
	}

	return nil
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
