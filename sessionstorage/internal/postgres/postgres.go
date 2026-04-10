// Package postgres implements the session storage driver for PostgreSQL.
package postgres

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/cccteam/ccc"
	"github.com/cccteam/ccc/securehash"
	"github.com/cccteam/ccc/tracer"
	"github.com/cccteam/httpio"
	"github.com/cccteam/session/internal/dbtype"
	"github.com/cccteam/session/sessioninfo"
	"github.com/georgysavva/scany/v2/pgxscan"
	"github.com/go-playground/errors/v5"
	"github.com/jackc/pgerrcode"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
)

// SessionStorageDriver represents the session storage implementation for PostgreSQL.
type SessionStorageDriver struct {
	conn             Queryer
	sessionTableName string
	userTableName    string
	customDataConfig *dbtype.CustomSessionDataConfig
}

// NewSessionStorageDriver creates a new SessionStorageDriver
func NewSessionStorageDriver(conn Queryer) *SessionStorageDriver {
	return &SessionStorageDriver{
		conn:             conn,
		sessionTableName: "Sessions",
		userTableName:    "SessionUsers",
	}
}

// SetSessionTableName sets the name of the session table.
func (s *SessionStorageDriver) SetSessionTableName(name string) {
	s.sessionTableName = name
}

// SetUserTableName sets the name of the user table.
func (s *SessionStorageDriver) SetUserTableName(name string) {
	s.userTableName = name
}

// SetCustomSessionDataConfig sets the configuration for a separate custom session data table.
func (s *SessionStorageDriver) SetCustomSessionDataConfig(config *dbtype.CustomSessionDataConfig) {
	s.customDataConfig = config
}

// Session returns the session information from the database for given sessionID
func (s *SessionStorageDriver) Session(ctx context.Context, sessionID ccc.UUID) (*dbtype.Session, error) {
	ctx, span := tracer.Start(ctx)
	defer span.End()

	query, args := s.sessionQuery(sessionID)
	rows, err := s.conn.Query(ctx, query, args...)
	if err != nil {
		return nil, errors.Wrap(err, "Queryer.Query()")
	}
	defer rows.Close()

	if !rows.Next() {
		if err := rows.Err(); err != nil {
			return nil, errors.Wrap(err, "rows.Err()")
		}

		return nil, httpio.NewNotFoundMessagef("session %q not found", sessionID)
	}

	customColumns := []string{}
	if s.customDataConfig != nil {
		customColumns = s.customDataConfig.Columns
	}

	session := &dbtype.Session{}
	scanDests := make([]any, 0, 5+len(customColumns))
	scanDests = append(scanDests, &session.ID, &session.Username, &session.CreatedAt, &session.UpdatedAt, &session.Expired)

	customValues := make([]any, len(customColumns))
	for i := range customColumns {
		customValues[i] = new(any)
	}
	scanDests = append(scanDests, customValues...)

	if err := rows.Scan(scanDests...); err != nil {
		return nil, errors.Wrap(err, "rows.Scan()")
	}

	if len(customColumns) > 0 {
		session.CustomData = make(map[string]any, len(customColumns))
		for i, col := range customColumns {
			val, ok := customValues[i].(*any)
			if !ok {
				return nil, errors.Newf("unexpected type for custom column %q", col)
			}
			session.CustomData[col] = *val
		}
	}

	return session, nil
}

// UpdateSessionActivity updates the session activity column with the current time
func (s *SessionStorageDriver) UpdateSessionActivity(ctx context.Context, sessionID ccc.UUID) error {
	ctx, span := tracer.Start(ctx)
	defer span.End()

	query := fmt.Sprintf(`
		UPDATE "%s" SET "UpdatedAt" = $1
		WHERE "Id" = $2`, s.sessionTableName)

	res, err := s.conn.Exec(ctx, query, time.Now(), sessionID)
	if err != nil {
		return errors.Wrapf(err, "failed to update Sessions table for ID: %s", sessionID)
	}

	if cnt := res.RowsAffected(); cnt != 1 {
		return httpio.NewNotFoundMessagef("session %q not found", sessionID)
	}

	return nil
}

// InsertSession inserts a Session into database
func (s *SessionStorageDriver) InsertSession(ctx context.Context, insertSession *dbtype.InsertSession, customData ...*sessioninfo.CustomData) (ccc.UUID, error) {
	ctx, span := tracer.Start(ctx)
	defer span.End()

	if len(customData) > 0 && s.customDataConfig == nil {
		return ccc.NilUUID, errors.New("custom session data provided but custom session data config is not set")
	}

	id, err := ccc.NewUUID()
	if err != nil {
		return ccc.NilUUID, errors.Wrap(err, "ccc.NewUUID()")
	}

	txn, err := s.conn.Begin(ctx)
	if err != nil {
		return ccc.NilUUID, errors.Wrap(err, "Queryer.Begin()")
	}
	defer func() {
		_ = txn.Rollback(ctx)
	}()

	query := fmt.Sprintf(`
		INSERT INTO "%s"
			("Id", "Username", "CreatedAt", "UpdatedAt", "Expired")
		VALUES
			($1, $2, $3, $4, $5)
		`, s.sessionTableName)

	if _, err := txn.Exec(ctx, query, id, insertSession.Username, insertSession.CreatedAt, insertSession.UpdatedAt, insertSession.Expired); err != nil {
		return ccc.NilUUID, errors.Wrap(err, "tx.Exec()")
	}

	if len(customData) > 0 {
		columns := []string{pgx.Identifier{"SessionId"}.Sanitize()}
		args := []any{id}
		for _, c := range customData {
			columns = append(columns, pgx.Identifier{c.ColumnName}.Sanitize())
			args = append(args, c.Value)
		}
		placeholders := make([]string, len(args))
		for i := range args {
			placeholders[i] = fmt.Sprintf("$%d", i+1)
		}

		q := fmt.Sprintf(`
			INSERT INTO %s
				(%s)
			VALUES
				(%s)
		`, pgx.Identifier{s.customDataConfig.TableName}.Sanitize(), strings.Join(columns, ", "), strings.Join(placeholders, ", "))

		if _, err := txn.Exec(ctx, q, args...); err != nil {
			return ccc.NilUUID, errors.Wrap(err, "tx.Exec()")
		}
	}

	if err := txn.Commit(ctx); err != nil {
		return ccc.NilUUID, errors.Wrap(err, "tx.Commit()")
	}

	return id, nil
}

// DestroySession marks the session as expired
func (s *SessionStorageDriver) DestroySession(ctx context.Context, sessionID ccc.UUID) error {
	ctx, span := tracer.Start(ctx)
	defer span.End()

	query := fmt.Sprintf(`
		UPDATE "%s" SET "Expired" = TRUE, "UpdatedAt" = $2
		WHERE "Id" = $1`, s.sessionTableName)

	if _, err := s.conn.Exec(ctx, query, sessionID, time.Now()); err != nil {
		// Attempting to destroy a session that does not exist is something that
		// can happen when a browser returns with old state. Erroring in this
		// case is extra noise, so we will ignore instead.
		return errors.Wrap(err, "Queryer.Exec()")
	}

	return nil
}

// User returns the user record associated with the user id
func (s *SessionStorageDriver) User(ctx context.Context, id ccc.UUID) (*dbtype.SessionUser, error) {
	ctx, span := tracer.Start(ctx)
	defer span.End()

	query := fmt.Sprintf(`
		SELECT
			"Id", 
			"Username", 
			"PasswordHash", 
			"Disabled"
		FROM "%s"
		WHERE "Id" = $1
	`, s.userTableName)

	user := &dbtype.SessionUser{}
	if err := pgxscan.Get(ctx, s.conn, user, query, id); err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, httpio.NewNotFoundMessagef("user id %q does not exist", id)
		}

		return nil, errors.Wrap(err, "pgxscan.Get()")
	}

	return user, nil
}

// UserByUserName returns the user record associated with the username
func (s *SessionStorageDriver) UserByUserName(ctx context.Context, username string) (*dbtype.SessionUser, error) {
	ctx, span := tracer.Start(ctx)
	defer span.End()

	query := fmt.Sprintf(`
		SELECT
			"Id", 
			"Username", 
			"PasswordHash", 
			"Disabled"
		FROM "%s"
		WHERE "NormalizedUsername" = casefold(normalize($1))
	`, s.userTableName)

	user := &dbtype.SessionUser{}
	if err := pgxscan.Get(ctx, s.conn, user, query, username); err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, httpio.NewNotFoundMessagef("username %q does not exist", username)
		}

		return nil, errors.Wrapf(err, "pgxscan.Get()")
	}

	return user, nil
}

// CreateUser creates a new user
func (s *SessionStorageDriver) CreateUser(ctx context.Context, user *dbtype.InsertSessionUser) (*dbtype.SessionUser, error) {
	ctx, span := tracer.Start(ctx)
	defer span.End()

	id, err := ccc.NewUUID()
	if err != nil {
		return nil, errors.Wrap(err, "ccc.NewUUID()")
	}

	query := fmt.Sprintf(`
		INSERT INTO "%s"
			("Id", "Username", "PasswordHash", "Disabled")
		VALUES
			($1, $2, $3, $4)
		`, s.userTableName)

	if _, err := s.conn.Exec(ctx, query, id, user.Username, user.PasswordHash, user.Disabled); err != nil {
		var pgErr *pgconn.PgError
		if errors.As(err, &pgErr) && pgErr.Code == pgerrcode.UniqueViolation && pgErr.ConstraintName == "SessionUsers_NormalizedUsername_idx" {
			return nil, httpio.NewConflictMessagef("username %q already exists", user.Username)
		}

		return nil, errors.Wrap(err, "Queryer.Exec()")
	}

	return s.User(ctx, id)
}

// SetUserUsername updates the user password username
func (s *SessionStorageDriver) SetUserUsername(ctx context.Context, userID ccc.UUID, username string) error {
	ctx, span := tracer.Start(ctx)
	defer span.End()

	query := fmt.Sprintf(`
		UPDATE "%s" SET "Username" = $2
		WHERE "Id" = $1`, s.userTableName)

	if cmdTag, err := s.conn.Exec(ctx, query, userID, username); err != nil {
		var pgErr *pgconn.PgError
		if errors.As(err, &pgErr) && pgErr.Code == pgerrcode.UniqueViolation && pgErr.ConstraintName == "SessionUsers_NormalizedUsername_idx" {
			return httpio.NewConflictMessagef("username %q already exists", username)
		}

		return errors.Wrap(err, "Queryer.Exec()")
	} else if cmdTag.RowsAffected() == 0 {
		return httpio.NewNotFoundMessagef("user id %q does not exist", userID)
	}

	return nil
}

// SetUserPasswordHash updates the user password hash
func (s *SessionStorageDriver) SetUserPasswordHash(ctx context.Context, userID ccc.UUID, hash *securehash.Hash) error {
	ctx, span := tracer.Start(ctx)
	defer span.End()

	query := fmt.Sprintf(`
		UPDATE "%s" SET "PasswordHash" = $2
		WHERE "Id" = $1`, s.userTableName)

	if cmdTag, err := s.conn.Exec(ctx, query, userID, hash); err != nil {
		return errors.Wrap(err, "Queryer.Exec()")
	} else if cmdTag.RowsAffected() == 0 {
		return httpio.NewNotFoundMessagef("user id %q does not exist", userID)
	}

	return nil
}

// DeactivateUser deactivates a user
func (s *SessionStorageDriver) DeactivateUser(ctx context.Context, id ccc.UUID) error {
	ctx, span := tracer.Start(ctx)
	defer span.End()

	query := fmt.Sprintf(`
		UPDATE "%s" SET "Disabled" = TRUE
		WHERE "Id" = $1`, s.userTableName)

	if cmdTag, err := s.conn.Exec(ctx, query, id); err != nil {
		return errors.Wrap(err, "Queryer.Exec()")
	} else if cmdTag.RowsAffected() == 0 {
		return httpio.NewNotFoundMessagef("user id %q does not exist", id)
	}

	return nil
}

// DeleteUser deletes a user
func (s *SessionStorageDriver) DeleteUser(ctx context.Context, id ccc.UUID) error {
	ctx, span := tracer.Start(ctx)
	defer span.End()

	query := fmt.Sprintf(`
		DELETE FROM "%s"
		WHERE "Id" = $1`, s.userTableName)

	if cmdTag, err := s.conn.Exec(ctx, query, id); err != nil {
		return errors.Wrap(err, "Queryer.Exec()")
	} else if cmdTag.RowsAffected() == 0 {
		return httpio.NewNotFoundMessagef("user id %q does not exist", id)
	}

	return nil
}

// ActivateUser activates a user
func (s *SessionStorageDriver) ActivateUser(ctx context.Context, id ccc.UUID) error {
	ctx, span := tracer.Start(ctx)
	defer span.End()

	query := fmt.Sprintf(`
		UPDATE "%s" SET "Disabled" = FALSE
		WHERE "Id" = $1`, s.userTableName)

	if cmdTag, err := s.conn.Exec(ctx, query, id); err != nil {
		return errors.Wrap(err, "Queryer.Exec()")
	} else if cmdTag.RowsAffected() == 0 {
		return httpio.NewNotFoundMessagef("user id %q does not exist", id)
	}

	return nil
}

// DestroyAllUserSessions destroys all sessions for a given user
func (s *SessionStorageDriver) DestroyAllUserSessions(ctx context.Context, username string) error {
	ctx, span := tracer.Start(ctx)
	defer span.End()

	query := fmt.Sprintf(`
		UPDATE "%s" 
		SET "Expired" = TRUE, "UpdatedAt" = $2
		WHERE "Username" = $1`, s.sessionTableName)

	if _, err := s.conn.Exec(ctx, query, username, time.Now()); err != nil {
		return errors.Wrap(err, "Queryer.Exec()")
	}

	return nil
}

func (s *SessionStorageDriver) sessionQuery(sessionID ccc.UUID) (query string, args []any) {
	var columns strings.Builder
	columns.WriteString(`s."Id", s."Username", s."CreatedAt", s."UpdatedAt", s."Expired"`)

	joinClause := ""
	if s.customDataConfig != nil && len(s.customDataConfig.Columns) > 0 {
		for _, col := range s.customDataConfig.Columns {
			fmt.Fprintf(&columns, `, c.%s`, pgx.Identifier{col}.Sanitize())
		}
		joinClause = fmt.Sprintf(`LEFT JOIN %s c ON s."Id" = c.%s`, pgx.Identifier{s.customDataConfig.TableName}.Sanitize(), pgx.Identifier{"SessionId"}.Sanitize())
	}

	query = fmt.Sprintf(`
			SELECT %s 
			FROM "%s" s 
			%s 
			WHERE s."Id" = $1`,
		columns.String(), s.sessionTableName, joinClause)

	return query, []any{sessionID}
}
