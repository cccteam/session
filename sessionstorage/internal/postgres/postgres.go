// Package postgres implements the session storage driver for PostgreSQL.
package postgres

import (
	"context"
	"fmt"
	"time"

	"github.com/cccteam/ccc"
	"github.com/cccteam/ccc/securehash"
	"github.com/cccteam/httpio"
	"github.com/cccteam/session/internal/dbtype"
	"github.com/georgysavva/scany/v2/pgxscan"
	"github.com/go-playground/errors/v5"
	"github.com/jackc/pgx/v5"
)

// SessionStorageDriver represents the session storage implementation for PostgreSQL.
type SessionStorageDriver struct {
	conn             Queryer
	sessionTableName string
	userTableName    string
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

// Session returns the session information from the database for given sessionID
func (s *SessionStorageDriver) Session(ctx context.Context, sessionID ccc.UUID) (*dbtype.Session, error) {
	ctx, span := ccc.StartTrace(ctx)
	defer span.End()

	query := fmt.Sprintf(`
		SELECT
			"Id", 
			"Username", 
			"CreatedAt", 
			"UpdatedAt", 
			"Expired"
		FROM "%s"
		WHERE "Id" = $1
	`, s.sessionTableName)

	session := &dbtype.Session{}
	if err := pgxscan.Get(ctx, s.conn, session, query, sessionID); err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, httpio.NewNotFoundMessagef("session %q not found", sessionID)
		}

		return nil, errors.Wrap(err, "pgxscan.Get()")
	}

	return session, nil
}

// UpdateSessionActivity updates the session activity column with the current time
func (s *SessionStorageDriver) UpdateSessionActivity(ctx context.Context, sessionID ccc.UUID) error {
	ctx, span := ccc.StartTrace(ctx)
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
func (s *SessionStorageDriver) InsertSession(ctx context.Context, insertSession *dbtype.InsertSession) (ccc.UUID, error) {
	ctx, span := ccc.StartTrace(ctx)
	defer span.End()

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

	if _, err := s.conn.Exec(ctx, query, id, insertSession.Username, insertSession.CreatedAt, insertSession.UpdatedAt, insertSession.Expired); err != nil {
		return ccc.NilUUID, errors.Wrap(err, "Queryer.Exec()")
	}

	return id, nil
}

// DestroySession marks the session as expired
func (s *SessionStorageDriver) DestroySession(ctx context.Context, sessionID ccc.UUID) error {
	ctx, span := ccc.StartTrace(ctx)
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
	ctx, span := ccc.StartTrace(ctx)
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
	ctx, span := ccc.StartTrace(ctx)
	defer span.End()

	query := fmt.Sprintf(`
		SELECT
			"Id", 
			"Username", 
			"PasswordHash", 
			"Disabled"
		FROM "%s"
		WHERE "Username" = $1
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

// UpdateUserPasswordHash updates the user password hash
func (s *SessionStorageDriver) UpdateUserPasswordHash(ctx context.Context, userID ccc.UUID, hash *securehash.Hash) error {
	ctx, span := ccc.StartTrace(ctx)
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
