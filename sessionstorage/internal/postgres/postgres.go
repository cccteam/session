// Package postgres implements the session storage driver for PostgreSQL.
package postgres

import (
	"context"
	"time"

	"github.com/cccteam/ccc"
	"github.com/cccteam/httpio"
	"github.com/cccteam/session/sessionstorage/internal/dbtype"
	"github.com/georgysavva/scany/v2/pgxscan"
	"github.com/go-playground/errors/v5"
	"github.com/jackc/pgx/v5"
)

// SessionStorageDriver represents the session storage implementation for PostgreSQL.
type SessionStorageDriver struct {
	conn Queryer
}

// NewSessionStorageDriver creates a new SessionStorageDriver
func NewSessionStorageDriver(conn Queryer) *SessionStorageDriver {
	return &SessionStorageDriver{
		conn: conn,
	}
}

// Session returns the session information from the database for given sessionID
func (s *SessionStorageDriver) Session(ctx context.Context, sessionID ccc.UUID) (*dbtype.Session, error) {
	ctx, span := ccc.StartTrace(ctx)
	defer span.End()

	query := `
		SELECT
			"Id", "Username", "CreatedAt", "UpdatedAt", "Expired"
		FROM "Sessions"
		WHERE "Id" = $1
	`

	session := &dbtype.Session{}
	if err := pgxscan.Get(ctx, s.conn, session, query, sessionID); err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, httpio.NewNotFoundMessagef("session %s not found in database", sessionID)
		}

		return nil, errors.Wrapf(err, "failed to scan row for session %s", sessionID)
	}

	return session, nil
}

// UpdateSessionActivity updates the session activity column with the current time
func (s *SessionStorageDriver) UpdateSessionActivity(ctx context.Context, sessionID ccc.UUID) error {
	ctx, span := ccc.StartTrace(ctx)
	defer span.End()

	query := `
		UPDATE "Sessions" SET "UpdatedAt" = $1
		WHERE "Id" = $2`

	res, err := s.conn.Exec(ctx, query, time.Now(), sessionID)
	if err != nil {
		return errors.Wrapf(err, "failed to update Sessions table for ID: %s", sessionID)
	}

	if cnt := res.RowsAffected(); cnt != 1 {
		return errors.Newf("failed to find Session %s", sessionID)
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

	query := `
		INSERT INTO "Sessions"
			("Id", "Username", "CreatedAt", "UpdatedAt", "Expired")
		VALUES
			($1, $2, $3, $4, $5)
		`

	if _, err := s.conn.Exec(ctx, query, id, insertSession.Username, insertSession.CreatedAt, insertSession.UpdatedAt, insertSession.Expired); err != nil {
		return ccc.NilUUID, errors.Wrap(err, "Queryer.Exec()")
	}

	return id, nil
}

// DestroySession marks the session as expired
func (s *SessionStorageDriver) DestroySession(ctx context.Context, sessionID ccc.UUID) error {
	ctx, span := ccc.StartTrace(ctx)
	defer span.End()

	query := `
		UPDATE "Sessions" SET "Expired" = TRUE, "UpdatedAt" = $2
		WHERE "Id" = $1`

	if _, err := s.conn.Exec(ctx, query, sessionID, time.Now()); err != nil {
		return errors.Wrap(err, "Queryer.Exec()")
	}

	return nil
}
