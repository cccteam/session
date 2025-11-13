// Package postgres implements the session storage driver for PostgreSQL.
package postgres

import (
	"context"
	"time"

	"github.com/cccteam/ccc"
	"github.com/cccteam/httpio"
	"github.com/cccteam/session/internal/dbtype"
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

// DestroySession marks the session as expired
func (d *SessionStorageDriver) DestroySession(ctx context.Context, sessionID ccc.UUID) error {
	ctx, span := ccc.StartTrace(ctx)
	defer span.End()

	query := `
		UPDATE "Sessions" SET "Expired" = TRUE
		WHERE "Id" = $1`

	if _, err := d.conn.Exec(ctx, query, sessionID); err != nil {
		return errors.Wrapf(err, "failed to update Sessions table for %s", sessionID)
	}

	return nil
}

// UpdateSessionActivity updates the session activity column with the current time
func (d *SessionStorageDriver) UpdateSessionActivity(ctx context.Context, sessionID ccc.UUID) error {
	ctx, span := ccc.StartTrace(ctx)
	defer span.End()

	query := `
		UPDATE "Sessions" SET "UpdatedAt" = $1
		WHERE "Id" = $2`

	res, err := d.conn.Exec(ctx, query, time.Now(), sessionID)
	if err != nil {
		return errors.Wrapf(err, "failed to update Sessions table for ID: %s", sessionID)
	}

	if cnt := res.RowsAffected(); cnt != 1 {
		return errors.Newf("failed to find Session %s", sessionID)
	}

	return nil
}

// Session returns the session information from the database for given sessionID
func (d *SessionStorageDriver) Session(ctx context.Context, sessionID ccc.UUID) (*dbtype.Session, error) {
	ctx, span := ccc.StartTrace(ctx)
	defer span.End()

	query := `
		SELECT
			"Id", "Username", "CreatedAt", "UpdatedAt", "Expired"
		FROM "Sessions"
		WHERE "Id" = $1
	`

	i := &dbtype.Session{}
	if err := pgxscan.Get(ctx, d.conn, i, query, sessionID); err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, httpio.NewNotFoundMessagef("session %s not found in database", sessionID)
		}

		return nil, errors.Wrapf(err, "failed to scan row for session %s", sessionID)
	}

	return i, nil
}

// InsertSession inserts Session into database
func (d *SessionStorageDriver) InsertSession(ctx context.Context, session *dbtype.InsertSession) (ccc.UUID, error) {
	ctx, span := ccc.StartTrace(ctx)
	defer span.End()

	id, err := ccc.NewUUID()
	if err != nil {
		return ccc.NilUUID, errors.Wrap(err, "failed to generate UUID for session")
	}

	query := `
		INSERT INTO "Sessions"
			("Id", "Username", "CreatedAt", "UpdatedAt", "Expired")
		VALUES
			($1, $2, $3, $4, $5)
		`

	if _, err := d.conn.Exec(ctx, query, id, session.Username, session.CreatedAt, session.UpdatedAt, session.Expired); err != nil {
		return ccc.NilUUID, errors.Wrap(err, "failed to insert into table Sessions")
	}

	return id, nil
}
