package db

import (
	"context"
	"time"

	"github.com/cccteam/ccc"
	"github.com/cccteam/httpio"
	"github.com/georgysavva/scany/v2/pgxscan"
	"github.com/go-playground/errors/v5"
	"github.com/jackc/pgx/v5"
	"go.opentelemetry.io/otel"
)

type Session struct {
	ID        ccc.UUID  `db:"Id"`
	OidcSID   string    `db:"OidcSid"`
	Username  string    `db:"Username"`
	CreatedAt time.Time `db:"CreatedAt"`
	UpdatedAt time.Time `db:"UpdatedAt"`
	Expired   bool      `db:"Expired"`
}

type InsertSession struct {
	OidcSID   string    `db:"OidcSid"`
	Username  string    `db:"Username"`
	CreatedAt time.Time `db:"CreatedAt"`
	UpdatedAt time.Time `db:"UpdatedAt"`
	Expired   bool      `db:"Expired"`
}

type Connection struct {
	name string
	conn Queryer
}

func NewDBConnection(conn Queryer) *Connection {
	return &Connection{
		conn: conn,
	}
}

func (d *Connection) DestroySession(ctx context.Context, sessionID ccc.UUID) error {
	ctx, span := otel.Tracer(d.name).Start(ctx, "Connection.DestroySession()")
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
func (d *Connection) UpdateSessionActivity(ctx context.Context, sessionID ccc.UUID) error {
	ctx, span := otel.Tracer(d.name).Start(ctx, "Connection.UpdateSessionActivity()")
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
func (d *Connection) Session(ctx context.Context, sessionID ccc.UUID) (*Session, error) {
	ctx, span := otel.Tracer(d.name).Start(ctx, "Connection.Session()")
	defer span.End()

	query := `
		SELECT
			"Id", "OidcSid", "Username", "CreatedAt", "UpdatedAt", "Expired"
		FROM "Sessions"
		WHERE "Id" = $1
	`

	i := &Session{}
	if err := pgxscan.Get(ctx, d.conn, i, query, sessionID); err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, httpio.NewNotFoundMessagef("session %s not found in database", sessionID)
		}

		return nil, errors.Wrapf(err, "failed to scan row for session %s", sessionID)
	}

	return i, nil
}

// InsertSession inserts Session into database
func (d *Connection) InsertSession(ctx context.Context, session *InsertSession) (ccc.UUID, error) {
	ctx, span := otel.Tracer(d.name).Start(ctx, "Connection.InsertSession()")
	defer span.End()

	id, err := ccc.NewUUID()
	if err != nil {
		return ccc.NilUUID, errors.Wrap(err, "failed to generate UUID for session")
	}

	query := `
		INSERT INTO "Sessions"
			("Id", "OidcSid", "Username", "CreatedAt", "UpdatedAt", "Expired")
		VALUES
			($1, $2, $3, $4, $5, $6)
		`

	if _, err := d.conn.Exec(ctx, query, id, session.OidcSID, session.Username, session.CreatedAt, session.UpdatedAt, session.Expired); err != nil {
		return ccc.NilUUID, errors.Wrap(err, "failed to insert into table Sessions")
	}

	return id, nil
}

// DestroySessionOIDC marks the session as expired
func (d *Connection) DestroySessionOIDC(ctx context.Context, oidcSID string) error {
	ctx, span := otel.Tracer(d.name).Start(ctx, "Connection.DestroySessionOIDC()")
	defer span.End()

	query := `
		UPDATE "Sessions" SET "Expired" = TRUE
		WHERE NOT "Expired" AND "Username" = (
			SELECT "Username"
			FROM "Sessions"
			WHERE "OidcSid" = $1
		)`

	_, err := d.conn.Exec(ctx, query, oidcSID)
	if err != nil {
		return errors.Wrapf(err, "failed to destroy sessions for user with OIDC session: %s", oidcSID)
	}

	return nil
}
