package postgres

import (
	"context"

	"github.com/cccteam/ccc"
	"github.com/cccteam/httpio"
	"github.com/cccteam/session/internal/dbtype"
	"github.com/georgysavva/scany/v2/pgxscan"
	"github.com/go-playground/errors/v5"
	"github.com/jackc/pgx/v5"
)

// SessionOIDC returns the session information from the database for given sessionID
func (d *SessionStorageDriver) SessionOIDC(ctx context.Context, sessionID ccc.UUID) (*dbtype.SessionOIDC, error) {
	ctx, span := ccc.StartTrace(ctx)
	defer span.End()

	query := `
		SELECT
			"Id", "OidcSid", "Username", "CreatedAt", "UpdatedAt", "Expired"
		FROM "Sessions"
		WHERE "Id" = $1
	`

	i := &dbtype.SessionOIDC{}
	if err := pgxscan.Get(ctx, d.conn, i, query, sessionID); err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, httpio.NewNotFoundMessagef("session %s not found in database", sessionID)
		}

		return nil, errors.Wrapf(err, "failed to scan row for session %s", sessionID)
	}

	return i, nil
}

// InsertSessionOIDC inserts Session into database
func (d *SessionStorageDriver) InsertSessionOIDC(ctx context.Context, session *dbtype.InsertSessionOIDC) (ccc.UUID, error) {
	ctx, span := ccc.StartTrace(ctx)
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
func (d *SessionStorageDriver) DestroySessionOIDC(ctx context.Context, oidcSID string) error {
	ctx, span := ccc.StartTrace(ctx)
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
