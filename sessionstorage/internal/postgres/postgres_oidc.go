package postgres

import (
	"context"

	"github.com/cccteam/ccc"
	"github.com/cccteam/session/sessionstorage/internal/dbtype"
	"github.com/go-playground/errors/v5"
)

// InsertSessionOIDC inserts a Session into database
func (s *SessionStorageDriver) InsertSessionOIDC(ctx context.Context, insertSession *dbtype.InsertSessionOIDC) (ccc.UUID, error) {
	ctx, span := ccc.StartTrace(ctx)
	defer span.End()

	id, err := ccc.NewUUID()
	if err != nil {
		return ccc.NilUUID, errors.Wrap(err, "ccc.NewUUID()")
	}

	query := `
		INSERT INTO "Sessions"
			("Id", "OidcSid", "Username", "CreatedAt", "UpdatedAt", "Expired")
		VALUES
			($1, $2, $3, $4, $5, $6)
		`

	if _, err := s.conn.Exec(ctx, query, id, insertSession.OidcSID, insertSession.Username, insertSession.CreatedAt, insertSession.UpdatedAt, insertSession.Expired); err != nil {
		return ccc.NilUUID, errors.Wrap(err, "Queryer.Exec()")
	}

	return id, nil
}

// DestroySessionOIDC marks the session as expired using the oidcSID
func (s *SessionStorageDriver) DestroySessionOIDC(ctx context.Context, oidcSID string) error {
	ctx, span := ccc.StartTrace(ctx)
	defer span.End()

	query := `
		UPDATE "Sessions" SET "Expired" = TRUE
		WHERE NOT "Expired" AND "Username" = (
			SELECT "Username"
			FROM "Sessions"
			WHERE "OidcSid" = $1
		)`

	if _, err := s.conn.Exec(ctx, query, oidcSID); err != nil {
		return errors.Wrapf(err, "failed to destroy sessions for user with OIDC session: %s", oidcSID)
	}

	return nil
}
