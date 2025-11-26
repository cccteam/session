package postgres

import (
	"context"
	"fmt"

	"github.com/cccteam/ccc"
	"github.com/cccteam/session/sessionstorage/internal/dbtype"
	"github.com/go-playground/errors/v5"
)

// InsertSessionOIDC inserts a Session into database
func (s *SessionStorageDriver) InsertSessionOIDC(ctx context.Context, insertSession *dbtype.InsertOIDCSession) (ccc.UUID, error) {
	ctx, span := ccc.StartTrace(ctx)
	defer span.End()

	id, err := ccc.NewUUID()
	if err != nil {
		return ccc.NilUUID, errors.Wrap(err, "ccc.NewUUID()")
	}

	query := fmt.Sprintf(`
		INSERT INTO "%s"
			("Id", "OidcSid", "Username", "CreatedAt", "UpdatedAt", "Expired")
		VALUES
			($1, $2, $3, $4, $5, $6)
		`, s.sessionTableName)

	if _, err := s.conn.Exec(ctx, query, id, insertSession.OidcSID, insertSession.Username, insertSession.CreatedAt, insertSession.UpdatedAt, insertSession.Expired); err != nil {
		return ccc.NilUUID, errors.Wrap(err, "Queryer.Exec()")
	}

	return id, nil
}

// DestroySessionOIDC marks the session as expired using the oidcSID
func (s *SessionStorageDriver) DestroySessionOIDC(ctx context.Context, oidcSID string) error {
	ctx, span := ccc.StartTrace(ctx)
	defer span.End()

	query := fmt.Sprintf(`
		UPDATE "%[1]s" SET "Expired" = TRUE
		WHERE NOT "Expired" AND "Username" = (
			SELECT "Username"
			FROM "%[1]s"
			WHERE "OidcSid" = $1
		)`, s.sessionTableName)

	if _, err := s.conn.Exec(ctx, query, oidcSID); err != nil {
		return errors.Wrap(err, "Queryer.Exec()")
	}

	return nil
}
