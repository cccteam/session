package postgres

import (
	"context"
	"fmt"

	"github.com/cccteam/ccc"
	"github.com/cccteam/ccc/tracer"
	"github.com/cccteam/session/internal/dbtype"
	"github.com/cccteam/session/sessioninfo"
	"github.com/go-playground/errors/v5"
)

// InsertSessionOIDC inserts an OIDC Session into the database and returns its id. It
// honors the request's custom session data semantics: per-call data or a configured
// resolver is written atomically with the session insert; a resolver error aborts the
// insert (see SessionStorageDriver.execSessionInsert).
func (s *SessionStorageDriver) InsertSessionOIDC(ctx context.Context, insertSession *dbtype.InsertOIDCSession, req *sessioninfo.NewSessionRequest) (ccc.UUID, error) {
	ctx, span := tracer.Start(ctx)
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
	args := []any{id, insertSession.OidcSID, insertSession.Username, insertSession.CreatedAt, insertSession.UpdatedAt, insertSession.Expired}

	if err := s.execSessionInsert(ctx, id, query, args, req); err != nil {
		return ccc.NilUUID, err
	}

	return id, nil
}

// DestroySessionOIDC marks the session as expired using the oidcSID
func (s *SessionStorageDriver) DestroySessionOIDC(ctx context.Context, oidcSID string) error {
	ctx, span := tracer.Start(ctx)
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
