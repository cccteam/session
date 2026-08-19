package spanner

import (
	"context"
	"fmt"

	"cloud.google.com/go/spanner"
	"github.com/cccteam/ccc"
	"github.com/cccteam/ccc/tracer"
	"github.com/cccteam/session/internal/dbtype"
	"github.com/cccteam/session/sessioninfo"
	"github.com/go-playground/errors/v5"
)

// InsertSessionOIDC inserts an OIDC Session into the database and returns its id. It
// honors the request's custom session data semantics: per-call data or a configured
// resolver is written atomically with the session insert; a resolver error aborts the
// insert (see SessionStorageDriver.applySessionInsert).
func (s *SessionStorageDriver) InsertSessionOIDC(ctx context.Context, insertSession *dbtype.InsertOIDCSession, req *sessioninfo.NewSessionRequest) (ccc.UUID, error) {
	ctx, span := tracer.Start(ctx)
	defer span.End()

	id, err := ccc.NewUUID()
	if err != nil {
		return ccc.NilUUID, errors.Wrap(err, "ccc.NewUUID()")
	}

	session := &struct {
		ID ccc.UUID
		*dbtype.InsertOIDCSession
	}{
		ID:                id,
		InsertOIDCSession: insertSession,
	}

	mutation, err := spanner.InsertStruct(s.sessionTableName, session)
	if err != nil {
		return ccc.NilUUID, errors.Wrap(err, "spanner.InsertStruct()")
	}

	if err := s.applySessionInsert(ctx, id, mutation, req); err != nil {
		return ccc.NilUUID, err
	}

	return id, nil
}

// DestroySessionOIDC marks the session as expired using the oidcSID
func (s *SessionStorageDriver) DestroySessionOIDC(ctx context.Context, oidcSID string) error {
	ctx, span := tracer.Start(ctx)
	defer span.End()

	_, err := s.spanner.ReadWriteTransaction(ctx, func(_ context.Context, txn *spanner.ReadWriteTransaction) error {
		stmt := spanner.NewStatement(fmt.Sprintf(`
			UPDATE %[1]s
			SET Expired = TRUE, UpdatedAt = CURRENT_TIMESTAMP()
			WHERE NOT Expired AND Username = (
				SELECT Username
				FROM %[1]s
				WHERE OidcSid = @oidcSID
			)
		`, s.sessionTableName))
		stmt.Params["oidcSID"] = oidcSID

		if _, err := txn.Update(ctx, stmt); err != nil {
			return errors.Wrap(err, "spanner.ReadWriteTransaction.Update()")
		}

		return nil
	})
	if err != nil {
		return errors.Wrap(err, "spanner.Client.ReadWriteTransaction()")
	}

	return nil
}
