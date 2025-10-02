package spanner

import (
	"context"

	"cloud.google.com/go/spanner"
	"github.com/cccteam/ccc"
	"github.com/cccteam/httpio"
	"github.com/cccteam/session/dbtype"
	"github.com/cccteam/spxscan"
	"github.com/go-playground/errors/v5"
	"go.opentelemetry.io/otel"
	"google.golang.org/grpc/codes"
)

// InsertSessionOIDC inserts a Session into database
func (d *SessionStorageDriver) InsertSessionOIDC(ctx context.Context, insertSession *dbtype.InsertSessionOIDC) (ccc.UUID, error) {
	ctx, span := otel.Tracer(name).Start(ctx, "client.InsertSessionOIDC()")
	defer span.End()

	id, err := ccc.NewUUID()
	if err != nil {
		return ccc.NilUUID, errors.Wrap(err, "ccc.NewUUID()")
	}

	session := &struct {
		ID ccc.UUID
		*dbtype.InsertSessionOIDC
	}{
		ID:                id,
		InsertSessionOIDC: insertSession,
	}

	mutation, err := spanner.InsertStruct("Sessions", session)
	if err != nil {
		return ccc.NilUUID, errors.Wrap(err, "spanner.InsertStruct()")
	}
	if _, err := d.spanner.Apply(ctx, []*spanner.Mutation{mutation}); err != nil {
		return ccc.NilUUID, errors.Wrap(err, "spanner.Client.Apply()")
	}

	return id, nil
}

// SessionOIDC returns the session information from the database for given sessionID
func (d *SessionStorageDriver) SessionOIDC(ctx context.Context, sessionID ccc.UUID) (*dbtype.SessionOIDC, error) {
	_, span := otel.Tracer(name).Start(ctx, "client.SessionOIDC()")
	defer span.End()

	stmt := spanner.NewStatement(`
		SELECT
			Id, OidcSid, Username, CreatedAt, UpdatedAt, Expired
		FROM Sessions
		WHERE Id = @id
	`)
	stmt.Params["id"] = sessionID

	s := &dbtype.SessionOIDC{}
	if err := spxscan.Get(ctx, d.spanner.Single(), s, stmt); err != nil {
		if errors.Is(err, spxscan.ErrNotFound) {
			return nil, httpio.NewNotFoundMessagef("session %q not found", sessionID)
		}

		return nil, errors.Wrapf(err, "failed to scan row for session %q", sessionID)
	}

	return s, nil
}

// DestroySessionOIDC marks the session as expired using the oidcSID
func (d *SessionStorageDriver) DestroySessionOIDC(ctx context.Context, oidcSID string) error {
	_, span := otel.Tracer(name).Start(ctx, "client.DestroySessionOIDC()")
	defer span.End()

	_, err := d.spanner.ReadWriteTransaction(ctx, func(_ context.Context, txn *spanner.ReadWriteTransaction) error {
		stmt := spanner.NewStatement(`
			UPDATE Sessions 
			SET Expired = TRUE, UpdatedAt = CURRENT_TIMESTAMP()
			WHERE NOT Expired AND Username = (
				SELECT Username
				FROM Sessions
				WHERE OidcSid = @oidcSID
			)
		`)
		stmt.Params["oidcSID"] = oidcSID

		if _, err := txn.Update(ctx, stmt); err != nil {
			return errors.Wrap(err, "spanner.ReadWriteTransaction().Update()")
		}

		return nil
	})
	if err != nil {
		if spanner.ErrCode(err) != codes.NotFound {
			return errors.Wrap(err, "spanner.Client.ReadWriteTransaction()")
		}
	}

	return nil
}
