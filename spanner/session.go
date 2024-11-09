package spanner

import (
	"context"
	"time"

	"cloud.google.com/go/spanner"
	"github.com/cccteam/ccc"
	"github.com/cccteam/httpio"
	"github.com/cccteam/session/dbtypes"
	"github.com/cccteam/spxscan"
	"github.com/go-playground/errors/v5"
	"go.opentelemetry.io/otel"
	"google.golang.org/grpc/codes"
)

// Session returns the session information from the database for given sessionID
func (d *SessionStorageDriver) Session(ctx context.Context, sessionID ccc.UUID) (*dbtypes.Session, error) {
	_, span := otel.Tracer(name).Start(ctx, "SessionStorageDriver.Session()")
	defer span.End()

	stmt := spanner.NewStatement(`
		SELECT
			Id, Username, CreatedAt, UpdatedAt, Expired
		FROM Sessions
		WHERE Id = @id
	`)
	stmt.Params["id"] = sessionID

	s := &dbtypes.Session{}
	if err := spxscan.Get(ctx, d.spanner.Single(), s, stmt); err != nil {
		if errors.Is(err, spxscan.ErrNotFound) {
			return nil, httpio.NewNotFoundMessagef("session %q not found", sessionID)
		}

		return nil, errors.Wrapf(err, "failed to scan row for session %q", sessionID)
	}

	return s, nil
}

// UpdateSessionActivity updates the session activity column with the current time
func (d *SessionStorageDriver) UpdateSessionActivity(ctx context.Context, sessionID ccc.UUID) error {
	_, span := otel.Tracer(name).Start(ctx, "SessionStorageDriver.UpdateSessionActivity()")
	defer span.End()

	sessionUpdate := struct {
		ID        ccc.UUID  `spanner:"Id"`
		UpdatedAt time.Time `spanner:"UpdatedAt"`
	}{
		ID:        sessionID,
		UpdatedAt: time.Now(),
	}

	mutation, err := spanner.UpdateStruct("Sessions", sessionUpdate)
	if err != nil {
		return errors.Wrap(err, "spanner.UpdateStruct()")
	}

	if _, err := d.spanner.Apply(ctx, []*spanner.Mutation{mutation}); err != nil {
		if spanner.ErrCode(err) == codes.NotFound {
			return httpio.NewNotFoundMessagef("session %q not found", sessionUpdate.ID)
		}

		return errors.Wrap(err, "spanner.Client.Apply()")
	}

	return nil
}

// InsertSession inserts a Session into database
func (d *SessionStorageDriver) InsertSession(ctx context.Context, insertSession *dbtypes.InsertSession) (ccc.UUID, error) {
	ctx, span := otel.Tracer(name).Start(ctx, "SessionStorageDriver.InsertSession()")
	defer span.End()

	id, err := ccc.NewUUID()
	if err != nil {
		return ccc.NilUUID, errors.Wrap(err, "ccc.NewUUID()")
	}

	session := &struct {
		ID ccc.UUID
		*dbtypes.InsertSession
	}{
		ID:            id,
		InsertSession: insertSession,
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

// DestroySession marks the session as expired
func (d *SessionStorageDriver) DestroySession(ctx context.Context, sessionID ccc.UUID) error {
	_, span := otel.Tracer(name).Start(ctx, "SessionStorageDriver.DestroySession()")
	defer span.End()

	sessionUpdate := struct {
		ID        ccc.UUID  `spanner:"Id"`
		Expired   bool      `spanner:"Expired"`
		UpdatedAt time.Time `spanner:"UpdatedAt"`
	}{
		ID:        sessionID,
		Expired:   true,
		UpdatedAt: time.Now(),
	}

	mutation, err := spanner.UpdateStruct("Sessions", sessionUpdate)
	if err != nil {
		return errors.Wrap(err, "spanner.UpdateStruct()")
	}

	if _, err := d.spanner.Apply(ctx, []*spanner.Mutation{mutation}); err != nil {
		if !(spanner.ErrCode(err) == codes.NotFound) {
			return errors.Wrap(err, "spanner.Client.Apply()")
		}
	}

	return nil
}
