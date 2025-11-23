// Package spanner provides the session storage driver for Spanner.
package spanner

import (
	"context"
	"time"

	"cloud.google.com/go/spanner"
	"github.com/cccteam/ccc"
	"github.com/cccteam/httpio"
	"github.com/cccteam/session/sessionstorage/internal/dbtype"
	"github.com/cccteam/spxscan"
	"github.com/go-playground/errors/v5"
	"google.golang.org/grpc/codes"
)

// SessionStorageDriver represents the session storage implementation for Spanner.
type SessionStorageDriver struct {
	spanner *spanner.Client
}

// NewSessionStorageDriver creates a new SessionStorageDriver
func NewSessionStorageDriver(client *spanner.Client) *SessionStorageDriver {
	return &SessionStorageDriver{
		spanner: client,
	}
}

// Session returns the session information from the database for given sessionID
func (s *SessionStorageDriver) Session(ctx context.Context, sessionID ccc.UUID) (*dbtype.Session, error) {
	ctx, span := ccc.StartTrace(ctx)
	defer span.End()

	stmt := spanner.NewStatement(`
		SELECT
			Id, Username, CreatedAt, UpdatedAt, Expired
		FROM Sessions
		WHERE Id = @id
	`)
	stmt.Params["id"] = sessionID

	session := &dbtype.Session{}
	if err := spxscan.Get(ctx, s.spanner.Single(), session, stmt); err != nil {
		if errors.Is(err, spxscan.ErrNotFound) {
			return nil, httpio.NewNotFoundMessagef("session %q not found", sessionID)
		}

		return nil, errors.Wrapf(err, "failed to scan row for session %q", sessionID)
	}

	return session, nil
}

// UpdateSessionActivity updates the session activity column with the current time
func (s *SessionStorageDriver) UpdateSessionActivity(ctx context.Context, sessionID ccc.UUID) error {
	ctx, span := ccc.StartTrace(ctx)
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

	if _, err := s.spanner.Apply(ctx, []*spanner.Mutation{mutation}); err != nil {
		if spanner.ErrCode(err) == codes.NotFound {
			return httpio.NewNotFoundMessagef("session %q not found", sessionUpdate.ID)
		}

		return errors.Wrap(err, "spanner.Client.Apply()")
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

	session := &struct {
		ID ccc.UUID
		*dbtype.InsertSession
	}{
		ID:            id,
		InsertSession: insertSession,
	}

	mutation, err := spanner.InsertStruct("Sessions", session)
	if err != nil {
		return ccc.NilUUID, errors.Wrap(err, "spanner.InsertStruct()")
	}
	if _, err := s.spanner.Apply(ctx, []*spanner.Mutation{mutation}); err != nil {
		return ccc.NilUUID, errors.Wrap(err, "spanner.Client.Apply()")
	}

	return id, nil
}

// DestroySession marks the session as expired
func (s *SessionStorageDriver) DestroySession(ctx context.Context, sessionID ccc.UUID) error {
	ctx, span := ccc.StartTrace(ctx)
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

	if _, err := s.spanner.Apply(ctx, []*spanner.Mutation{mutation}); err != nil {
		if spanner.ErrCode(err) != codes.NotFound {
			return errors.Wrap(err, "spanner.Client.Apply()")
		}
	}

	return nil
}
