// Package spanner provides the session storage driver for Spanner.
package spanner

import (
	"context"
	"fmt"
	"time"

	"cloud.google.com/go/spanner"
	"github.com/cccteam/ccc"
	"github.com/cccteam/ccc/securehash"
	"github.com/cccteam/httpio"
	"github.com/cccteam/session/internal/dbtype"
	"github.com/cccteam/spxscan"
	"github.com/go-playground/errors/v5"
	"google.golang.org/grpc/codes"
)

// SessionStorageDriver represents the session storage implementation for Spanner.
type SessionStorageDriver struct {
	spanner          *spanner.Client
	sessionTableName string
	userTableName    string
}

// NewSessionStorageDriver creates a new SessionStorageDriver
func NewSessionStorageDriver(client *spanner.Client) *SessionStorageDriver {
	return &SessionStorageDriver{
		spanner:          client,
		sessionTableName: "Sessions",
		userTableName:    "SessionUsers",
	}
}

// SetSessionTableName sets the name of the session table.
func (s *SessionStorageDriver) SetSessionTableName(name string) {
	s.sessionTableName = name
}

// SetUserTableName sets the name of the user table.
func (s *SessionStorageDriver) SetUserTableName(name string) {
	s.userTableName = name
}

// Session returns the session information from the database for given sessionID
func (s *SessionStorageDriver) Session(ctx context.Context, sessionID ccc.UUID) (*dbtype.Session, error) {
	ctx, span := ccc.StartTrace(ctx)
	defer span.End()

	stmt := spanner.NewStatement(fmt.Sprintf(`
		SELECT
			Id, 
			Username, 
			CreatedAt, 
			UpdatedAt, 
			Expired
		FROM %s
		WHERE Id = @id
	`, s.sessionTableName))
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

	mutation, err := spanner.UpdateStruct(s.sessionTableName, sessionUpdate)
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

	mutation, err := spanner.InsertStruct(s.sessionTableName, session)
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

	mutation, err := spanner.UpdateStruct(s.sessionTableName, sessionUpdate)
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

// User returns the user record associated with the user id
func (s *SessionStorageDriver) User(ctx context.Context, id ccc.UUID) (*dbtype.SessionUser, error) {
	ctx, span := ccc.StartTrace(ctx)
	defer span.End()

	stmt := spanner.NewStatement(fmt.Sprintf(`
		SELECT 
			Id,
			Username,
			PasswordHash,
			Disabled
		FROM %s
		WHERE Id = @id
	`, s.userTableName))
	stmt.Params["id"] = id

	user := &dbtype.SessionUser{}
	if err := spxscan.Get(ctx, s.spanner.Single(), user, stmt); err != nil {
		if errors.Is(err, spxscan.ErrNotFound) {
			return nil, httpio.NewNotFoundMessagef("user id %q does not exist", id)
		}

		return nil, errors.Wrap(err, "spxscan.Get()")
	}

	return user, nil
}

// UserByUserName returns the user record associated with the username
func (s *SessionStorageDriver) UserByUserName(ctx context.Context, username string) (*dbtype.SessionUser, error) {
	ctx, span := ccc.StartTrace(ctx)
	defer span.End()

	stmt := spanner.NewStatement(fmt.Sprintf(`
		SELECT 
			Id,
			Username,
			PasswordHash,
			Disabled
		FROM %s
		WHERE Username = @username
	`, s.userTableName))
	stmt.Params["username"] = username

	user := &dbtype.SessionUser{}
	if err := spxscan.Get(ctx, s.spanner.Single(), user, stmt); err != nil {
		if errors.Is(err, spxscan.ErrNotFound) {
			return nil, httpio.NewNotFoundMessagef("username %q does not exist", username)
		}

		return nil, errors.Wrap(err, "spxscan.Get()")
	}

	return user, nil
}

// UpdateUserPasswordHash updates the user password hash
func (s *SessionStorageDriver) UpdateUserPasswordHash(ctx context.Context, userID ccc.UUID, hash *securehash.Hash) error {
	ctx, span := ccc.StartTrace(ctx)
	defer span.End()

	passwordUpdate := struct {
		ID           ccc.UUID         `spanner:"Id"`
		PasswordHash *securehash.Hash `spanner:"PasswordHash"`
		UpdatedAt    time.Time        `spanner:"UpdatedAt"`
	}{
		ID:           userID,
		PasswordHash: hash,
		UpdatedAt:    time.Now(),
	}

	mutation, err := spanner.UpdateStruct(s.userTableName, passwordUpdate)
	if err != nil {
		return errors.Wrap(err, "spanner.UpdateStruct()")
	}

	if _, err := s.spanner.Apply(ctx, []*spanner.Mutation{mutation}); err != nil {
		if spanner.ErrCode(err) == codes.NotFound {
			return httpio.NewNotFoundMessagef("user id %q not found", passwordUpdate.ID)
		}

		return errors.Wrap(err, "spanner.Client.Apply()")
	}

	return nil
}
