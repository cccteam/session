package sessionstorage

import (
	"context"
	"reflect"
	"time"

	"github.com/cccteam/ccc"
	"github.com/cccteam/ccc/tracer"
	"github.com/cccteam/httpio"
	"github.com/cccteam/session/internal/dbtype"
	"github.com/cccteam/session/sessioninfo"
	"github.com/go-playground/errors/v5"
)

// sessionStorage is what you use to create / update sessions inside of the handlers or as a standalone if you don't want the handlers
type sessionStorage struct {
	db db
}

// SetSessionTableName sets the name of the session table.
func (s *sessionStorage) SetSessionTableName(name string) {
	s.db.SetSessionTableName(name)
}

// SetUserTableName sets the name of the user table.
func (s *sessionStorage) SetUserTableName(name string) {
	s.db.SetUserTableName(name)
}

// NewSession inserts SessionInfo into the database. customData is nil or *T for the
// configured custom session data struct type; when non-nil it is written atomically
// with the session insert (per-call data wins over any configured resolver) and
// requires a custom session data configuration on the storage.
func (s *sessionStorage) NewSession(ctx context.Context, username string, customData any) (ccc.UUID, error) {
	ctx, span := tracer.Start(ctx)
	defer span.End()

	session := &dbtype.InsertSession{
		Username:  username,
		CreatedAt: time.Now(),
		UpdatedAt: time.Now(),
	}

	req := &sessioninfo.NewSessionRequest{
		Reason:     sessioninfo.ReasonPreauth,
		Username:   username,
		CustomData: customData,
	}

	id, err := s.db.InsertSession(ctx, session, req)
	if err != nil {
		return ccc.NilUUID, errors.Wrap(err, "db.InsertSession()")
	}

	return id, nil
}

// Session returns the session information from the database for given sessionID
func (s *sessionStorage) Session(ctx context.Context, sessionID ccc.UUID) (*sessioninfo.SessionData, error) {
	ctx, span := tracer.Start(ctx)
	defer span.End()

	si, err := s.db.Session(ctx, sessionID)
	if err != nil {
		return nil, errors.Wrap(err, "db.Session()")
	}

	return &sessioninfo.SessionData{
		SessionInfo: (*sessioninfo.SessionInfo)(si.Session),
		CustomData:  si.CustomData,
	}, nil
}

// UpdateSessionActivity updates the database with the current time for the session activity
func (s *sessionStorage) UpdateSessionActivity(ctx context.Context, sessionID ccc.UUID) error {
	ctx, span := tracer.Start(ctx)
	defer span.End()

	if err := s.db.UpdateSessionActivity(ctx, sessionID); err != nil {
		return errors.Wrap(err, "db.UpdateSessionActivity()")
	}

	return nil
}

// DestroySession marks the session as expired
func (s *sessionStorage) DestroySession(ctx context.Context, sessionID ccc.UUID) error {
	ctx, span := tracer.Start(ctx)
	defer span.End()

	if err := s.db.DestroySession(ctx, sessionID); err != nil {
		return errors.Wrap(err, "db.DestroySession()")
	}

	return nil
}

// UpdateCustomSessionData updates the custom session data for an active session via a
// transactional read-modify-write: mutate receives the current row as *T for the
// configured struct type (zero-value when no row exists) and the full row is written
// back; a mutate error aborts with nothing written. It is intended for genuine
// mid-session updates only — initial population belongs in the session-creation
// transaction.
func (s *sessionStorage) UpdateCustomSessionData(ctx context.Context, sessionID ccc.UUID, mutate func(data any) error) error {
	ctx, span := tracer.Start(ctx)
	defer span.End()

	session, err := s.db.Session(ctx, sessionID)
	if err != nil {
		return errors.Wrap(err, "db.Session()")
	}

	if session.Expired {
		return httpio.NewBadRequestMessage("cannot update custom session data for an expired session")
	}

	if err := s.db.UpdateCustomSessionData(ctx, sessionID, mutate); err != nil {
		return errors.Wrap(err, "db.UpdateCustomSessionData()")
	}

	return nil
}

// CustomDataType returns the struct type the attached custom session data
// configuration was built for, or nil when no configuration is attached.
func (s *sessionStorage) CustomDataType() reflect.Type {
	return s.db.CustomDataType()
}

// DestroyAllUserSessions destroys all sessions for a given user
func (s *sessionStorage) DestroyAllUserSessions(ctx context.Context, username string) error {
	ctx, span := tracer.Start(ctx)
	defer span.End()

	if err := s.db.DestroyAllUserSessions(ctx, username); err != nil {
		return errors.Wrap(err, "db.DestroyAllUserSessions()")
	}

	return nil
}
