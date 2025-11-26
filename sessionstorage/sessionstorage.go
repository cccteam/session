package sessionstorage

import (
	"context"
	"time"

	"github.com/cccteam/ccc"
	"github.com/cccteam/session/sessioninfo"
	"github.com/cccteam/session/sessionstorage/internal/dbtype"
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

// NewSession inserts SessionInfo into the spanner database
func (s *sessionStorage) NewSession(ctx context.Context, username string) (ccc.UUID, error) {
	ctx, span := ccc.StartTrace(ctx)
	defer span.End()

	session := &dbtype.InsertSession{
		Username:  username,
		CreatedAt: time.Now(),
		UpdatedAt: time.Now(),
	}

	id, err := s.db.InsertSession(ctx, session)
	if err != nil {
		return ccc.NilUUID, errors.Wrap(err, "db.InsertSession()")
	}

	return id, nil
}

// Session returns the session information from the database for given sessionID
func (s *sessionStorage) Session(ctx context.Context, sessionID ccc.UUID) (*sessioninfo.SessionInfo, error) {
	ctx, span := ccc.StartTrace(ctx)
	defer span.End()

	si, err := s.db.Session(ctx, sessionID)
	if err != nil {
		return nil, errors.Wrap(err, "db.Session()")
	}

	return (*sessioninfo.SessionInfo)(si), nil
}

// UpdateSessionActivity updates the database with the current time for the session activity
func (s *sessionStorage) UpdateSessionActivity(ctx context.Context, sessionID ccc.UUID) error {
	ctx, span := ccc.StartTrace(ctx)
	defer span.End()

	if err := s.db.UpdateSessionActivity(ctx, sessionID); err != nil {
		return errors.Wrap(err, "db.UpdateSessionActivity()")
	}

	return nil
}

// DestroySession marks the session as expired
func (s *sessionStorage) DestroySession(ctx context.Context, sessionID ccc.UUID) error {
	ctx, span := ccc.StartTrace(ctx)
	defer span.End()

	if err := s.db.DestroySession(ctx, sessionID); err != nil {
		return errors.Wrap(err, "db.DestroySession()")
	}

	return nil
}
