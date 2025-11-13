package sessionstorage

import (
	"context"
	"time"

	"github.com/cccteam/ccc"
	"github.com/cccteam/session/internal/dbtype"
	"github.com/cccteam/session/sessioninfo"
	"github.com/cccteam/session/sessionstorage/internal/postgres"
	"github.com/go-playground/errors/v5"
)

// PostgresPreauth is what you use to create / update sessions inside of the handlers or as a standalone if you don't want the handlers
type PostgresPreauth struct {
	db db
}

// NewPostgresPreauth is the function that you use to create the session manager that handles the session creation and updates
func NewPostgresPreauth(db postgres.Queryer) *PostgresPreauth {
	return &PostgresPreauth{
		db: postgres.NewSessionStorageDriver(db),
	}
}

// NewSession inserts SessionInfo into the spanner database
func (p *PostgresPreauth) NewSession(ctx context.Context, username string) (ccc.UUID, error) {
	ctx, span := ccc.StartTrace(ctx)
	defer span.End()

	session := &dbtype.InsertSession{
		Username:  username,
		CreatedAt: time.Now(),
		UpdatedAt: time.Now(),
	}

	id, err := p.db.InsertSession(ctx, session)
	if err != nil {
		return ccc.NilUUID, errors.Wrap(err, "PostgresPreauthSessionStorage.db.InsertSession()")
	}

	return id, nil
}

// Session returns the session information from the database for given sessionID
func (p *PostgresPreauth) Session(ctx context.Context, sessionID ccc.UUID) (*sessioninfo.SessionInfo, error) {
	ctx, span := ccc.StartTrace(ctx)
	defer span.End()

	si, err := p.db.Session(ctx, sessionID)
	if err != nil {
		return nil, errors.Wrap(err, "PostgresPreauthSessionStorage.db.Session()")
	}

	return &sessioninfo.SessionInfo{
		ID:        si.ID,
		Username:  si.Username,
		CreatedAt: si.CreatedAt,
		UpdatedAt: si.UpdatedAt,
		Expired:   si.Expired,
	}, nil
}

// UpdateSessionActivity updates the database with the current time for the session activity
func (p *PostgresPreauth) UpdateSessionActivity(ctx context.Context, sessionID ccc.UUID) error {
	ctx, span := ccc.StartTrace(ctx)
	defer span.End()

	if err := p.db.UpdateSessionActivity(ctx, sessionID); err != nil {
		return errors.Wrap(err, "PostgresPreauthSessionStorage.db.UpdateSessionActivity()")
	}

	return nil
}

// DestroySession marks the session as expired
func (p *PostgresPreauth) DestroySession(ctx context.Context, sessionID ccc.UUID) error {
	ctx, span := ccc.StartTrace(ctx)
	defer span.End()

	if err := p.db.DestroySession(ctx, sessionID); err != nil {
		return errors.Wrap(err, "PostgresPreauthSessionStorage.db.DestroySession()")
	}

	return nil
}
