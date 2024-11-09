package session

import (
	"context"
	"time"

	"github.com/cccteam/ccc"
	"github.com/cccteam/session/dbtypes"
	"github.com/cccteam/session/postgres"
	"github.com/cccteam/session/sessioninfo"
	"github.com/go-playground/errors/v5"
	"go.opentelemetry.io/otel"
)

// PostgresPreauthSessionStorage is what you use to create / update sessions inside of the handlers or as a standalone if you don't want the handlers
type PostgresPreauthSessionStorage struct {
	db DB
}

// NewPostgresPreauthSessionStorage is the function that you use to create the session manager that handles the session creation and updates
func NewPostgresPreauthSessionStorage(db postgres.Queryer) *PostgresPreauthSessionStorage {
	return &PostgresPreauthSessionStorage{
		db: postgres.NewStorageDriver(db),
	}
}

// NewSession inserts SessionInfo into the spanner database
func (p *PostgresPreauthSessionStorage) NewSession(ctx context.Context, username string) (ccc.UUID, error) {
	ctx, span := otel.Tracer(name).Start(ctx, "PostgresPreauthSessionStorage.NewSession()")
	defer span.End()

	session := &dbtypes.InsertSession{
		Username:  username,
		CreatedAt: time.Now(),
		UpdatedAt: time.Now(),
	}

	id, err := p.db.InsertSession(ctx, session)
	if err != nil {
		return ccc.NilUUID, errors.Wrap(err, "PostgresPreauthSessionStorage.insertSession()")
	}

	return id, nil
}

// Session returns the session information from the database for given sessionID
func (p *PostgresPreauthSessionStorage) Session(ctx context.Context, sessionID ccc.UUID) (*sessioninfo.SessionInfo, error) {
	ctx, span := otel.Tracer(name).Start(ctx, "Client.Session()")
	defer span.End()

	si, err := p.db.Session(ctx, sessionID)
	if err != nil {
		return nil, errors.Wrap(err, "dbx.DB.Session()")
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
func (p *PostgresPreauthSessionStorage) UpdateSessionActivity(ctx context.Context, sessionID ccc.UUID) error {
	ctx, span := otel.Tracer(name).Start(ctx, "PostgresPreauthSessionStorage.UpdateSessionActivity()")
	defer span.End()

	if err := p.db.UpdateSessionActivity(ctx, sessionID); err != nil {
		return errors.Wrap(err, "db.updateSessionActivity()")
	}

	return nil
}

// DestroySession marks the session as expired
func (p *PostgresPreauthSessionStorage) DestroySession(ctx context.Context, sessionID ccc.UUID) error {
	ctx, span := otel.Tracer(name).Start(ctx, "PostgresPreauthSessionStorage.DestroySession()")
	defer span.End()

	if err := p.db.DestroySession(ctx, sessionID); err != nil {
		return errors.Wrap(err, "db.DestroySession()")
	}

	return nil
}
