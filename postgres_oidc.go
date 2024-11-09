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

type PostgresOIDCSessionStorage struct {
	db DB
}

func NewPostgresOIDCSessionStorage(db postgres.Queryer) *PostgresOIDCSessionStorage {
	return &PostgresOIDCSessionStorage{
		db: postgres.NewSessionStorageDriver(db),
	}
}

// NewSession inserts SessionInfo into database
func (p *PostgresOIDCSessionStorage) NewSession(ctx context.Context, username, oidcSID string) (ccc.UUID, error) {
	ctx, span := otel.Tracer(name).Start(ctx, "PostgresOIDCSessionStorage.NewSession()")
	defer span.End()

	session := &dbtypes.InsertSessionOIDC{
		OidcSID:   oidcSID,
		Username:  username,
		CreatedAt: time.Now(),
		UpdatedAt: time.Now(),
	}

	id, err := p.db.InsertSessionOIDC(ctx, session)
	if err != nil {
		return ccc.NilUUID, errors.Wrap(err, "PostgresOIDCSessionStorage.insertSession()")
	}

	return id, nil
}

// DestroySessionOIDC marks the session as expired
func (p *PostgresOIDCSessionStorage) DestroySessionOIDC(ctx context.Context, oidcSID string) error {
	ctx, span := otel.Tracer(name).Start(ctx, "PostgresOIDCSessionStorage.DestroySessionOIDC()")
	defer span.End()

	if err := p.db.DestroySessionOIDC(ctx, oidcSID); err != nil {
		return errors.Wrap(err, "failed to destroy session")
	}

	return nil
}

// Session returns the session information from the database for given sessionID
func (p *PostgresOIDCSessionStorage) Session(ctx context.Context, sessionID ccc.UUID) (*sessioninfo.SessionInfo, error) {
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
func (p *PostgresOIDCSessionStorage) UpdateSessionActivity(ctx context.Context, sessionID ccc.UUID) error {
	ctx, span := otel.Tracer(name).Start(ctx, "PostgresqlSessionStorage.UpdateSessionActivity()")
	defer span.End()

	if err := p.db.UpdateSessionActivity(ctx, sessionID); err != nil {
		return errors.Wrap(err, "db.updateSessionActivity()")
	}

	return nil
}

// DestroySession marks the session as expired
func (p *PostgresOIDCSessionStorage) DestroySession(ctx context.Context, sessionID ccc.UUID) error {
	ctx, span := otel.Tracer(name).Start(ctx, "PostgresqlSessionStorage.DestroySession()")
	defer span.End()

	if err := p.db.DestroySession(ctx, sessionID); err != nil {
		return errors.Wrap(err, "db.DestroySession()")
	}

	return nil
}
