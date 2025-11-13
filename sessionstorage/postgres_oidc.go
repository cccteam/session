package sessionstorage

import (
	"context"
	"time"

	"github.com/cccteam/ccc"
	"github.com/cccteam/session/sessioninfo"
	"github.com/cccteam/session/sessionstorage/internal/dbtype"
	"github.com/cccteam/session/sessionstorage/internal/postgres"
	"github.com/go-playground/errors/v5"
)

// PostgresOIDC is the session storage implementation for PostgreSQL with OIDC support.
type PostgresOIDC struct {
	db db
}

// NewPostgresOIDC creates a new PostgresOIDC instance.
func NewPostgresOIDC(db postgres.Queryer) *PostgresOIDC {
	return &PostgresOIDC{
		db: postgres.NewSessionStorageDriver(db),
	}
}

// NewSession inserts SessionInfo into database
func (p *PostgresOIDC) NewSession(ctx context.Context, username, oidcSID string) (ccc.UUID, error) {
	ctx, span := ccc.StartTrace(ctx)
	defer span.End()

	session := &dbtype.InsertSessionOIDC{
		OidcSID: oidcSID,
		InsertSession: dbtype.InsertSession{
			Username:  username,
			CreatedAt: time.Now(),
			UpdatedAt: time.Now(),
		},
	}

	id, err := p.db.InsertSessionOIDC(ctx, session)
	if err != nil {
		return ccc.NilUUID, errors.Wrap(err, "PostgresOIDCSessionStorage.db.InsertSessionOIDC()")
	}

	return id, nil
}

// DestroySessionOIDC marks the session as expired
func (p *PostgresOIDC) DestroySessionOIDC(ctx context.Context, oidcSID string) error {
	ctx, span := ccc.StartTrace(ctx)
	defer span.End()

	if err := p.db.DestroySessionOIDC(ctx, oidcSID); err != nil {
		return errors.Wrap(err, "PostgresOIDCSessionStorage.db.DestroySessionOIDC()")
	}

	return nil
}

// Session returns the session information from the database for given sessionID
func (p *PostgresOIDC) Session(ctx context.Context, sessionID ccc.UUID) (*sessioninfo.SessionInfo, error) {
	ctx, span := ccc.StartTrace(ctx)
	defer span.End()

	si, err := p.db.Session(ctx, sessionID)
	if err != nil {
		return nil, errors.Wrap(err, "PostgresOIDCSessionStorage.db.Session()")
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
func (p *PostgresOIDC) UpdateSessionActivity(ctx context.Context, sessionID ccc.UUID) error {
	ctx, span := ccc.StartTrace(ctx)
	defer span.End()

	if err := p.db.UpdateSessionActivity(ctx, sessionID); err != nil {
		return errors.Wrap(err, "PostgresOIDCSessionStorage.db.UpdateSessionActivity()")
	}

	return nil
}

// DestroySession marks the session as expired
func (p *PostgresOIDC) DestroySession(ctx context.Context, sessionID ccc.UUID) error {
	ctx, span := ccc.StartTrace(ctx)
	defer span.End()

	if err := p.db.DestroySession(ctx, sessionID); err != nil {
		return errors.Wrap(err, "PostgresOIDCSessionStorage.db.DestroySession()")
	}

	return nil
}
