package session

import (
	"context"
	"time"

	"github.com/cccteam/ccc"
	"github.com/cccteam/session/postgres"
	"github.com/go-playground/errors/v5"
	"go.opentelemetry.io/otel"
)

type PostgresOIDCSessionManager struct {
	*postgresSessionManager
}

func NewPostgresOIDCSessionManager(userManager UserManager, db postgres.Queryer) *PostgresOIDCSessionManager {
	return &PostgresOIDCSessionManager{
		postgresSessionManager: newPostgresSessionManager(userManager, db),
	}
}

// NewSession inserts SessionInfo into database
func (p *PostgresOIDCSessionManager) NewSession(ctx context.Context, username, oidcSID string) (ccc.UUID, error) {
	ctx, span := otel.Tracer(name).Start(ctx, "PostgresqlOIDCSessionManager.NewSession()")
	defer span.End()

	session := &postgres.InsertSession{
		OidcSID:   oidcSID,
		Username:  username,
		CreatedAt: time.Now(),
		UpdatedAt: time.Now(),
	}

	id, err := p.db.InsertSession(ctx, session)
	if err != nil {
		return ccc.NilUUID, errors.Wrap(err, "PostgresqlOIDCSessionManager.insertSession()")
	}

	return id, nil
}

// DestroySessionOIDC marks the session as expired
func (p *PostgresOIDCSessionManager) DestroySessionOIDC(ctx context.Context, oidcSID string) error {
	ctx, span := otel.Tracer(name).Start(ctx, "PostgresqlOIDCSessionManager.DestroySessionOIDC()")
	defer span.End()

	if err := p.db.DestroySessionOIDC(ctx, oidcSID); err != nil {
		return errors.Wrap(err, "failed to destroy session")
	}

	return nil
}
