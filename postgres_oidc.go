package session

import (
	"context"
	"time"

	"github.com/cccteam/ccc"
	"github.com/cccteam/session/postgres"
	"github.com/go-playground/errors/v5"
	"go.opentelemetry.io/otel"
)

type PostgresOIDCSessionStorage struct {
	*postgresSessionStorage
}

func NewPostgresOIDCSessionStorage(db postgres.Queryer) *PostgresOIDCSessionStorage {
	return &PostgresOIDCSessionStorage{
		postgresSessionStorage: newPostgresSessionStorage(db),
	}
}

// NewSession inserts SessionInfo into database
func (p *PostgresOIDCSessionStorage) NewSession(ctx context.Context, username, oidcSID string) (ccc.UUID, error) {
	ctx, span := otel.Tracer(name).Start(ctx, "PostgresqlOIDCSessionStorage.NewSession()")
	defer span.End()

	session := &postgres.InsertSession{
		OidcSID:   oidcSID,
		Username:  username,
		CreatedAt: time.Now(),
		UpdatedAt: time.Now(),
	}

	id, err := p.db.InsertSession(ctx, session)
	if err != nil {
		return ccc.NilUUID, errors.Wrap(err, "PostgresqlOIDCSessionStorage.insertSession()")
	}

	return id, nil
}

// DestroySessionOIDC marks the session as expired
func (p *PostgresOIDCSessionStorage) DestroySessionOIDC(ctx context.Context, oidcSID string) error {
	ctx, span := otel.Tracer(name).Start(ctx, "PostgresqlOIDCSessionStorage.DestroySessionOIDC()")
	defer span.End()

	if err := p.db.DestroySessionOIDC(ctx, oidcSID); err != nil {
		return errors.Wrap(err, "failed to destroy session")
	}

	return nil
}
