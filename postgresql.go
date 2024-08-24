package session

import (
	"context"

	"github.com/cccteam/ccc"
	"github.com/cccteam/session/db"
	"github.com/go-playground/errors/v5"
	"go.opentelemetry.io/otel"
)

type PostgresqlSessionManager struct {
	access Accessor
	db     db.DB // has to be some sort of connection pool so I created our own queryer interface
}

func NewPostgresqlManager(accessor Accessor, dbcon db.Queryer) *PostgresqlSessionManager {
	return &PostgresqlSessionManager{
		access: accessor,
		db:     db.NewDBConnection(dbcon),
	}
}

// UpdateSessionActivity updates the database with the current time for the session activity
func (p *PostgresqlSessionManager) UpdateSessionActivity(ctx context.Context, sessionID ccc.UUID) error {
	ctx, span := otel.Tracer(name).Start(ctx, "PostgresqlSessionManager.UpdateSessionActivity()")
	defer span.End()

	if err := p.db.UpdateSessionActivity(ctx, sessionID); err != nil {
		return errors.Wrap(err, "db.updateSessionActivity()")
	}

	return nil
}

// DestroySession marks the session as expired
func (p *PostgresqlSessionManager) DestroySession(ctx context.Context, sessionID ccc.UUID) error {
	ctx, span := otel.Tracer(name).Start(ctx, "PostgresqlSessionManager.DestroySession()")
	defer span.End()

	if err := p.db.DestroySession(ctx, sessionID); err != nil {
		return errors.Wrap(err, "db.DestroySession()")
	}

	return nil
}
