package session

import (
	"context"
	"time"

	"github.com/cccteam/ccc"
	"github.com/cccteam/session/postgres"
	"github.com/go-playground/errors/v5"
	"go.opentelemetry.io/otel"
)

// PostgresPreauthSessionManager is what you use when to create / update sessions inside of the handlers or as a standalone if you don't want the handlers
type PostgresPreauthSessionManager struct {
	*postgresSessionManager
}

// NewPostgresPreauthSessionManager is the function that you use to create the session manager that handles the session creation and updates
func NewPostgresPreauthSessionManager(userManager UserManager, db postgres.Queryer) *PostgresPreauthSessionManager {
	return &PostgresPreauthSessionManager{
		postgresSessionManager: newPostgresSessionManager(userManager, db),
	}
}

// NewSession inserts SessionInfo into the spanner database
func (p *PostgresPreauthSessionManager) NewSession(ctx context.Context, username string) (ccc.UUID, error) {
	ctx, span := otel.Tracer(name).Start(ctx, "PostgresPreauthSessionManager.NewSession()")
	defer span.End()

	session := &postgres.InsertSession{
		Username:  username,
		CreatedAt: time.Now(),
		UpdatedAt: time.Now(),
	}

	id, err := p.db.InsertSession(ctx, session)
	if err != nil {
		return ccc.NilUUID, errors.Wrap(err, "PostgresPreauthSessionManager.insertSession()")
	}

	return id, nil
}
