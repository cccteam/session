package session

import (
	"context"
	"time"

	"github.com/cccteam/access"
	"github.com/cccteam/ccc"
	"github.com/cccteam/session/db"
	"github.com/cccteam/session/sessiontypes"
	"github.com/go-playground/errors/v5"
	"go.opentelemetry.io/otel"
)

type PostgresqlOIDCSessionManager struct {
	*PostgresqlSessionManager
}

func NewPostgresqlOIDCSessionManager(accessor Accessor, dbcon db.Queryer) *PostgresqlOIDCSessionManager {
	return &PostgresqlOIDCSessionManager{
		PostgresqlSessionManager: NewPostgresqlManager(accessor, dbcon),
	}
}

// Session returns the session information from the database for given sessionID
func (p *PostgresqlOIDCSessionManager) Session(ctx context.Context, sessionID ccc.UUID) (*sessiontypes.SessionInfo, error) {
	ctx, span := otel.Tracer(name).Start(ctx, "Client.Session()")
	defer span.End()

	si, err := p.db.Session(ctx, sessionID)
	if err != nil {
		return nil, errors.Wrap(err, "dbx.DB.Session()")
	}

	permissions, err := p.access.UserPermissions(ctx, access.User(si.Username))
	if err != nil {
		return nil, errors.Wrap(err, "Client.UserPermissions()")
	}

	return &sessiontypes.SessionInfo{
		ID:          si.ID,
		Username:    si.Username,
		CreatedAt:   si.CreatedAt,
		UpdatedAt:   si.UpdatedAt,
		Expired:     si.Expired,
		Permissions: permissions,
	}, nil
}

// NewSession inserts SessionInfo into database
func (p *PostgresqlOIDCSessionManager) NewSession(ctx context.Context, username, oidcSID string) (ccc.UUID, error) {
	ctx, span := otel.Tracer(name).Start(ctx, "PostgresqlOIDCSessionManager.NewSession()")
	defer span.End()

	session := &db.InsertSession{
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
func (p *PostgresqlOIDCSessionManager) DestroySessionOIDC(ctx context.Context, oidcSID string) error {
	ctx, span := otel.Tracer(name).Start(ctx, "PostgresqlOIDCSessionManager.DestroySessionOIDC()")
	defer span.End()

	if err := p.db.DestroySessionOIDC(ctx, oidcSID); err != nil {
		return errors.Wrap(err, "failed to destroy session")
	}

	return nil
}