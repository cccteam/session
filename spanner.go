package session

import (
	"context"

	cloudspanner "cloud.google.com/go/spanner"
	"github.com/cccteam/ccc"
	"github.com/cccteam/ccc/accesstypes"
	"github.com/cccteam/session/sessioninfo"
	"github.com/cccteam/session/spanner"
	"github.com/go-playground/errors/v5"
	"go.opentelemetry.io/otel"
)

type spannerSessionManager struct {
	access UserManager
	db     spanner.DB
}

func newSpannerSessionManager(userManager UserManager, db *cloudspanner.Client) *spannerSessionManager {
	return &spannerSessionManager{
		access: userManager,
		db:     spanner.New(db),
	}
}

// Session returns the session information from the database for given sessionID
func (p *spannerSessionManager) Session(ctx context.Context, sessionID ccc.UUID) (*sessioninfo.SessionInfo, error) {
	ctx, span := otel.Tracer(name).Start(ctx, "Client.Session()")
	defer span.End()

	si, err := p.db.Session(ctx, sessionID)
	if err != nil {
		return nil, errors.Wrap(err, "dbx.DB.Session()")
	}

	permissions, err := p.access.UserPermissions(ctx, accesstypes.User(si.Username))
	if err != nil {
		return nil, errors.Wrap(err, "Client.UserPermissions()")
	}

	return &sessioninfo.SessionInfo{
		ID:          si.ID,
		Username:    si.Username,
		CreatedAt:   si.CreatedAt,
		UpdatedAt:   si.UpdatedAt,
		Expired:     si.Expired,
		Permissions: permissions,
	}, nil
}

// UpdateSessionActivity updates the database with the current time for the session activity
func (p *spannerSessionManager) UpdateSessionActivity(ctx context.Context, sessionID ccc.UUID) error {
	ctx, span := otel.Tracer(name).Start(ctx, "SpannerSessionManager.UpdateSessionActivity()")
	defer span.End()

	if err := p.db.UpdateSessionActivity(ctx, sessionID); err != nil {
		return errors.Wrap(err, "db.updateSessionActivity()")
	}

	return nil
}

// DestroySession marks the session as expired
func (p *spannerSessionManager) DestroySession(ctx context.Context, sessionID ccc.UUID) error {
	ctx, span := otel.Tracer(name).Start(ctx, "SpannerSessionManager.DestroySession()")
	defer span.End()

	if err := p.db.DestroySession(ctx, sessionID); err != nil {
		return errors.Wrap(err, "db.DestroySession()")
	}

	return nil
}
