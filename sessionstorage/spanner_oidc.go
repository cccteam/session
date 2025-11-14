package sessionstorage

import (
	"context"
	"time"

	cloudspanner "cloud.google.com/go/spanner"
	"github.com/cccteam/ccc"
	"github.com/cccteam/session/sessioninfo"
	"github.com/cccteam/session/sessionstorage/internal/dbtype"
	"github.com/cccteam/session/sessionstorage/internal/spanner"
	"github.com/go-playground/errors/v5"
)

// SpannerOIDC is the session storage implementation for Spanner with OIDC support.
type SpannerOIDC struct {
	db db
}

// NewSpannerOIDC creates a new SpannerOIDCSessionStorage instance.
func NewSpannerOIDC(db *cloudspanner.Client) *SpannerOIDC {
	return &SpannerOIDC{
		db: spanner.NewSessionStorageDriver(db),
	}
}

// NewSession inserts SessionInfo into database
func (p *SpannerOIDC) NewSession(ctx context.Context, username, oidcSID string) (ccc.UUID, error) {
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
		return ccc.NilUUID, errors.Wrap(err, "SpannerOIDCSessionStorage.InsertSessionOIDC()")
	}

	return id, nil
}

// DestroySessionOIDC marks the session as expired
func (p *SpannerOIDC) DestroySessionOIDC(ctx context.Context, oidcSID string) error {
	ctx, span := ccc.StartTrace(ctx)
	defer span.End()

	if err := p.db.DestroySessionOIDC(ctx, oidcSID); err != nil {
		return errors.Wrap(err, "SpannerOIDCSessionStorage.db.DestroySessionOIDC()")
	}

	return nil
}

// Session returns the session information from the database for given sessionID
func (p *SpannerOIDC) Session(ctx context.Context, sessionID ccc.UUID) (*sessioninfo.SessionInfo, error) {
	ctx, span := ccc.StartTrace(ctx)
	defer span.End()

	si, err := p.db.SessionOIDC(ctx, sessionID)
	if err != nil {
		return nil, errors.Wrap(err, "SpannerOIDCSessionStorage.db.SessionOIDC()")
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
func (p *SpannerOIDC) UpdateSessionActivity(ctx context.Context, sessionID ccc.UUID) error {
	ctx, span := ccc.StartTrace(ctx)
	defer span.End()

	if err := p.db.UpdateSessionActivity(ctx, sessionID); err != nil {
		return errors.Wrap(err, "SpannerOIDCSessionStorage.db.UpdateSessionActivity()")
	}

	return nil
}

// DestroySession marks the session as expired
func (p *SpannerOIDC) DestroySession(ctx context.Context, sessionID ccc.UUID) error {
	ctx, span := ccc.StartTrace(ctx)
	defer span.End()

	if err := p.db.DestroySession(ctx, sessionID); err != nil {
		return errors.Wrap(err, "SpannerOIDCSessionStorage.db.DestroySession()")
	}

	return nil
}
