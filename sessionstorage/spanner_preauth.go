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

// SpannerPreauth is what you use to create / update sessions inside of the handlers or as a standalone if you don't want the handlers
type SpannerPreauth struct {
	db db
}

// NewSpannerPreauth is the function that you use to create the session manager that handles the session creation and updates
func NewSpannerPreauth(db *cloudspanner.Client) *SpannerPreauth {
	return &SpannerPreauth{
		spanner.NewSessionStorageDriver(db),
	}
}

// NewSession inserts SessionInfo into the spanner database
func (p *SpannerPreauth) NewSession(ctx context.Context, username string) (ccc.UUID, error) {
	ctx, span := ccc.StartTrace(ctx)
	defer span.End()

	session := &dbtype.InsertSession{
		Username:  username,
		CreatedAt: time.Now(),
		UpdatedAt: time.Now(),
	}

	id, err := p.db.InsertSession(ctx, session)
	if err != nil {
		return ccc.NilUUID, errors.Wrap(err, "SpannerPreauthSessionStorage.db.InsertSession()")
	}

	return id, nil
}

// Session returns the session information from the database for given sessionID
func (p *SpannerPreauth) Session(ctx context.Context, sessionID ccc.UUID) (*sessioninfo.SessionInfo, error) {
	ctx, span := ccc.StartTrace(ctx)
	defer span.End()

	si, err := p.db.Session(ctx, sessionID)
	if err != nil {
		return nil, errors.Wrap(err, "SpannerPreauthSessionStorage.db.Session()")
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
func (p *SpannerPreauth) UpdateSessionActivity(ctx context.Context, sessionID ccc.UUID) error {
	ctx, span := ccc.StartTrace(ctx)
	defer span.End()

	if err := p.db.UpdateSessionActivity(ctx, sessionID); err != nil {
		return errors.Wrap(err, "SpannerPreauthSessionStorage.db.UpdateSessionActivity()")
	}

	return nil
}

// DestroySession marks the session as expired
func (p *SpannerPreauth) DestroySession(ctx context.Context, sessionID ccc.UUID) error {
	ctx, span := ccc.StartTrace(ctx)
	defer span.End()

	if err := p.db.DestroySession(ctx, sessionID); err != nil {
		return errors.Wrap(err, "SpannerPreauthSessionStorage.db.DestroySession()")
	}

	return nil
}
