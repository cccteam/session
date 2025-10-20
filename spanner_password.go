package session

import (
	"context"
	"time"

	cloudspanner "cloud.google.com/go/spanner"
	"github.com/cccteam/ccc"
	"github.com/cccteam/session/dbtype"
	"github.com/cccteam/session/sessioninfo"
	"github.com/cccteam/session/spanner"
	"github.com/go-playground/errors/v5"
	"go.opentelemetry.io/otel"
)

// SpannerPasswordSessionStorage is what you use to create / update sessions inside of the handlers or as a standalone if you don't want the handlers
type SpannerPasswordSessionStorage struct {
	db DB
}

// NewSpannerPasswordSessionStorage is the function that you use to create the session manager that handles the session creation and updates
func NewSpannerPasswordSessionStorage(db *cloudspanner.Client) *SpannerPasswordSessionStorage {
	return &SpannerPasswordSessionStorage{
		spanner.NewSessionStorageDriver(db),
	}
}

// NewSession inserts SessionInfo into the spanner database
func (p *SpannerPasswordSessionStorage) NewSession(ctx context.Context, username string) (ccc.UUID, error) {
	ctx, span := otel.Tracer(name).Start(ctx, "SpannerPasswordSessionStorage.NewSession()")
	defer span.End()

	session := &dbtype.InsertSession{
		Username:  username,
		CreatedAt: time.Now(),
		UpdatedAt: time.Now(),
	}

	id, err := p.db.InsertSession(ctx, session)
	if err != nil {
		return ccc.NilUUID, errors.Wrap(err, "SpannerPasswordSessionStorage.db.InsertSession()")
	}

	return id, nil
}

// Session returns the session information from the database for given sessionID
func (p *SpannerPasswordSessionStorage) Session(ctx context.Context, sessionID ccc.UUID) (*sessioninfo.SessionInfo, error) {
	ctx, span := otel.Tracer(name).Start(ctx, "SpannerPasswordSessionStorage.Session()")
	defer span.End()

	si, err := p.db.Session(ctx, sessionID)
	if err != nil {
		return nil, errors.Wrap(err, "SpannerPasswordSessionStorage.db.Session()")
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
func (p *SpannerPasswordSessionStorage) UpdateSessionActivity(ctx context.Context, sessionID ccc.UUID) error {
	ctx, span := otel.Tracer(name).Start(ctx, "SpannerPasswordSessionStorage.UpdateSessionActivity()")
	defer span.End()

	if err := p.db.UpdateSessionActivity(ctx, sessionID); err != nil {
		return errors.Wrap(err, "SpannerPasswordSessionStorage.db.UpdateSessionActivity()")
	}

	return nil
}

// DestroySession marks the session as expired
func (p *SpannerPasswordSessionStorage) DestroySession(ctx context.Context, sessionID ccc.UUID) error {
	ctx, span := otel.Tracer(name).Start(ctx, "SpannerPasswordSessionStorage.DestroySession()")
	defer span.End()

	if err := p.db.DestroySession(ctx, sessionID); err != nil {
		return errors.Wrap(err, "SpannerPasswordSessionStorage.db.DestroySession()")
	}

	return nil
}
