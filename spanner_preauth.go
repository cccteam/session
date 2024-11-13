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

// SpannerPreauthSessionStorage is what you use to create / update sessions inside of the handlers or as a standalone if you don't want the handlers
type SpannerPreauthSessionStorage struct {
	db DB
}

// NewSpannerPreauthSessionStorage is the function that you use to create the session manager that handles the session creation and updates
func NewSpannerPreauthSessionStorage(db *cloudspanner.Client) *SpannerPreauthSessionStorage {
	return &SpannerPreauthSessionStorage{
		spanner.NewSessionStorageDriver(db),
	}
}

// NewSession inserts SessionInfo into the spanner database
func (p *SpannerPreauthSessionStorage) NewSession(ctx context.Context, username string) (ccc.UUID, error) {
	ctx, span := otel.Tracer(name).Start(ctx, "SpannerPreauthSessionStorage.NewSession()")
	defer span.End()

	session := &dbtype.InsertSession{
		Username:  username,
		CreatedAt: time.Now(),
		UpdatedAt: time.Now(),
	}

	id, err := p.db.InsertSession(ctx, session)
	if err != nil {
		return ccc.NilUUID, errors.Wrap(err, "SpannerPreauthSessionStorage.insertSession()")
	}

	return id, nil
}

// Session returns the session information from the database for given sessionID
func (p *SpannerPreauthSessionStorage) Session(ctx context.Context, sessionID ccc.UUID) (*sessioninfo.SessionInfo, error) {
	ctx, span := otel.Tracer(name).Start(ctx, "Client.Session()")
	defer span.End()

	si, err := p.db.Session(ctx, sessionID)
	if err != nil {
		return nil, errors.Wrap(err, "dbx.DB.Session()")
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
func (p *SpannerPreauthSessionStorage) UpdateSessionActivity(ctx context.Context, sessionID ccc.UUID) error {
	ctx, span := otel.Tracer(name).Start(ctx, "SpannerPreauthSessionStorage.UpdateSessionActivity()")
	defer span.End()

	if err := p.db.UpdateSessionActivity(ctx, sessionID); err != nil {
		return errors.Wrap(err, "db.updateSessionActivity()")
	}

	return nil
}

// DestroySession marks the session as expired
func (p *SpannerPreauthSessionStorage) DestroySession(ctx context.Context, sessionID ccc.UUID) error {
	ctx, span := otel.Tracer(name).Start(ctx, "SpannerPreauthSessionStorage.DestroySession()")
	defer span.End()

	if err := p.db.DestroySession(ctx, sessionID); err != nil {
		return errors.Wrap(err, "db.DestroySession()")
	}

	return nil
}
