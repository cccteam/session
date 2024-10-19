package session

import (
	"context"
	"time"

	cloudspanner "cloud.google.com/go/spanner"
	"github.com/cccteam/ccc"
	"github.com/cccteam/session/spanner"
	"github.com/go-playground/errors/v5"
	"go.opentelemetry.io/otel"
)

// SpannerPreauthSessionStorage is what you use to create / update sessions inside of the handlers or as a standalone if you don't want the handlers
type SpannerPreauthSessionStorage struct {
	*spannerSessionStorage
}

// NewSpannerPreauthSessionStorage is the function that you use to create the session manager that handles the session creation and updates
func NewSpannerPreauthSessionStorage(db *cloudspanner.Client) *SpannerPreauthSessionStorage {
	return &SpannerPreauthSessionStorage{
		spannerSessionStorage: newSpannerSessionStorage(db),
	}
}

// NewSession inserts SessionInfo into the spanner database
func (p *SpannerPreauthSessionStorage) NewSession(ctx context.Context, username string) (ccc.UUID, error) {
	ctx, span := otel.Tracer(name).Start(ctx, "SpannerPreauthSessionStorage.NewSession()")
	defer span.End()

	session := &spanner.InsertSession{
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
