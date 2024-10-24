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

type SpannerOIDCSessionStorage struct {
	*spannerSessionStorage
}

func NewSpannerOIDCSessionStorage(db *cloudspanner.Client) *SpannerOIDCSessionStorage {
	return &SpannerOIDCSessionStorage{
		spannerSessionStorage: newSpannerSessionStorage(db),
	}
}

// NewSession inserts SessionInfo into database
func (p *SpannerOIDCSessionStorage) NewSession(ctx context.Context, username, oidcSID string) (ccc.UUID, error) {
	ctx, span := otel.Tracer(name).Start(ctx, "SpannerqlOIDCSessionStorage.NewSession()")
	defer span.End()

	session := &spanner.InsertSession{
		OidcSID:   oidcSID,
		Username:  username,
		CreatedAt: time.Now(),
		UpdatedAt: time.Now(),
	}

	id, err := p.db.InsertSession(ctx, session)
	if err != nil {
		return ccc.NilUUID, errors.Wrap(err, "SpannerqlOIDCSessionStorage.insertSession()")
	}

	return id, nil
}

// DestroySessionOIDC marks the session as expired
func (p *SpannerOIDCSessionStorage) DestroySessionOIDC(ctx context.Context, oidcSID string) error {
	ctx, span := otel.Tracer(name).Start(ctx, "SpannerqlOIDCSessionStorage.DestroySessionOIDC()")
	defer span.End()

	if err := p.db.DestroySessionOIDC(ctx, oidcSID); err != nil {
		return errors.Wrap(err, "failed to destroy session")
	}

	return nil
}
