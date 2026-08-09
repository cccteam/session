package sessionstorage

import (
	"context"
	"encoding/json"
	"time"

	cloudspanner "cloud.google.com/go/spanner"
	"github.com/cccteam/ccc"
	"github.com/cccteam/ccc/tracer"
	"github.com/cccteam/session/internal/dbtype"
	"github.com/cccteam/session/sessioninfo"
	"github.com/cccteam/session/sessionstorage/internal/postgres"
	"github.com/cccteam/session/sessionstorage/internal/spanner"
	"github.com/go-playground/errors/v5"
)

var _ OIDCStore = (*OIDC)(nil)

// OIDC is the session storage implementation for with OIDC support.
type OIDC struct {
	sessionStorage
}

// NewSpannerOIDC creates a new SpannerOIDCSessionStorage instance.
func NewSpannerOIDC(client *cloudspanner.Client, opts ...SpannerOption) *OIDC {
	driver := spanner.NewSessionStorageDriver(client)
	for _, opt := range opts {
		opt.applySpanner(driver)
	}

	return &OIDC{
		sessionStorage: sessionStorage{
			db: driver,
		},
	}
}

// NewPostgresOIDC creates a new PostgresOIDC instance.
func NewPostgresOIDC(pg postgres.Queryer, opts ...PostgresOption) *OIDC {
	driver := postgres.NewSessionStorageDriver(pg)
	for _, opt := range opts {
		opt.applyPostgres(driver)
	}

	return &OIDC{
		sessionStorage: sessionStorage{
			db: driver,
		},
	}
}

// NewSession creates a new OIDC session and returns its ID. claims carries the raw
// verified ID-token claims into any configured custom session data resolver, which runs
// inside the session-insert transaction; a resolver error aborts session creation.
func (s *OIDC) NewSession(ctx context.Context, username, oidcSID string, claims json.RawMessage) (ccc.UUID, error) {
	ctx, span := tracer.Start(ctx)
	defer span.End()

	session := &dbtype.InsertOIDCSession{
		OidcSID: oidcSID,
		InsertSession: dbtype.InsertSession{
			Username:  username,
			CreatedAt: time.Now(),
			UpdatedAt: time.Now(),
		},
	}

	req := &sessioninfo.NewSessionRequest{
		Reason:   sessioninfo.ReasonLogin,
		Username: username,
		Claims:   claims,
	}

	id, err := s.db.InsertSessionOIDC(ctx, session, req)
	if err != nil {
		return ccc.NilUUID, errors.Wrap(err, "db.InsertSessionOIDC()")
	}

	return id, nil
}

// DestroySessionOIDC marks the session as expired
func (s *OIDC) DestroySessionOIDC(ctx context.Context, oidcSID string) error {
	ctx, span := tracer.Start(ctx)
	defer span.End()

	if err := s.db.DestroySessionOIDC(ctx, oidcSID); err != nil {
		return errors.Wrap(err, "db.DestroySessionOIDC()")
	}

	return nil
}
