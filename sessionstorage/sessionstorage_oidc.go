package sessionstorage

import (
	"context"
	"time"

	cloudspanner "cloud.google.com/go/spanner"
	"github.com/cccteam/ccc"
	"github.com/cccteam/session/sessionstorage/internal/dbtype"
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
func NewSpannerOIDC(client *cloudspanner.Client) *OIDC {
	return &OIDC{
		sessionStorage: sessionStorage{
			db: spanner.NewSessionStorageDriver(client),
		},
	}
}

// NewPostgresOIDC creates a new PostgresOIDC instance.
func NewPostgresOIDC(pg postgres.Queryer) *OIDC {
	return &OIDC{
		sessionStorage: sessionStorage{
			db: postgres.NewSessionStorageDriver(pg),
		},
	}
}

// NewSession inserts SessionInfo into database
func (s *OIDC) NewSession(ctx context.Context, username, oidcSID string) (ccc.UUID, error) {
	ctx, span := ccc.StartTrace(ctx)
	defer span.End()

	session := &dbtype.InsertOIDCSession{
		OidcSID: oidcSID,
		InsertSession: dbtype.InsertSession{
			Username:  username,
			CreatedAt: time.Now(),
			UpdatedAt: time.Now(),
		},
	}

	id, err := s.db.InsertSessionOIDC(ctx, session)
	if err != nil {
		return ccc.NilUUID, errors.Wrap(err, "db.InsertSessionOIDC()")
	}

	return id, nil
}

// DestroySessionOIDC marks the session as expired
func (s *OIDC) DestroySessionOIDC(ctx context.Context, oidcSID string) error {
	ctx, span := ccc.StartTrace(ctx)
	defer span.End()

	if err := s.db.DestroySessionOIDC(ctx, oidcSID); err != nil {
		return errors.Wrap(err, "db.DestroySessionOIDC()")
	}

	return nil
}
