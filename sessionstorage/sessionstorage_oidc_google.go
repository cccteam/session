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

var _ GoogleOIDCStore = (*GoogleOIDC)(nil)

// GoogleOIDC is the session storage implementation for Google OIDC support. Its user
// anchor is the Sub-keyed GoogleOIDCUsers table and its session rows carry no OidcSid
// (Google issues no sid claim) — ship the schema/*/oidc-google/migrations migration.
type GoogleOIDC struct {
	sessionStorage
}

// NewSpannerGoogleOIDC creates a new Spanner-backed GoogleOIDC instance.
func NewSpannerGoogleOIDC(client *cloudspanner.Client, opts ...SpannerOption) *GoogleOIDC {
	driver := spanner.NewGoogleSessionStorageDriver(client)
	for _, opt := range opts {
		opt.applySpanner(driver)
	}

	return &GoogleOIDC{
		sessionStorage: sessionStorage{
			db: driver,
		},
	}
}

// NewPostgresGoogleOIDC creates a new PostgreSQL-backed GoogleOIDC instance.
func NewPostgresGoogleOIDC(pg postgres.Queryer, opts ...PostgresOption) *GoogleOIDC {
	driver := postgres.NewGoogleSessionStorageDriver(pg)
	for _, opt := range opts {
		opt.applyPostgres(driver)
	}

	return &GoogleOIDC{
		sessionStorage: sessionStorage{
			db: driver,
		},
	}
}

// NewSession creates a new Google OIDC session and returns its ID. claims carries the
// raw verified ID-token claims into any configured custom session data resolver, which
// runs inside the session-insert transaction; a resolver error aborts session creation.
// When the OIDC user anchor is enabled, the same transaction upserts the
// GoogleOIDCUsers record for the claims' sub and runs any configured custom user data
// hook.
func (s *GoogleOIDC) NewSession(ctx context.Context, username string, claims json.RawMessage) (ccc.UUID, error) {
	ctx, span := tracer.Start(ctx)
	defer span.End()

	session := &dbtype.InsertSession{
		Username:  username,
		CreatedAt: time.Now(),
		UpdatedAt: time.Now(),
	}

	req := &sessioninfo.NewSessionRequest{
		Reason:   sessioninfo.ReasonLogin,
		Username: username,
		Claims:   claims,
	}

	// The drivers never parse JSON: the anchor key claims are extracted here and ride
	// the request. The driver enforces their presence when the anchor is enabled.
	if len(claims) > 0 {
		var key struct {
			Sub string `json:"sub"`
			Hd  string `json:"hd"`
		}
		if err := json.Unmarshal(claims, &key); err != nil {
			return ccc.NilUUID, errors.Wrap(err, "json.Unmarshal()")
		}
		req.Sub, req.Hd = key.Sub, key.Hd
	}

	id, err := s.db.InsertSessionGoogleOIDC(ctx, session, req)
	if err != nil {
		return ccc.NilUUID, errors.Wrap(err, "db.InsertSessionGoogleOIDC()")
	}

	return id, nil
}

// GoogleOIDCUser returns the Google OIDC user anchor record for the given ID.
func (s *GoogleOIDC) GoogleOIDCUser(ctx context.Context, id ccc.UUID) (*GoogleOIDCUser, error) {
	ctx, span := tracer.Start(ctx)
	defer span.End()

	u, err := s.db.GoogleOIDCUser(ctx, id)
	if err != nil {
		return nil, errors.Wrap(err, "db.GoogleOIDCUser()")
	}

	return u, nil
}

// GoogleOIDCUserBySub returns the Google OIDC user anchor record for the given sub
// claim — the stable, never-reused identity key Google gives you (usernames and email
// addresses are mutable).
func (s *GoogleOIDC) GoogleOIDCUserBySub(ctx context.Context, sub string) (*GoogleOIDCUser, error) {
	ctx, span := tracer.Start(ctx)
	defer span.End()

	u, err := s.db.GoogleOIDCUserBySub(ctx, sub)
	if err != nil {
		return nil, errors.Wrap(err, "db.GoogleOIDCUserBySub()")
	}

	return u, nil
}
