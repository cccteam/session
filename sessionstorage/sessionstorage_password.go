package sessionstorage

import (
	"context"

	cloudspanner "cloud.google.com/go/spanner"
	"github.com/cccteam/ccc"
	"github.com/cccteam/ccc/securehash"
	"github.com/cccteam/session/internal/dbtype"
	"github.com/cccteam/session/sessionstorage/internal/postgres"
	"github.com/cccteam/session/sessionstorage/internal/spanner"
	"github.com/go-playground/errors/v5"
)

var _ PasswordAuthStore = (*PasswordAuth)(nil)

// PasswordAuth is the session storage implementation with PasswordAuth support.
type PasswordAuth struct {
	sessionStorage
}

// NewSpannerPasswordAuth creates a new Password storage instance.
func NewSpannerPasswordAuth(client *cloudspanner.Client) *PasswordAuth {
	return &PasswordAuth{
		sessionStorage: sessionStorage{
			db: spanner.NewSessionStorageDriver(client),
		},
	}
}

// NewPostgresPassword creates a new PostgresPassword instance.
func NewPostgresPassword(pg postgres.Queryer) *PasswordAuth {
	return &PasswordAuth{
		sessionStorage: sessionStorage{
			db: postgres.NewSessionStorageDriver(pg),
		},
	}
}

// User returns the user record associated with the username
func (p *PasswordAuth) User(ctx context.Context, id ccc.UUID) (*dbtype.SessionUser, error) {
	ctx, span := ccc.StartTrace(ctx)
	defer span.End()

	u, err := p.db.User(ctx, id)
	if err != nil {
		return nil, errors.Wrap(err, "db.User()")
	}

	return u, nil
}

// UserByUserName returns the user record associated with the username
func (p *PasswordAuth) UserByUserName(ctx context.Context, username string) (*dbtype.SessionUser, error) {
	ctx, span := ccc.StartTrace(ctx)
	defer span.End()

	u, err := p.db.UserByUserName(ctx, username)
	if err != nil {
		return nil, errors.Wrap(err, "db.UserByUserName()")
	}

	return u, nil
}

// SetUserPasswordHash updates the user password hash
func (p *PasswordAuth) SetUserPasswordHash(ctx context.Context, id ccc.UUID, hash *securehash.Hash) error {
	ctx, span := ccc.StartTrace(ctx)
	defer span.End()

	if err := p.db.SetUserPasswordHash(ctx, id, hash); err != nil {
		return errors.Wrap(err, "db.SetUserPasswordHash()")
	}

	return nil
}
