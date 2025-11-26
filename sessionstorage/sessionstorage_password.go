package sessionstorage

import (
	"context"

	cloudspanner "cloud.google.com/go/spanner"
	"github.com/cccteam/ccc"
	"github.com/cccteam/ccc/securehash"
	"github.com/cccteam/session/sessionstorage/internal/dbtype"
	"github.com/cccteam/session/sessionstorage/internal/postgres"
	"github.com/cccteam/session/sessionstorage/internal/spanner"
	"github.com/go-playground/errors/v5"
)

var _ PasswordStore = (*Password)(nil)

// Password is the session storage implementation with Password support.
type Password struct {
	sessionStorage
}

// NewSpannerPassword creates a new Password storage instance.
func NewSpannerPassword(client *cloudspanner.Client) *Password {
	return &Password{
		sessionStorage: sessionStorage{
			db: spanner.NewSessionStorageDriver(client),
		},
	}
}

// NewPostgresPassword creates a new PostgresPassword instance.
func NewPostgresPassword(pg postgres.Queryer) *Password {
	return &Password{
		sessionStorage: sessionStorage{
			db: postgres.NewSessionStorageDriver(pg),
		},
	}
}

// User returns the user record associated with the username
func (p *Password) User(ctx context.Context, id ccc.UUID) (*dbtype.SessionUser, error) {
	ctx, span := ccc.StartTrace(ctx)
	defer span.End()

	u, err := p.db.User(ctx, id)
	if err != nil {
		return nil, errors.Wrap(err, "db.User()")
	}

	return u, nil
}

// UserByUserName returns the user record associated with the username
func (p *Password) UserByUserName(ctx context.Context, username string) (*dbtype.SessionUser, error) {
	ctx, span := ccc.StartTrace(ctx)
	defer span.End()

	u, err := p.db.UserByUserName(ctx, username)
	if err != nil {
		return nil, errors.Wrap(err, "db.Session()")
	}

	return u, nil
}

// UpdateUserPasswordHash updates the user password hash
func (p *Password) UpdateUserPasswordHash(ctx context.Context, id ccc.UUID, hash *securehash.Hash) error {
	ctx, span := ccc.StartTrace(ctx)
	defer span.End()

	if err := p.db.UpdateUserPasswordHash(ctx, id, hash); err != nil {
		return errors.Wrap(err, "db.UpdateUserPasswordHash()")
	}

	return nil
}
