package sessionstorage

import (
	"context"

	cloudspanner "cloud.google.com/go/spanner"
	"github.com/cccteam/ccc"
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

// UserByUserName returns the user record associated with the username
func (s *Password) UserByUserName(ctx context.Context, username string) (*dbtype.SessionUser, error) {
	ctx, span := ccc.StartTrace(ctx)
	defer span.End()

	u, err := s.db.UserByUserName(ctx, username)
	if err != nil {
		return nil, errors.Wrap(err, "db.Session()")
	}

	return u, nil
}
