package spanner

import (
	"context"

	"cloud.google.com/go/spanner"
	"github.com/cccteam/session/dbtype"
	"google.golang.org/grpc/codes"
)

// User returns the user information from the database for a given username.
func (s *SessionStorageDriver) User(ctx context.Context, username string) (*dbtype.User, error) {
	stmt := spanner.NewStatement("SELECT username, password FROM users WHERE username = @username")
	stmt.Params["username"] = username
	row, err := s.spanner.Single().Query(ctx, stmt).Next()
	if err != nil {
		if spanner.ErrCode(err) == codes.NotFound {
			return nil, spanner.ToSpannerError(err)
		}
		return nil, err
	}

	u := &dbtype.User{}
	if err := row.ToStruct(u); err != nil {
		return nil, err
	}
	return u, nil
}

// CreateUser creates a new user in the database.
func (s *SessionStorageDriver) CreateUser(ctx context.Context, username, password string) error {
	m := spanner.Insert("users",
		[]string{"username", "password"},
		[]any{username, password})
	_, err := s.spanner.Apply(ctx, []*spanner.Mutation{m})
	return err
}
