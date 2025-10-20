package postgres

import (
	"context"
	"errors"

	"github.com/cccteam/httpio"
	"github.com/cccteam/session/dbtype"
	"github.com/jackc/pgx/v5"
)

const selectUser = "SELECT username, password FROM users WHERE username = $1"
const insertUser = "INSERT INTO users (username, password) VALUES ($1, $2)"

// User returns the user information from the database for a given username.
func (s *SessionStorageDriver) User(ctx context.Context, username string) (*dbtype.User, error) {
	u := &dbtype.User{}
	err := s.conn.QueryRow(ctx, selectUser, username).Scan(&u.Username, &u.Password)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, httpio.NewNotFoundMessage("user not found")
		}
		return nil, err
	}
	return u, nil
}

// CreateUser creates a new user in the database.
func (s *SessionStorageDriver) CreateUser(ctx context.Context, username, password string) error {
	_, err := s.conn.Exec(ctx, insertUser, username, password)
	return err
}
