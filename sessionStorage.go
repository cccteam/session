package session

import (
	"context"
	"session/dbx"
)

type sessionStorage struct {
}

func (st *sessionStorage) Session(ctx context.Context, sessionID string) (*dbx.SessionInfo, error) {
	return nil, nil
}

func (st *sessionStorage) DestroySession(ctx context.Context, sessionID string) error {
	return nil
}

func (st *sessionStorage) NewSession(ctx context.Context, dbSess *dbx.SessionInfo) (*dbx.SessionInfo, error) {
	return nil, nil
}

func (st *sessionStorage) UpdateSessionActivity(ctx context.Context, sessionID string) error {
	return nil
}
