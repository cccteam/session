package postgres

import (
	"context"

	"github.com/cccteam/ccc"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
)

type Queryer interface {
	Begin(ctx context.Context) (pgx.Tx, error)
	Query(ctx context.Context, query string, args ...interface{}) (pgx.Rows, error)
	QueryRow(ctx context.Context, query string, args ...interface{}) pgx.Row
	Exec(ctx context.Context, query string, args ...interface{}) (pgconn.CommandTag, error)
}

type DB interface {
	// Session returns the session information from the database for given sessionID.
	Session(ctx context.Context, sessionID ccc.UUID) (*Session, error)

	// InsertSession inserts Session into database.
	InsertSession(ctx context.Context, sessionInfo *InsertSession) (ccc.UUID, error)

	// UpdateSessionActivity updates the session activity column with the current time.
	UpdateSessionActivity(ctx context.Context, sessionID ccc.UUID) error

	// DestroySession marks the session as expired.
	DestroySession(ctx context.Context, sessionID ccc.UUID) error

	// DestroySessionOIDC marks the session as expired
	DestroySessionOIDC(ctx context.Context, oidcSID string) error
}
