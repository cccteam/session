package spanner

import (
	"context"

	"github.com/cccteam/ccc"
)

// DB is the interface for the database methods
type DB interface {
	// Session returns the session information from the database for given sessionID.
	Session(ctx context.Context, sessionID ccc.UUID) (*Session, error)

	// InsertSession creates a new session in the database and returns its session ID.
	InsertSession(ctx context.Context, session *InsertSession) (ccc.UUID, error)

	// UpdateSessionActivity updates the session activity column with the current time.
	UpdateSessionActivity(ctx context.Context, sessionID ccc.UUID) error

	// DestroySession marks the session as expired.
	DestroySession(ctx context.Context, sessionID ccc.UUID) error

	// DestroySessionOIDC marks the session as expired
	DestroySessionOIDC(ctx context.Context, oidcSID string) error
}
