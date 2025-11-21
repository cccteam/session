// Package sessionstorage implements database storage for session data.
// There are implementations for both Spanner and Postgres for each
// session type (i.e. OIDC, Username/Password, etc)
package sessionstorage

import (
	"context"

	"github.com/cccteam/ccc"
	"github.com/cccteam/session/sessioninfo"
	"github.com/cccteam/session/sessionstorage/internal/dbtype"
	"github.com/cccteam/session/sessionstorage/internal/postgres"
	"github.com/cccteam/session/sessionstorage/internal/spanner"
)

// Base defines an interface for managing session storage.
type Base interface {
	DestroySession(ctx context.Context, sessionID ccc.UUID) error
	UpdateSessionActivity(ctx context.Context, sessionID ccc.UUID) error
	Session(ctx context.Context, sessionID ccc.UUID) (*sessioninfo.SessionInfo, error)
}

// OIDCAzure defines an interface for managing OIDC sessions.
type OIDCAzure interface {
	DestroySessionOIDC(ctx context.Context, oidcSID string) error
	NewSession(ctx context.Context, username, oidcSID string) (ccc.UUID, error)

	// shared storage methods
	Base
}

var (
	_ Preauth = (*SpannerPreauth)(nil)
	_ Preauth = (*PostgresPreauth)(nil)
)

// Preauth defines an interface for managing pre-authenticated sessions.
type Preauth interface {
	NewSession(ctx context.Context, username string) (ccc.UUID, error)

	// shared storage methods
	Base
}

var (
	_ db = (*spanner.SessionStorageDriver)(nil)
	_ db = (*postgres.SessionStorageDriver)(nil)
)

// db defines an interface for database operations related to session management.
type db interface {
	// Session returns the session information from the database for given sessionID.
	Session(ctx context.Context, sessionID ccc.UUID) (*dbtype.Session, error)
	// InsertSession creates a new session in the database and returns its session ID.
	InsertSession(ctx context.Context, session *dbtype.InsertSession) (ccc.UUID, error)
	// UpdateSessionActivity updates the session activity column with the current time.
	UpdateSessionActivity(ctx context.Context, sessionID ccc.UUID) error
	// DestroySession marks the session as expired.
	DestroySession(ctx context.Context, sessionID ccc.UUID) error

	//
	// OIDC specific methods
	//

	// InsertSessionOIDC creates a new OIDC session in the database and returns its session ID.
	InsertSessionOIDC(ctx context.Context, session *dbtype.InsertSessionOIDC) (ccc.UUID, error)
	// DestroySessionOIDC marks the OIDC session as expired by oidcSID.
	DestroySessionOIDC(ctx context.Context, oidcSID string) error
}
