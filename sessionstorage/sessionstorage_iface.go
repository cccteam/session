// Package sessionstorage implements database storage for session data.
// There are implementations for both Spanner and Postgres for each
// session type (i.e. OIDC, Username/Password, etc)
package sessionstorage

import (
	"context"

	"github.com/cccteam/ccc"
	"github.com/cccteam/ccc/securehash"
	"github.com/cccteam/session/internal/dbtype"
	"github.com/cccteam/session/sessioninfo"
	"github.com/cccteam/session/sessionstorage/internal/postgres"
	"github.com/cccteam/session/sessionstorage/internal/spanner"
)

// BaseStore defines an interface for managing session storage.
type BaseStore interface {
	// Session returns the session information from the database for given sessionID
	Session(ctx context.Context, sessionID ccc.UUID) (*sessioninfo.SessionInfo, error)
	// UpdateSessionActivity updates the database with the current time for the session activity
	UpdateSessionActivity(ctx context.Context, sessionID ccc.UUID) error
	// DestroySession marks the session as expired
	DestroySession(ctx context.Context, sessionID ccc.UUID) error
	// SetSessionTableName sets the name of the session table.
	SetSessionTableName(name string)
	// SetUserTableName sets the name of the user table.
	SetUserTableName(name string)
}

var _ PreauthStore = (*Preauth)(nil)

// PreauthStore defines an interface for managing pre-authenticated session storage.
type PreauthStore interface {
	// NewSession creates a new session in the database, returning its id
	NewSession(ctx context.Context, username string) (ccc.UUID, error)

	// shared storage methods
	BaseStore
}

var _ PasswordAuthStore = (*PasswordAuth)(nil)

// PasswordAuthStore defines an interface for managing password sessions.
type PasswordAuthStore interface {
	// User returns a session user for give user id
	User(ctx context.Context, id ccc.UUID) (*dbtype.SessionUser, error)
	// UserByUsername returns a session user for give username
	UserByUserName(ctx context.Context, username string) (*dbtype.SessionUser, error)
	// SetUserPasswordHash updates the user password hash
	SetUserPasswordHash(ctx context.Context, id ccc.UUID, hash *securehash.Hash) error
	// ActivateUser activates a user
	ActivateUser(ctx context.Context, id ccc.UUID) error
	// CreateUser creates a new user
	CreateUser(ctx context.Context, username string, hash *securehash.Hash) (*dbtype.SessionUser, error)
	// DeactivateUser deactivates a user
	DeactivateUser(ctx context.Context, id ccc.UUID) error
	// DeleteUser deletes a user
	DeleteUser(ctx context.Context, id ccc.UUID) error
	// DestroyAllUserSessions destroys all sessions for a given user
	DestroyAllUserSessions(ctx context.Context, username string) error

	// shared storage methods
	PreauthStore
}

var _ OIDCStore = (*OIDC)(nil)

// OIDCStore defines an interface for managing OIDC session storage.
type OIDCStore interface {
	DestroySessionOIDC(ctx context.Context, oidcSID string) error
	NewSession(ctx context.Context, username, oidcSID string) (ccc.UUID, error)

	// shared storage methods
	BaseStore
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
	// SetSessionTableName sets the name of the session table.
	SetSessionTableName(name string)
	// SetUserTableName sets the name of the user table.
	SetUserTableName(name string)

	//
	// Password specific methods
	//

	// User returns a session user for give user id
	User(ctx context.Context, id ccc.UUID) (*dbtype.SessionUser, error)
	// UserByUsername returns a session user for give username
	UserByUserName(ctx context.Context, username string) (*dbtype.SessionUser, error)
	// SetUserPasswordHash updates the user password hash
	SetUserPasswordHash(ctx context.Context, id ccc.UUID, hash *securehash.Hash) error
	// ActivateUser activates a user
	ActivateUser(ctx context.Context, id ccc.UUID) error
	// CreateUser creates a new user
	CreateUser(ctx context.Context, username string, hash *securehash.Hash) (*dbtype.SessionUser, error)
	// DeactivateUser deactivates a user
	DeactivateUser(ctx context.Context, id ccc.UUID) error
	// DeleteUser deletes a user
	DeleteUser(ctx context.Context, id ccc.UUID) error
	// DestroyAllUserSessions destroys all sessions for a given user
	DestroyAllUserSessions(ctx context.Context, username string) error

	//
	// OIDC specific methods
	//

	// InsertSessionOIDC creates a new OIDC session in the database and returns its session ID.
	InsertSessionOIDC(ctx context.Context, session *dbtype.InsertOIDCSession) (ccc.UUID, error)
	// DestroySessionOIDC marks the OIDC session as expired by oidcSID.
	DestroySessionOIDC(ctx context.Context, oidcSID string) error
}
