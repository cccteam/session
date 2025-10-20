package session

import (
	"context"
	"net/http"

	"github.com/cccteam/ccc"
	"github.com/cccteam/ccc/accesstypes"
	"github.com/cccteam/session/dbtype"
	"github.com/cccteam/session/sessioninfo"
)

// UserManager defines an interface for managing user-related information.
type UserManager interface {
	Domains(ctx context.Context) ([]accesstypes.Domain, error)
	UserRoles(ctx context.Context, user accesstypes.User, domains ...accesstypes.Domain) (accesstypes.RoleCollection, error)
	RoleExists(ctx context.Context, domain accesstypes.Domain, role accesstypes.Role) bool
	AddUserRoles(ctx context.Context, domain accesstypes.Domain, user accesstypes.User, roles ...accesstypes.Role) error
	DeleteUserRoles(ctx context.Context, domain accesstypes.Domain, user accesstypes.User, roles ...accesstypes.Role) error
	UserPermissions(ctx context.Context, user accesstypes.User, domains ...accesstypes.Domain) (accesstypes.UserPermissionCollection, error)
}

// UserPermissionManager defines an interface for retrieving user permissions.
type UserPermissionManager interface {
	UserPermissions(ctx context.Context, user accesstypes.User, domains ...accesstypes.Domain) (accesstypes.UserPermissionCollection, error)
}

type storageManager interface {
	DestroySession(ctx context.Context, sessionID ccc.UUID) error
	UpdateSessionActivity(ctx context.Context, sessionID ccc.UUID) error
	Session(ctx context.Context, sessionID ccc.UUID) (*sessioninfo.SessionInfo, error)
}

// PasswordCredentialReader defines an interface for retrieving stored password hashes.
type PasswordCredentialReader interface {
	HashedPassword(ctx context.Context, username string) (string, error)
}

// OIDCAzureSessionStorage defines an interface for managing OIDC sessions.
type OIDCAzureSessionStorage interface {
	DestroySessionOIDC(ctx context.Context, oidcSID string) error
	NewSession(ctx context.Context, username, oidcSID string) (ccc.UUID, error)

	// common storage functions
	storageManager
}

// PreauthSessionStorage defines an interface for managing pre-authenticated sessions.
type PreauthSessionStorage interface {
	NewSession(ctx context.Context, username string) (ccc.UUID, error)

	// common storage functions
	storageManager
}

// PasswordSessionStorage defines an interface for managing username/password sessions.
type PasswordSessionStorage interface {
	NewSession(ctx context.Context, username string) (ccc.UUID, error)

	// common storage functions
	storageManager
}

type sessionHandlers interface {
	Authenticated() http.HandlerFunc
	Logout() http.HandlerFunc
	SetSessionTimeout(next http.Handler) http.Handler
	StartSession(next http.Handler) http.Handler
	ValidateSession(next http.Handler) http.Handler
	SetXSRFToken(next http.Handler) http.Handler
	ValidateXSRFToken(next http.Handler) http.Handler
}

// PasswordHandlers defines the interface for username/password session handlers.
type PasswordHandlers interface {
	Login() http.HandlerFunc
	sessionHandlers
}

// DB defines an interface for database operations related to session management.
type DB interface {
	// SessionOIDC returns the session information from the database for given sessionID.
	SessionOIDC(ctx context.Context, sessionID ccc.UUID) (*dbtype.SessionOIDC, error)
	// InsertSessionOIDC creates a new session in the database and returns its session ID.
	InsertSessionOIDC(ctx context.Context, session *dbtype.InsertSessionOIDC) (ccc.UUID, error)
	// DestroySessionOIDC marks the session as expired by oidcSID.
	DestroySessionOIDC(ctx context.Context, oidcSID string) error
	// Session returns the session information from the database for given sessionID.
	Session(ctx context.Context, sessionID ccc.UUID) (*dbtype.Session, error)
	// InsertSession creates a new session in the database and returns its session ID.
	InsertSession(ctx context.Context, session *dbtype.InsertSession) (ccc.UUID, error)
	// UpdateSessionActivity updates the session activity column with the current time.
	UpdateSessionActivity(ctx context.Context, sessionID ccc.UUID) error
	// DestroySession marks the session as expired.
	DestroySession(ctx context.Context, sessionID ccc.UUID) error
}
