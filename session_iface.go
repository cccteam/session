package session

import (
	"context"
	"net/http"

	"github.com/cccteam/ccc"
	"github.com/cccteam/ccc/accesstypes"
	"github.com/cccteam/session/dbtypes"
	"github.com/cccteam/session/sessioninfo"
)

type UserManager interface {
	Domains(ctx context.Context) ([]accesstypes.Domain, error)
	UserRoles(ctx context.Context, user accesstypes.User, domains ...accesstypes.Domain) (accesstypes.RoleCollection, error)
	RoleExists(ctx context.Context, domain accesstypes.Domain, role accesstypes.Role) bool
	AddUserRoles(ctx context.Context, domain accesstypes.Domain, user accesstypes.User, roles ...accesstypes.Role) error
	DeleteUserRoles(ctx context.Context, domain accesstypes.Domain, user accesstypes.User, roles ...accesstypes.Role) error
	UserPermissions(ctx context.Context, user accesstypes.User, domains ...accesstypes.Domain) (accesstypes.UserPermissionCollection, error)
}

type UserPermissionManager interface {
	UserPermissions(ctx context.Context, user accesstypes.User, domains ...accesstypes.Domain) (accesstypes.UserPermissionCollection, error)
}

type storageManager interface {
	DestroySession(ctx context.Context, sessionID ccc.UUID) error
	UpdateSessionActivity(ctx context.Context, sessionID ccc.UUID) error
	Session(ctx context.Context, sessionID ccc.UUID) (*sessioninfo.SessionInfo, error)
}

type OIDCAzureSessionStorage interface {
	DestroySessionOIDC(ctx context.Context, oidcSID string) error
	NewSession(ctx context.Context, username, oidcSID string) (ccc.UUID, error)

	// common storage functions
	storageManager
}

type PreauthSessionStorage interface {
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

type DB interface {
	// Session returns the session information from the database for given sessionID.
	SessionOIDC(ctx context.Context, sessionID ccc.UUID) (*dbtypes.SessionOIDC, error)
	// InsertSession creates a new session in the database and returns its session ID.
	InsertSessionOIDC(ctx context.Context, session *dbtypes.InsertSessionOIDC) (ccc.UUID, error)
	// DestroySessionOIDC marks the session as expired by oidcSID.
	DestroySessionOIDC(ctx context.Context, oidcSID string) error
	// Session returns the session information from the database for given sessionID.
	Session(ctx context.Context, sessionID ccc.UUID) (*dbtypes.Session, error)
	// InsertSession creates a new session in the database and returns its session ID.
	InsertSession(ctx context.Context, session *dbtypes.InsertSession) (ccc.UUID, error)
	// UpdateSessionActivity updates the session activity column with the current time.
	UpdateSessionActivity(ctx context.Context, sessionID ccc.UUID) error
	// DestroySession marks the session as expired.
	DestroySession(ctx context.Context, sessionID ccc.UUID) error
}
