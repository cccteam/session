package session

import (
	"context"

	"github.com/cccteam/access/accesstypes"
	"github.com/cccteam/ccc"
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

type storageManager interface {
	DestroySession(ctx context.Context, sessionID ccc.UUID) error
	UpdateSessionActivity(ctx context.Context, sessionID ccc.UUID) error
	Session(ctx context.Context, sessionID ccc.UUID) (*sessioninfo.SessionInfo, error)
}

type OIDCAzureSessionStorage interface {
	DestroySessionOIDC(ctx context.Context, oidcSID string) error
	NewSession(ctx context.Context, username, oidcSID string) (ccc.UUID, error)

	// common storage functions that aren't oidc specific
	storageManager
}
