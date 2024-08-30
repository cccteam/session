package session

import (
	"context"

	"github.com/cccteam/access/accesstypes"
	"github.com/cccteam/ccc"
	"github.com/cccteam/session/sessioninfo"
)

type UserManager interface {
	Domains(ctx context.Context) ([]accesstypes.Domain, error)
	UserRoles(ctx context.Context, username accesstypes.User, domain ...accesstypes.Domain) (map[accesstypes.Domain][]accesstypes.Role, error)
	RoleExists(ctx context.Context, role accesstypes.Role, domain accesstypes.Domain) bool
	AddUserRoles(ctx context.Context, user accesstypes.User, roles []accesstypes.Role, domain accesstypes.Domain) error
	DeleteUserRole(ctx context.Context, user accesstypes.User, role accesstypes.Role, domain accesstypes.Domain) error
	UserPermissions(ctx context.Context, username accesstypes.User, domain ...accesstypes.Domain) (map[accesstypes.Domain][]accesstypes.Permission, error)
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
