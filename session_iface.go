package session

import (
	"context"

	"github.com/cccteam/access"
	"github.com/cccteam/ccc"
	"github.com/cccteam/session/sessiontypes"
)

type Accessor interface {
	Domains(ctx context.Context) ([]access.Domain, error)
	UserRoles(ctx context.Context, username access.User, domain ...access.Domain) (map[access.Domain][]access.Role, error)
	RoleExists(ctx context.Context, role access.Role, domain access.Domain) bool
	AddUserRoles(ctx context.Context, user access.User, roles []access.Role, domain access.Domain) error
	DeleteUserRole(ctx context.Context, user access.User, role access.Role, domain access.Domain) error
	UserPermissions(ctx context.Context, username access.User, domain ...access.Domain) (map[access.Domain][]access.Permission, error)
}

type StorageManager interface {
	DestroySession(ctx context.Context, sessionID ccc.UUID) error
	UpdateSessionActivity(ctx context.Context, sessionID ccc.UUID) error
	Session(ctx context.Context, sessionID ccc.UUID) (*sessiontypes.SessionInfo, error)
}

type OIDCAzureSessionStorage interface {
	DestroySessionOIDC(ctx context.Context, oidcSID string) error
	NewSession(ctx context.Context, username, oidcSID string) (ccc.UUID, error)

	// common storage functions that aren't oidc specific
	StorageManager
}
