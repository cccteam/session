package signin

import (
	"context"

	"github.com/cccteam/ccc/accesstypes"
)

// UserRoleManager defines the role store operations required by OIDC role
// synchronization (see RoleSync). The sync writes memberships in two places,
// the global partition and every tenant domain: a role that exists in the
// global partition is held there, a role that exists in every tenant domain is
// held there, and a membership the directory does not name is removed wherever
// it is held.
//
// RoleExists errors must be returned, never flattened to false: the sync is
// reconcile-with-delete, and a swallowed store error would silently remove a
// user's valid role membership at login.
type UserRoleManager interface {
	// UserRoles lists the roles the user holds in the given places. With no
	// scopes it lists every membership the user holds, keyed by where each is
	// held.
	UserRoles(ctx context.Context, user accesstypes.User, scopes ...accesstypes.PolicyScope) (accesstypes.RoleCollection, error)
	// RoleExists reports whether a role of that name is held in the place: in
	// the global partition for a global role, in every tenant domain for a
	// domain default role or a custom role created in every domain.
	RoleExists(ctx context.Context, scope accesstypes.PolicyScope, role accesstypes.Role) (bool, error)
	// AddUserRoles writes the user's membership in the roles, held in the place.
	AddUserRoles(ctx context.Context, scope accesstypes.PolicyScope, user accesstypes.User, roles ...accesstypes.Role) error
	// DeleteUserRoles removes the user's membership in the roles held in the place.
	DeleteUserRoles(ctx context.Context, scope accesstypes.PolicyScope, user accesstypes.User, roles ...accesstypes.Role) error
}
