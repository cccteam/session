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
// A directory names roles without regard to case (a Google group is an email
// address, and the groups lookup lowercases what it reads), so the sync hands
// the store a name and takes back the role in the spelling the store holds it:
// what the person holds and what the directory names compare as one set of
// names, and every write carries the store's spelling.
//
// ResolveRole errors must be returned, never flattened to "not found": the sync
// is reconcile-with-delete, and a swallowed store error would silently remove a
// user's valid role membership at login.
type UserRoleManager interface {
	// UserRoles lists the roles the user holds in the given places. With no
	// scopes it lists every membership the user holds, keyed by where each is
	// held.
	UserRoles(ctx context.Context, user accesstypes.User, scopes ...accesstypes.PolicyScope) (accesstypes.RoleCollection, error)
	// ResolveRole returns the role held in the place under name, matched without
	// regard to case, in the spelling the store holds it: in the global
	// partition for a global role, in every tenant domain for a domain default
	// role or a custom role created in every domain. Not found is (“”, false,
	// nil); two roles differing only in case with no exact match is an error.
	ResolveRole(ctx context.Context, scope accesstypes.PolicyScope, name string) (accesstypes.Role, bool, error)
	// AddUserRoles writes the user's membership in the roles, held in the place.
	AddUserRoles(ctx context.Context, scope accesstypes.PolicyScope, user accesstypes.User, roles ...accesstypes.Role) error
	// DeleteUserRoles removes the user's membership in the roles held in the place.
	DeleteUserRoles(ctx context.Context, scope accesstypes.PolicyScope, user accesstypes.User, roles ...accesstypes.Role) error
}
