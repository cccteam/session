// Package session provides session handlers for various authentication implementations.
// Currently supported are:
// 1) Azure OIDC Authorization Code Flow with PKCE
// 2) Google Workspace OIDC Authorization Code Flow with PKCE, restricted to a hosted domain
// 3) Preauth: Allows you to implement your own authentication, but still use session handlers
// 4) Username/Password: Implements user storage and password management
//
// All three support custom session data: an app-defined table whose row is resolved
// atomically inside the session-insert transaction (or supplied per call), decoded on
// every authenticated request, reset on session regeneration, and cleaned up with the
// session via the table's ON DELETE CASCADE. See the "Custom session data" section of
// the README for the full lifecycle, schema contract, and failure semantics.
//
// Password auth and OIDC additionally support custom user data: an app-defined table
// keyed by the durable user record (SessionUsers, or the library-managed OIDCUsers
// anchor for OIDC), written atomically with user creation or login and read on demand —
// it survives logout, expiry, and regeneration, and dies with the user. See the
// "Custom user data" and "OIDC user anchor" sections of the README.
package session

import (
	"context"

	"github.com/cccteam/ccc/accesstypes"
	"github.com/cccteam/session/internal/basesession"
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

// LogHandler defines the handler signature required for handling logs.
type LogHandler = basesession.LogHandler
