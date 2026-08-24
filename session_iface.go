// Package session provides session handlers for various authentication implementations.
// Currently supported are:
// 1) Azure OIDC Authorization Code Flow with PKCE
// 2) Preauth: Allows you to implement your own authentication, but still use session handlers
// 3) Username/Password: Implements user storage and password management
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
// synchronization (see RoleSync). The domain sweep list is NOT part of this
// interface — it is configuration of the sync feature, supplied to RoleSync as a
// DomainsProvider by the application, which owns the tenant table.
//
// RoleExists errors must be returned, never flattened to false: the sync is
// reconcile-with-delete, and a swallowed store error would silently remove a
// user's valid role membership at login.
type UserRoleManager interface {
	UserRoles(ctx context.Context, user accesstypes.User, domains ...accesstypes.Domain) (accesstypes.RoleCollection, error)
	RoleExists(ctx context.Context, domain accesstypes.Domain, role accesstypes.Role) (bool, error)
	AddUserRoles(ctx context.Context, domain accesstypes.Domain, user accesstypes.User, roles ...accesstypes.Role) error
	DeleteUserRoles(ctx context.Context, domain accesstypes.Domain, user accesstypes.User, roles ...accesstypes.Role) error
}

// LogHandler defines the handler signature required for handling logs.
type LogHandler = basesession.LogHandler
