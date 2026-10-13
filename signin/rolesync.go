package signin

import (
	"cmp"
	"context"
	"maps"
	"slices"

	"github.com/cccteam/ccc/accesstypes"
	"github.com/cccteam/ccc/tracer"
	"github.com/cccteam/httpio"
	"github.com/cccteam/logger"
	"github.com/cccteam/session/internal/util"
	"github.com/cccteam/session/sessioninfo"
	"github.com/go-playground/errors/v5"
)

// RoleSyncConfig is the required role-synchronization slot of a method whose identity
// provider asserts the user's roles, such as the Microsoft Entra ID method. Construct
// the slot with RoleSync to enable synchronization, or with DisableRoleSync to leave
// role management entirely to the application. There is no default. (The Google
// Workspace method has its own slot, because its roles come from a group lookup.)
type RoleSyncConfig interface {
	// reconciler returns the enabled reconciler, or nil when synchronization is
	// disabled. Unexported: RoleSync and DisableRoleSync are the only
	// implementations.
	reconciler() *RoleReconciler
}

// RoleReconciler reconciles a user's role memberships to the role names an identity
// provider asserted. A method gets one from ReconcilerOf at registration.
type RoleReconciler struct {
	manager UserRoleManager
}

func (r *RoleReconciler) reconciler() *RoleReconciler { return r }

// ReconcilerOf validates a method's required role sync slot. It returns nil when role
// sync is disabled, and an error when the slot is missing or RoleSync was given no
// manager.
func ReconcilerOf(cfg RoleSyncConfig) (*RoleReconciler, error) {
	if cfg == nil {
		return nil, errors.New("roleSync is required: pass signin.RoleSync(manager) or signin.DisableRoleSync()")
	}
	r := cfg.reconciler()
	if r != nil && r.manager == nil {
		return nil, errors.New("signin.RoleSync() requires a non-nil UserRoleManager")
	}

	return r, nil
}

// RequireRoles reconciles username's roles to roleNames. It refuses the sign-in with
// RefusedNoRoles when no recognized role results.
func (r *RoleReconciler) RequireRoles(ctx context.Context, username accesstypes.User, roleNames []string) error {
	hasRole, err := r.reconcile(ctx, username, roleNames)
	if err != nil {
		return errors.Wrap(err, "RoleReconciler.reconcile()")
	}
	if !hasRole {
		return sessioninfo.NewLoginRefusal(sessioninfo.RefusedNoRoles, httpio.NewUnauthorizedMessage("Unauthorized: user has no roles"))
	}

	return nil
}

// writeScopes returns the places the sync writes a membership: the global
// partition, where a global role is held, and every tenant domain, where a
// domain role is held. The sync asks RoleExists in these two places only and
// keeps no list of tenants, since a membership held in every domain reaches
// each tenant on its own, the ones created later included.
func writeScopes() []accesstypes.PolicyScope {
	return []accesstypes.PolicyScope{accesstypes.GlobalPolicyScope(), accesstypes.EveryDomainPolicyScope()}
}

// reconcile ensures that the user holds the named roles ONLY: a name that is a
// role in the global partition is held there, a name that is a role in every
// tenant domain is held there (a name may be both), and a membership the
// directory does not name is removed wherever it is held, a membership in one
// tenant domain included, since the directory is the authority and a membership
// it does not name does not survive a login. It returns true if the user holds
// at least one recognized role once the operation is complete.
// A RoleExists error aborts the sync: flattening it to false would land an existing
// valid role in removeRoles and delete the user's membership on a transient store blip.
func (r *RoleReconciler) reconcile(ctx context.Context, username accesstypes.User, roleNames []string) (hasRole bool, err error) {
	ctx, span := tracer.Start(ctx)
	defer span.End()

	existing, err := r.manager.UserRoles(ctx, username)
	if err != nil {
		return false, errors.Wrap(err, "UserRoleManager.UserRoles()")
	}

	wanted, err := r.wantedRoles(ctx, roleNames)
	if err != nil {
		return false, err
	}

	for _, scope := range writeScopes() {
		newRoles := util.Exclude(wanted[scope], existing[scope])
		if len(newRoles) > 0 {
			if err := r.manager.AddUserRoles(ctx, scope, username, newRoles...); err != nil {
				return false, errors.Wrap(err, "UserRoleManager.AddUserRoles()")
			}
			logger.FromCtx(ctx).Infof("User %s assigned to roles %v in scope %s", username, newRoles, scope)
		}

		hasRole = hasRole || len(wanted[scope]) > 0
	}

	for _, scope := range heldScopes(existing) {
		removeRoles := util.Exclude(existing[scope], wanted[scope])
		if len(removeRoles) > 0 {
			if err := r.manager.DeleteUserRoles(ctx, scope, username, removeRoles...); err != nil {
				return false, errors.Wrap(err, "UserRoleManager.DeleteUserRoles()")
			}
			logger.FromCtx(ctx).Infof("User %s removed from roles %v in scope %s", username, removeRoles, scope)
		}
	}

	return hasRole, nil
}

// wantedRoles maps each place the sync writes to the candidate names that are
// roles there, in candidate order: a name that exists in the global partition
// is wanted there, a name that exists in every tenant domain is wanted there,
// a name that exists in both is wanted in both, and a name that exists in
// neither is ignored. A RoleExists error is returned as is, never read as
// "missing".
func (r *RoleReconciler) wantedRoles(ctx context.Context, roleNames []string) (map[accesstypes.PolicyScope][]accesstypes.Role, error) {
	wanted := make(map[accesstypes.PolicyScope][]accesstypes.Role)
	for _, name := range roleNames {
		for _, scope := range writeScopes() {
			exists, err := r.manager.RoleExists(ctx, scope, accesstypes.Role(name))
			if err != nil {
				return nil, errors.Wrap(err, "UserRoleManager.RoleExists()")
			}
			if exists {
				wanted[scope] = append(wanted[scope], accesstypes.Role(name))
			}
		}
	}

	return wanted, nil
}

// heldScopes lists the places the user holds a membership, in a fixed order so
// the removals are applied and logged the same way on every login: the global
// partition, then every tenant domain, then the one-domain places by domain.
func heldScopes(existing accesstypes.RoleCollection) []accesstypes.PolicyScope {
	scopes := slices.Collect(maps.Keys(existing))
	slices.SortFunc(scopes, comparePolicyScopes)

	return scopes
}

// comparePolicyScopes orders the global partition before every tenant domain
// before the one-domain places, the one-domain places by domain, and places
// on different axes by axis.
func comparePolicyScopes(a, b accesstypes.PolicyScope) int {
	if c := cmp.Compare(scopeRank(a), scopeRank(b)); c != 0 {
		return c
	}
	domainA, _ := a.Domain()
	domainB, _ := b.Domain()
	if c := cmp.Compare(domainA, domainB); c != 0 {
		return c
	}

	return cmp.Compare(a.Axis(), b.Axis())
}

// scopeRank is the position of a kind of place in heldScopes' order.
func scopeRank(scope accesstypes.PolicyScope) int {
	switch {
	case scope.IsGlobal():
		return 0
	case scope.IsEveryDomain():
		return 1
	default:
		return 2
	}
}

type disabledRoleSync struct{}

func (disabledRoleSync) reconciler() *RoleReconciler { return nil }

// RoleSync enables directory-driven role synchronization for a method whose identity
// provider asserts the user's roles: on every sign-in the user's memberships are
// reconciled to the roles the provider names. A global role is held in the global
// partition and a domain role in every tenant domain, and a membership the directory
// does not name, wherever it is held, is removed. The sign-in is refused unless at
// least one recognized role results.
func RoleSync(manager UserRoleManager) RoleSyncConfig {
	return &RoleReconciler{manager: manager}
}

// DisabledRoleSyncConfig is the type returned by DisableRoleSync: a RoleSyncConfig that
// disables synchronization.
type DisabledRoleSyncConfig interface {
	RoleSyncConfig
}

// DisableRoleSync disables role synchronization for a method: no roles are read,
// written, or removed at sign-in, and the at-least-one-role gate does not apply; every
// user the identity provider verifies may sign in. Use it when the application manages
// roles itself (or uses no roles at all); the provider's role claims remain available
// to a custom session data resolver through the raw claims.
func DisableRoleSync() DisabledRoleSyncConfig {
	return disabledRoleSync{}
}
