package session

import (
	"cmp"
	"context"
	"maps"
	"slices"

	"github.com/cccteam/ccc/accesstypes"
	"github.com/cccteam/ccc/tracer"
	"github.com/cccteam/logger"
	"github.com/cccteam/session/internal/util"
	"github.com/go-playground/errors/v5"
)

// RoleSyncConfig is the required role-synchronization slot on NewOIDCAzure.
// Construct the slot with RoleSync to enable synchronization, or with
// DisableRoleSync to run the OIDC flow with role management left entirely to
// the application. There is no default — see the OIDCAzure documentation for
// the semantics of each choice. (The Google flow has its own slot:
// GoogleRoleSyncConfig.)
type RoleSyncConfig interface {
	// config returns the enabled configuration, or nil when synchronization is
	// disabled. Unexported: RoleSync and DisableRoleSync are the only
	// implementations.
	config() *roleSyncConfig
}

type roleSyncConfig struct {
	manager UserRoleManager
}

func (r *roleSyncConfig) config() *roleSyncConfig { return r }

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
func (r *roleSyncConfig) reconcile(ctx context.Context, username accesstypes.User, roleNames []string) (hasRole bool, err error) {
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
func (r *roleSyncConfig) wantedRoles(ctx context.Context, roleNames []string) (map[accesstypes.PolicyScope][]accesstypes.Role, error) {
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

func (disabledRoleSync) config() *roleSyncConfig { return nil }

// RoleSync enables directory-driven role synchronization for the OIDC Azure
// flow: on every login the user's memberships are reconciled to the roles the
// token names. A global role is held in the global partition and a domain role
// in every tenant domain, and a membership the directory does not name —
// wherever it is held — is removed. The login is rejected unless at least one
// recognized role results.
//
// See the OIDCAzure documentation for the full synchronization semantics.
func RoleSync(manager UserRoleManager) RoleSyncConfig {
	return &roleSyncConfig{manager: manager}
}

// DisabledRoleSyncConfig is the type returned by DisableRoleSync. It satisfies
// the role-synchronization slot of every OIDC provider constructor (Azure's
// RoleSyncConfig and Google's GoogleRoleSyncConfig).
type DisabledRoleSyncConfig interface {
	RoleSyncConfig
	GoogleRoleSyncConfig
}

// DisableRoleSync disables role synchronization for an OIDC flow: no roles are
// read, written, or removed at login, and the at-least-one-role login gate
// does not apply — every user the identity provider verifies may log in. Use
// it when the application manages roles itself (or uses no roles at all); IdP
// role claims remain available to a custom session data resolver via the raw
// claims.
func DisableRoleSync() DisabledRoleSyncConfig {
	return disabledRoleSync{}
}
