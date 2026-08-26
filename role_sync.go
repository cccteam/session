package session

import (
	"context"

	"github.com/cccteam/ccc/accesstypes"
	"github.com/go-playground/errors/v5"
)

// DomainsProvider returns the set of domains (tenant partitions) that role
// synchronization reconciles a user's IdP roles across on every login. It is
// called at each login so tenants created between logins are included.
//
// The provider returns tenant domains only: the global scope is always swept
// implicitly (it is structural — no domain value can address it, so any
// returned string is just a tenant name). Multi-tenant applications return
// their tenant domains; global-only applications use a nil provider.
type DomainsProvider func(ctx context.Context) ([]accesstypes.Domain, error)

// RoleSyncConfig is the required role-synchronization slot on NewOIDCAzure and
// NewOIDCAzure. Role synchronization and its domain sweep list are one
// capability: construct the slot with RoleSync to enable it, or with
// DisableRoleSync to run the OIDC flow with role management left entirely to
// the application. There is no default — see the OIDCAzure documentation for
// the semantics of each choice.
type RoleSyncConfig interface {
	// config returns the enabled configuration, or nil when synchronization is
	// disabled. Unexported: RoleSync and DisableRoleSync are the only
	// implementations.
	config() *roleSyncConfig
}

type roleSyncConfig struct {
	manager UserRoleManager
	domains DomainsProvider
}

func (r *roleSyncConfig) config() *roleSyncConfig { return r }

// syncScopes returns the full sweep list for one login: the global scope
// followed by a tenant scope for each of the provider's domains. Tenant names
// are pure data — no value can address the global partition, so no rejection
// is needed.
func (r *roleSyncConfig) syncScopes(ctx context.Context) ([]accesstypes.Scope, error) {
	scopes := []accesstypes.Scope{accesstypes.GlobalScope()}
	if r.domains == nil {
		return scopes, nil
	}

	appDomains, err := r.domains(ctx)
	if err != nil {
		return nil, errors.Wrap(err, "session.DomainsProvider")
	}
	for _, d := range appDomains {
		scopes = append(scopes, accesstypes.DomainScope(d))
	}

	return scopes, nil
}

type disabledRoleSync struct{}

func (disabledRoleSync) config() *roleSyncConfig { return nil }

// RoleSync enables IdP-driven role synchronization for the OIDC Azure flow: on
// every login the user's roles are reconciled to the token's role claims across
// the global scope plus a tenant scope for every domain returned by the
// provider, and the login is rejected unless the token yields at least one
// recognized role.
//
// The provider is required alongside the manager because there is no safe
// universal default for the sweep list: a global-only default in a multi-tenant
// application would log users in while silently never assigning (or sweeping)
// their tenant-domain roles. Global-only applications pass a nil provider.
//
// See the OIDCAzure documentation for the full synchronization semantics and
// their multi-tenancy limitations.
func RoleSync(manager UserRoleManager, domains DomainsProvider) RoleSyncConfig {
	return &roleSyncConfig{manager: manager, domains: domains}
}

// DisableRoleSync disables role synchronization for the OIDC Azure flow: no
// roles are read, written, or removed at login, and the at-least-one-role login
// gate does not apply — every user the identity provider verifies may log in.
// Use it when the application manages roles itself (or uses no roles at all);
// IdP role claims remain available to a custom session data resolver via the
// raw claims.
func DisableRoleSync() RoleSyncConfig {
	return disabledRoleSync{}
}
