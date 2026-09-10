package session

import (
	"context"
	"strings"

	"github.com/go-playground/errors/v5"
)

// GoogleRoleSyncConfig is the required role-synchronization slot on NewOIDCGoogle.
// Role synchronization and its configuration are one capability: construct the slot
// with GoogleRoleSync to enable it, or with DisableRoleSync to run the OIDC flow with
// role management left entirely to the application. There is no default — see the
// OIDCGoogle documentation for the semantics of each choice. Azure's RoleSync does not
// satisfy this slot: the Google flow's roles come from a Groups API lookup and a group
// naming convention, inputs Azure's slot does not carry.
type GoogleRoleSyncConfig interface {
	// googleConfig returns the enabled configuration, or nil when synchronization is
	// disabled. Unexported: GoogleRoleSync and DisableRoleSync are the only
	// implementations.
	googleConfig() *googleRoleSyncConfig
}

type googleRoleSyncConfig struct {
	roleSyncConfig
	groupPrefix string
	groups      GroupsProvider
}

func (g *googleRoleSyncConfig) googleConfig() *googleRoleSyncConfig { return g }

func (disabledRoleSync) googleConfig() *googleRoleSyncConfig { return nil }

// GoogleRoleSync enables directory-driven role synchronization for the OIDC Google
// flow. Google Workspace has no equivalent of Azure App Roles — group membership is the
// directory's only authorization signal — so the role names are derived from a group
// naming convention: a group email whose local part is groupPrefix followed by a role
// name (e.g. prefix "app-myapp-" and group "app-myapp-admin@example.com" yield the
// candidate role "admin"). On every login the user's groups are fetched through the
// GroupsProvider, mapped through the prefix, and reconciled exactly like Azure's token
// role claims: candidate names for which a role exists are assigned, roles the user
// holds that are absent are removed, and the login is rejected unless at least one
// recognized role results.
//
// Group emails are lowercase by nature, so derived role names are lowercase — define
// the application roles intended for Google sync with lowercase names.
//
// The domains provider is required alongside the manager because there is no safe
// universal default for the sweep list (see RoleSync); global-only applications pass a
// nil provider.
func GoogleRoleSync(manager UserRoleManager, domains DomainsProvider, groupPrefix string, groups GroupsProvider) GoogleRoleSyncConfig {
	return &googleRoleSyncConfig{
		roleSyncConfig: roleSyncConfig{manager: manager, domains: domains},
		groupPrefix:    strings.ToLower(groupPrefix),
		groups:         groups,
	}
}

// roleNames resolves the user's candidate role names: the user's group emails are
// fetched from the GroupsProvider and filtered through the prefix convention — a group
// counts iff its local part starts with the configured prefix, and the remainder of the
// local part is the candidate role name. Everything else (unrelated groups, a bare
// prefix with no role name, values without an @) is ignored.
func (g *googleRoleSyncConfig) roleNames(ctx context.Context, email string) ([]string, error) {
	groups, err := g.groups.UserGroups(ctx, email)
	if err != nil {
		return nil, errors.Wrap(err, "session.GroupsProvider.UserGroups()")
	}

	var names []string
	for _, group := range groups {
		local, _, found := strings.Cut(strings.ToLower(group), "@")
		if !found {
			continue
		}
		name, ok := strings.CutPrefix(local, g.groupPrefix)
		if !ok || name == "" {
			continue
		}
		names = append(names, name)
	}

	return names, nil
}
