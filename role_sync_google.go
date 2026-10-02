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
// satisfy this slot: the Google flow's roles come from a group lookup made with the
// person's own token and a group naming convention, inputs Azure's slot does not carry.
type GoogleRoleSyncConfig interface {
	// googleConfig returns the enabled configuration, or nil when synchronization is
	// disabled. Unexported: GoogleRoleSync and DisableRoleSync are the only
	// implementations.
	googleConfig() *googleRoleSyncConfig
}

type googleRoleSyncConfig struct {
	roleSyncConfig
	groupPrefix string
	lookup      groupLookupMode
	groups      groupsReader
}

// groupsReader is what the lookup runs through: cloudidentity.Lookup in production, the
// APP_ROLES simulation under the skipAuth build tag, and a fake in the tests. Unexported,
// since nothing outside the package chooses it.
type groupsReader interface {
	DirectGroups(ctx context.Context, token, member string) ([]string, error)
	NestedGroups(ctx context.Context, token, member string) ([]string, error)
}

func (g *googleRoleSyncConfig) googleConfig() *googleRoleSyncConfig { return g }

func (disabledRoleSync) googleConfig() *googleRoleSyncConfig { return nil }

// GroupLookup says how far the sign-in's group lookup reaches. It is sealed: DirectGroups
// and NestedGroups are its only values, so an application chooses one of the two and
// nothing else can be passed.
type GroupLookup interface {
	lookupMode() groupLookupMode
}

type groupLookupMode int

const (
	lookupUnset groupLookupMode = iota
	lookupDirect
	lookupNested
)

// The names the settings spell the lookups by.
const (
	lookupNameDirect = "direct"
	lookupNameNested = "nested"
)

func (m groupLookupMode) lookupMode() groupLookupMode {
	return m
}

func (m groupLookupMode) String() string {
	switch m {
	case lookupDirect:
		return lookupNameDirect
	case lookupNested:
		return lookupNameNested
	default:
		return "unset"
	}
}

// DirectGroups is the lookup that counts only the groups a person is directly assigned
// to: one call, however the directory is nested. It is the default, and the choice for
// a directory whose role groups are assigned to people directly.
func DirectGroups() GroupLookup {
	return lookupDirect
}

// NestedGroups is the lookup that also counts the groups those groups are in, level by
// level, up to cloudidentity.MaxDepth levels: a person in a team group that sits inside
// a role group holds the role. Each level is one round of calls to Google, so a deeply
// nested directory makes sign-in slower; DirectGroups restores the one call.
func NestedGroups() GroupLookup {
	return lookupNested
}

// ParseGroupLookup reads a lookup from its configured name: "direct" or "nested", in
// any case, surrounding space ignored. An empty value is DirectGroups, the default.
// Anything else is an error, so a misspelled setting stops the application when it
// constructs its auth rather than changing how roles are granted.
func ParseGroupLookup(value string) (GroupLookup, error) {
	switch strings.ToLower(strings.TrimSpace(value)) {
	case "", lookupNameDirect:
		return DirectGroups(), nil
	case lookupNameNested:
		return NestedGroups(), nil
	default:
		return nil, errors.Newf("%q is not a group lookup: use direct or nested", value)
	}
}

// GoogleRoleSync enables directory-driven role synchronization for the OIDC Google
// flow. Google Workspace has no equivalent of Azure App Roles — group membership is the
// directory's only authorization signal — so the role names are derived from a group
// naming convention: a group email whose local part is groupPrefix followed by a role
// name (e.g. prefix "app-myapp-" and group "app-myapp-admin@example.com" yield the
// candidate role "admin"). On every login the person's groups are read through the
// Cloud Identity Groups API with the person's own access token, as far as lookup
// reaches (DirectGroups or NestedGroups), mapped through the prefix, and reconciled
// exactly like Azure's token role claims: candidate names for which a role exists are
// assigned where the role is held (the global partition for a global role, every tenant
// domain for a domain role), roles the user holds that are absent are removed wherever
// they are held, and the login is rejected unless at least one recognized role results.
//
// Google answers only the groups whose member list the person may view, so a group
// grants a role only when its "who can view members" setting includes its members; a
// group that hides them is simply absent, and with NestedGroups nothing above it is
// reached. No administrator credential is involved.
//
// Group emails are lowercase by nature, so derived role names are lowercase — define
// the application roles intended for Google sync with lowercase names.
func GoogleRoleSync(manager UserRoleManager, groupPrefix string, lookup GroupLookup) GoogleRoleSyncConfig {
	cfg := &googleRoleSyncConfig{
		roleSyncConfig: roleSyncConfig{manager: manager},
		groupPrefix:    strings.ToLower(groupPrefix),
		groups:         defaultGroupsReader(),
	}
	if lookup != nil {
		cfg.lookup = lookup.lookupMode()
	}

	return cfg
}

// roleNames resolves the user's candidate role names: the person's groups are read with
// accessToken, the person's own token from the sign-in, and filtered through the prefix
// convention — a group counts iff its local part starts with the configured prefix, and
// the remainder of the local part is the candidate role name. Everything else (unrelated
// groups, a bare prefix with no role name, values without an @) is ignored. The token
// is used for the lookup and nowhere else.
func (g *googleRoleSyncConfig) roleNames(ctx context.Context, email, accessToken string) ([]string, error) {
	groups, err := g.userGroups(ctx, email, accessToken)
	if err != nil {
		return nil, err
	}

	var names []string
	for _, group := range groups {
		if name, ok := g.roleFromGroup(strings.ToLower(group)); ok {
			names = append(names, name)
		}
	}

	return names, nil
}

// userGroups reads the person's groups as far as the configured lookup reaches.
func (g *googleRoleSyncConfig) userGroups(ctx context.Context, email, accessToken string) ([]string, error) {
	if g.lookup == lookupNested {
		groups, err := g.groups.NestedGroups(ctx, accessToken, email)
		if err != nil {
			return nil, errors.Wrap(err, "groupsReader.NestedGroups()")
		}

		return groups, nil
	}
	groups, err := g.groups.DirectGroups(ctx, accessToken, email)
	if err != nil {
		return nil, errors.Wrap(err, "groupsReader.DirectGroups()")
	}

	return groups, nil
}

// roleFromPrefixedGroup applies the naming convention to one lowercased group email: the
// local part must start with the configured prefix, and the remainder is the role name.
func (g *googleRoleSyncConfig) roleFromPrefixedGroup(group string) (string, bool) {
	local, _, found := strings.Cut(group, "@")
	if !found {
		return "", false
	}
	name, ok := strings.CutPrefix(local, g.groupPrefix)
	if !ok || name == "" {
		return "", false
	}

	return name, true
}
