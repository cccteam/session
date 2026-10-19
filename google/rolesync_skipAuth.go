//go:build skipAuth

package google

import (
	"context"
	"strings"

	"github.com/cccteam/session/internal/simulated"
)

// skipAuthGroupDomain is the domain the simulated lookup spells its groups under: a
// reserved name that resolves nowhere, so a simulated group can never be mistaken for a
// real one.
const skipAuthGroupDomain = "skipauth.invalid"

// defaultGroupsReader is the simulation under the skipAuth build tag.
func defaultGroupsReader() groupsReader {
	return simulatedGroups{}
}

// simulatedGroups is the lookup under the skipAuth build tag: no call to Google. The
// token it is handed is not a token but the registration's name, which the simulated
// sign-in passed in its place (OIDC.Verify), and it answers the person's groups from
// that registration's roles variable (APP_<NAME>_ROLES, else APP_ROLES), one group per
// comma-separated entry spelled <role>@skipauth.invalid in lowercase, empty entries
// ignored, the way the simulated sign-in answers who they are. Every sign-in through a
// registration is in the same groups, as every such sign-in is the same person, and
// nesting adds nothing.
type simulatedGroups struct{}

func (simulatedGroups) DirectGroups(_ context.Context, registration, _ string) ([]string, error) {
	return simulatedRoleGroups(registration), nil
}

func (simulatedGroups) NestedGroups(_ context.Context, registration, _ string) ([]string, error) {
	return simulatedRoleGroups(registration), nil
}

func simulatedRoleGroups(registration string) []string {
	roles := simulated.Roles(registration)
	groups := make([]string, 0, len(roles))
	for _, role := range roles {
		groups = append(groups, strings.ToLower(role)+"@"+skipAuthGroupDomain)
	}

	return groups
}

// roleFromGroup derives a role name from a group. Under the skipAuth build tag the
// lookup is simulated, and a group at skipauth.invalid names its role outright, with no
// prefix to strip, because the simulation has no naming convention to follow and the
// developer setting APP_ROLES should not have to know the prefix. Any other group is
// read by the naming convention, so a real group still works.
func (g *groupSync) roleFromGroup(group string) (string, bool) {
	if name, ok := strings.CutSuffix(group, "@"+skipAuthGroupDomain); ok {
		return name, name != ""
	}

	return g.roleFromPrefixedGroup(group)
}
