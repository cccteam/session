//go:build skipAuth

package session

import (
	"context"
	"os"
	"strings"
)

// skipAuthGroupDomain is the domain the simulated lookup spells its groups under: a
// reserved name that resolves nowhere, so a simulated group can never be mistaken for a
// real one.
const skipAuthGroupDomain = "skipauth.invalid"

// defaultGroupsReader is the simulation under the skipAuth build tag.
func defaultGroupsReader() groupsReader {
	return simulatedGroups{}
}

// simulatedGroups is the lookup under the skipAuth build tag: no call to Google, no
// token. It answers the person's groups from APP_ROLES, one group per comma-separated
// entry spelled <role>@skipauth.invalid in lowercase, empty entries ignored, the way the
// simulated sign-in answers who they are from APP_USERNAME. Every simulated user is in
// the same groups, as every simulated login is APP_USERNAME, and nesting adds nothing.
type simulatedGroups struct{}

func (simulatedGroups) DirectGroups(context.Context, string, string) ([]string, error) {
	return simulatedRoleGroups(), nil
}

func (simulatedGroups) NestedGroups(context.Context, string, string) ([]string, error) {
	return simulatedRoleGroups(), nil
}

func simulatedRoleGroups() []string {
	var groups []string
	for _, role := range strings.Split(os.Getenv("APP_ROLES"), ",") {
		role = strings.TrimSpace(role)
		if role == "" {
			continue
		}
		groups = append(groups, strings.ToLower(role)+"@"+skipAuthGroupDomain)
	}

	return groups
}

// roleFromGroup derives a role name from a group. Under the skipAuth build tag the
// lookup is simulated, and a group at skipauth.invalid names its role outright, with no
// prefix to strip, because the simulation has no naming convention to follow and the
// developer setting APP_ROLES should not have to know the prefix. Any other group is
// read by the naming convention, so a real group still works.
func (g *googleRoleSyncConfig) roleFromGroup(group string) (string, bool) {
	if name, ok := strings.CutSuffix(group, "@"+skipAuthGroupDomain); ok {
		return name, name != ""
	}

	return g.roleFromPrefixedGroup(group)
}
