//go:build skipAuth

package session

import "strings"

// skipAuthGroupDomain is the domain the simulated directory spells its groups under (see
// googlegroups under the same build tag): a reserved name that resolves nowhere, so a
// simulated group can never be mistaken for a real one.
const skipAuthGroupDomain = "skipauth.invalid"

// roleFromGroup derives a role name from a group. Under the skipAuth build tag the
// directory is simulated: googlegroups answers the person's groups from APP_ROLES, one
// group per role spelled <role>@skipauth.invalid, and such a group names its role outright,
// with no prefix to strip, because the simulation has no naming convention to follow and
// the developer setting APP_ROLES should not have to know the prefix. Any other group is
// read by the naming convention, so a provider that presents real groups still works.
func (g *googleRoleSyncConfig) roleFromGroup(group string) (string, bool) {
	if name, ok := strings.CutSuffix(group, "@"+skipAuthGroupDomain); ok {
		return name, name != ""
	}

	return g.roleFromPrefixedGroup(group)
}
