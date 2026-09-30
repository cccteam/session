//go:build !skipAuth

package session

import "github.com/cccteam/session/internal/cloudidentity"

// defaultGroupsReader is the Cloud Identity Groups API, read with the person's own
// token.
func defaultGroupsReader() groupsReader {
	return cloudidentity.Lookup{}
}

// roleFromGroup derives a role name from one of the directory's groups: the naming
// convention alone decides, as GoogleRoleSync documents.
func (g *googleRoleSyncConfig) roleFromGroup(group string) (string, bool) {
	return g.roleFromPrefixedGroup(group)
}
