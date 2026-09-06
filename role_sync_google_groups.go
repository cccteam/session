//go:build !skipAuth

package session

// roleFromGroup derives a role name from one of the directory's groups: the naming
// convention alone decides, as GoogleRoleSync documents.
func (g *googleRoleSyncConfig) roleFromGroup(group string) (string, bool) {
	return g.roleFromPrefixedGroup(group)
}
