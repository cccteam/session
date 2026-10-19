//go:build !skipAuth

package google

// defaultGroupsReader is the Cloud Identity Groups API, read with the person's own
// token.
func defaultGroupsReader() groupsReader {
	return cloudIdentityGroups{}
}

// roleFromGroup derives a role name from one of the directory's groups: the naming
// convention alone decides, as RoleSync documents.
func (g *groupSync) roleFromGroup(group string) (string, bool) {
	return g.roleFromPrefixedGroup(group)
}
