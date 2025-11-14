package session

import (
	"context"

	"github.com/cccteam/ccc/accesstypes"
)

var _ UserRoleManager = DisabledUserRoleManager{}

// DisabledUserRoleManager implements the UserManager interface but disables all user management functions.
type DisabledUserRoleManager struct{}

// DisableUserRoleManagement returns a DisabledUserRoleManager instance.
func DisableUserRoleManagement() DisabledUserRoleManager {
	return DisabledUserRoleManager{}
}

// Domains returns a default global domain.
func (d DisabledUserRoleManager) Domains(_ context.Context) ([]accesstypes.Domain, error) {
	return []accesstypes.Domain{accesstypes.GlobalDomain}, nil
}

// UserRoles always returns an empty RoleCollection.
func (d DisabledUserRoleManager) UserRoles(_ context.Context, _ accesstypes.User, _ ...accesstypes.Domain) (accesstypes.RoleCollection, error) {
	return make(accesstypes.RoleCollection), nil
}

// RoleExists always returns true, indicating that any role exists.
func (d DisabledUserRoleManager) RoleExists(_ context.Context, _ accesstypes.Domain, _ accesstypes.Role) bool {
	return true
}

// AddUserRoles does nothing and returns nil.
func (d DisabledUserRoleManager) AddUserRoles(_ context.Context, _ accesstypes.Domain, _ accesstypes.User, _ ...accesstypes.Role) error {
	return nil
}

// DeleteUserRoles does nothing and returns nil.
func (d DisabledUserRoleManager) DeleteUserRoles(_ context.Context, _ accesstypes.Domain, _ accesstypes.User, _ ...accesstypes.Role) error {
	return nil
}
