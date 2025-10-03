package session

import (
	"context"

	"github.com/cccteam/ccc/accesstypes"
)

// DisabledUserManager implements the UserManager interface but disables all user management functions.
type DisabledUserManager struct{}

// DisableUserManagement returns a DisabledUserManager instance.
func DisableUserManagement() DisabledUserManager {
	return DisabledUserManager{}
}

// Domains returns a default global domain.
func (d DisabledUserManager) Domains(_ context.Context) ([]accesstypes.Domain, error) {
	return []accesstypes.Domain{accesstypes.GlobalDomain}, nil
}

// UserRoles always returns an empty RoleCollection.
func (d DisabledUserManager) UserRoles(_ context.Context, _ accesstypes.User, _ ...accesstypes.Domain) (accesstypes.RoleCollection, error) {
	return make(accesstypes.RoleCollection), nil
}

// RoleExists always returns true, indicating that any role exists.
func (d DisabledUserManager) RoleExists(_ context.Context, _ accesstypes.Domain, _ accesstypes.Role) bool {
	return true
}

// AddUserRoles does nothing and returns nil.
func (d DisabledUserManager) AddUserRoles(_ context.Context, _ accesstypes.Domain, _ accesstypes.User, _ ...accesstypes.Role) error {
	return nil
}

// DeleteUserRoles does nothing and returns nil.
func (d DisabledUserManager) DeleteUserRoles(_ context.Context, _ accesstypes.Domain, _ accesstypes.User, _ ...accesstypes.Role) error {
	return nil
}

// UserPermissions returns an empty UserPermissionCollection.
func (d DisabledUserManager) UserPermissions(_ context.Context, _ accesstypes.User, _ ...accesstypes.Domain) (accesstypes.UserPermissionCollection, error) {
	return make(accesstypes.UserPermissionCollection), nil
}
