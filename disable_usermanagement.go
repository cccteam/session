// Handles disabling permission functions for the session package
package session

import (
	"context"

	"github.com/cccteam/ccc/accesstypes"
)

// DisabledPermissioner is a struct that implements UserPermissioner with no-op methods.
type DisabledPermissioner struct{}

func DisablePermissionManagement() DisabledPermissioner {
	return DisabledPermissioner{}
}

// UserPermissions is a no-op implementation that an empty UserPermissionCollection.
func (n DisabledPermissioner) UserPermissions(_ context.Context, _ accesstypes.User, _ ...accesstypes.Domain) (accesstypes.UserPermissionCollection, error) {
	return make(accesstypes.UserPermissionCollection), nil
}

// DisabledPermissions returns a DisabledPermissioner for use with the session package.
func DisabledPermissions() DisabledPermissioner {
	return DisabledPermissioner{}
}

type DisabledUserManagement struct{}

func DisableUserManagement() DisabledUserManagement {
	return DisabledUserManagement{}
}

func (d DisabledUserManagement) Domains(_ context.Context) ([]accesstypes.Domain, error) {
	return []accesstypes.Domain{accesstypes.GlobalDomain}, nil
}

func (d DisabledUserManagement) UserRoles(_ context.Context, _ accesstypes.User, _ ...accesstypes.Domain) (accesstypes.RoleCollection, error) {
	return make(accesstypes.RoleCollection), nil
}

func (d DisabledUserManagement) RoleExists(_ context.Context, _ accesstypes.Domain, _ accesstypes.Role) bool {
	return true
}

func (d DisabledUserManagement) AddUserRoles(_ context.Context, _ accesstypes.Domain, _ accesstypes.User, _ ...accesstypes.Role) error {
	return nil
}

func (d DisabledUserManagement) DeleteUserRoles(_ context.Context, _ accesstypes.Domain, _ accesstypes.User, _ ...accesstypes.Role) error {
	return nil
}

func (d DisabledUserManagement) UserPermissions(_ context.Context, _ accesstypes.User, _ ...accesstypes.Domain) (accesstypes.UserPermissionCollection, error) {
	return make(accesstypes.UserPermissionCollection), nil
}
