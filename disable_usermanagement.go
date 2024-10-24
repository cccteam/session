package session

import (
	"context"

	"github.com/cccteam/ccc/accesstypes"
)

type DisabledUserManager struct{}

func DisableUserManagement() DisabledUserManager {
	return DisabledUserManager{}
}

func (d DisabledUserManager) Domains(_ context.Context) ([]accesstypes.Domain, error) {
	return []accesstypes.Domain{accesstypes.GlobalDomain}, nil
}

func (d DisabledUserManager) UserRoles(_ context.Context, _ accesstypes.User, _ ...accesstypes.Domain) (accesstypes.RoleCollection, error) {
	return make(accesstypes.RoleCollection), nil
}

func (d DisabledUserManager) RoleExists(_ context.Context, _ accesstypes.Domain, _ accesstypes.Role) bool {
	return true
}

func (d DisabledUserManager) AddUserRoles(_ context.Context, _ accesstypes.Domain, _ accesstypes.User, _ ...accesstypes.Role) error {
	return nil
}

func (d DisabledUserManager) DeleteUserRoles(_ context.Context, _ accesstypes.Domain, _ accesstypes.User, _ ...accesstypes.Role) error {
	return nil
}

func (d DisabledUserManager) UserPermissions(_ context.Context, _ accesstypes.User, _ ...accesstypes.Domain) (accesstypes.UserPermissionCollection, error) {
	return make(accesstypes.UserPermissionCollection), nil
}
