package session

import (
	"context"

	"github.com/cccteam/ccc/accesstypes"
	"github.com/cccteam/session/internal/basesession"
)

// UserRoleManager defines an interface for managing user roles.
type UserRoleManager interface {
	Domains(ctx context.Context) ([]accesstypes.Domain, error)
	UserRoles(ctx context.Context, user accesstypes.User, domains ...accesstypes.Domain) (accesstypes.RoleCollection, error)
	RoleExists(ctx context.Context, domain accesstypes.Domain, role accesstypes.Role) bool
	AddUserRoles(ctx context.Context, domain accesstypes.Domain, user accesstypes.User, roles ...accesstypes.Role) error
	DeleteUserRoles(ctx context.Context, domain accesstypes.Domain, user accesstypes.User, roles ...accesstypes.Role) error
}

// LogHandler defines the handler signature required for handling logs.
type LogHandler = basesession.LogHandler
