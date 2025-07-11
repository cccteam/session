package roles

import (
	"context"

	"github.com/cccteam/ccc/accesstypes"
	"github.com/cccteam/logger"
	"github.com/cccteam/session/util" // Assuming util package is accessible
	"github.com/go-playground/errors/v5"
	"go.opentelemetry.io/otel"
)

const name = "github.com/cccteam/session/roles" // Define package name for tracer

// RoleAssigner defines the interface for assigning roles to a user.
type RoleAssigner interface {
	// AssignRoles ensures that the user is assigned to the specified roles ONLY.
	// It returns true if the user has at least one assigned role after the operation.
	AssignRoles(ctx context.Context, username accesstypes.User, roles []string) (hasRole bool, err error)
}

// UserManager defines the interface required by RoleAssignmentClient.
// This should be implemented by the existing UserManager.
type UserManager interface {
	Domains(ctx context.Context) ([]accesstypes.Domain, error)
	UserRoles(ctx context.Context, user accesstypes.User, domains ...accesstypes.Domain) (map[accesstypes.Domain][]accesstypes.Role, error)
	RoleExists(ctx context.Context, domain accesstypes.Domain, role accesstypes.Role) bool
	AddUserRoles(ctx context.Context, domain accesstypes.Domain, user accesstypes.User, roles ...accesstypes.Role) error
	DeleteUserRoles(ctx context.Context, domain accesstypes.Domain, user accesstypes.User, roles ...accesstypes.Role) error
}

// RoleAssignmentClient implements the RoleAssigner interface.
type RoleAssignmentClient struct {
	userManager UserManager
}

// NewRoleAssignmentClient creates a new RoleAssignmentClient.
func NewRoleAssignmentClient(userManager UserManager) *RoleAssignmentClient {
	return &RoleAssignmentClient{
		userManager: userManager,
	}
}

// AssignRoles ensures that the user is assigned to the specified roles ONLY
// returns true if the user has at least one assigned role (after the operation is complete)
func (c *RoleAssignmentClient) AssignRoles(ctx context.Context, username accesstypes.User, roles []string) (hasRole bool, err error) {
	ctx, span := otel.Tracer(name).Start(ctx, "RoleAssignmentClient.AssignRoles()")
	defer span.End()

	domains, err := c.userManager.Domains(ctx)
	if err != nil {
		return false, errors.Wrap(err, "UserManager.Domains()")
	}

	existingRoles, err := c.userManager.UserRoles(ctx, username, domains...)
	if err != nil {
		return false, errors.Wrap(err, "UserManager.UserRoles()")
	}

	for _, domain := range domains {
		var rolesToAssign []accesstypes.Role
		for _, r := range roles {
			if c.userManager.RoleExists(ctx, domain, accesstypes.Role(r)) {
				rolesToAssign = append(rolesToAssign, accesstypes.Role(r))
			}
		}

		newRoles := util.Exclude(rolesToAssign, existingRoles[domain])
		if len(newRoles) > 0 {
			if err := c.userManager.AddUserRoles(ctx, domain, username, newRoles...); err != nil {
				return false, errors.Wrap(err, "UserManager.AddUserRoles()")
			}
			logger.Ctx(ctx).Infof("User %s assigned to roles %v in domain %s", username, newRoles, domain)
		}

		removeRoles := util.Exclude(existingRoles[domain], rolesToAssign)
		if len(removeRoles) > 0 {
			if err := c.userManager.DeleteUserRoles(ctx, domain, username, removeRoles...); err != nil {
				return false, errors.Wrap(err, "UserManager.DeleteUserRole()")
			}
			logger.Ctx(ctx).Infof("User %s removed from roles %v in domain %s", username, removeRoles, domain)
		}

		hasRole = hasRole || len(rolesToAssign) > 0
	}

	return hasRole, nil
}
