package access

import (
	"context"

	"session/dbx"
)

// UserManager is the interface for managing RBAC including the management of roles and permissions for users
type UserManager interface {
	// AddRoleUsers assigns a given role to a slice of users if the role exists
	AddRoleUsers(ctx context.Context, users []User, role Role, domain Domain) error

	// AddUserRoles assigns a list of roles to a user if the role exists
	AddUserRoles(ctx context.Context, user User, roles []Role, domain Domain) error

	// DeleteRoleUsers removes users from a given role
	DeleteRoleUsers(ctx context.Context, users []User, role Role, domain Domain) error

	// DeleteUserRole deletes the role assignment for a user in a specific domain.
	// Behavior is the same whether or not the role exists for the user.
	DeleteUserRole(ctx context.Context, username User, role Role, domain Domain) error

	// User returns a User by the given username with the roles that have been assigned.
	User(ctx context.Context, username User, domain ...Domain) (*UserAccess, error)

	// Users gets a list of users with their assigned roles
	Users(ctx context.Context, domain ...Domain) ([]*UserAccess, error)

	// UserRoles returns a map of the domain
	UserRoles(ctx context.Context, username User, domain ...Domain) (map[Domain][]Role, error)

	// UserPermissions returns a map of domains with a slice of permissions for each
	UserPermissions(ctx context.Context, username User, domain ...Domain) (map[Domain][]Permission, error)

	// AddRole adds a new role to a domain without assigning it to a user
	//
	// Note: due to the design of casbin, we must add a "noop" user to the role to enumerate it without permissions.
	AddRole(ctx context.Context, domain Domain, role Role) error

	// RoleExists determines if the given Role exists for Domain
	RoleExists(ctx context.Context, role Role, domain Domain) bool

	// Roles returns the full list of roles for a given domain
	Roles(ctx context.Context, domain Domain) ([]Role, error)

	// DeleteRole deletes a role from the system.
	// If there are users assigned, it will not be deleted.
	DeleteRole(ctx context.Context, role Role, domain Domain) (bool, error)

	// AddRolePermissions adds a list of permissions to a role in a given domain
	AddRolePermissions(ctx context.Context, permissions []Permission, role Role, domain Domain) error

	// DeleteRolePermissions removes a list of permissions to a role in a given domain
	DeleteRolePermissions(ctx context.Context, permissions []Permission, role Role, domain Domain) error

	// DeleteAllRolePermissions removes all permissions for a given role in a domain
	DeleteAllRolePermissions(ctx context.Context, role Role, domain Domain) error

	// RoleUsers returns the list of users attached to a role in a given domain
	RoleUsers(ctx context.Context, role Role, domain Domain) ([]User, error)

	// RolePermissions returns the list of permissions attached to a role in a given domain
	RolePermissions(ctx context.Context, role Role, domain Domain) ([]Permission, error)

	// Domains returns the full list of domains
	Domains(ctx context.Context) ([]Domain, error)

	// DomainExists returns true if the domain provided is a valid
	DomainExists(ctx context.Context, domain Domain) (bool, error)

	SessionManager
}

type SessionManager interface {
	DestroySession(ctx context.Context, sessionID string) error
	DestroySessionOIDC(ctx context.Context, oidcSID string) error
	NewSession(ctx context.Context, sessionInfo *dbx.SessionInfo) (*SessionInfo, error)
	Session(ctx context.Context, sessionID string) (*SessionInfo, error)
	UpdateSessionActivity(ctx context.Context, sessionID string) error
}
