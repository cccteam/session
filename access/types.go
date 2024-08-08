package access

import (
	"time"
)

// PermissionsListFunc is a function that provides the list of app permissions for the users client
type PermissionsListFunc func() []Permission

// UserAccess struct contains the name and role mappings for a user
type UserAccess struct {
	Name        string
	Roles       map[Domain][]Role
	Permissions map[Domain][]Permission
}

// SessionInfo struct contains information about a session
type SessionInfo struct {
	ID          string
	Username    string
	CreatedAt   time.Time
	UpdatedAt   time.Time
	Expired     bool
	Permissions map[Domain][]Permission
}
