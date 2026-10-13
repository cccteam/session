package session

import "github.com/cccteam/session/signin"

// UserRoleManager is the role store a role-synchronizing sign-in reconciles through.
// See signin.UserRoleManager.
type UserRoleManager = signin.UserRoleManager

// RoleSyncConfig is the required role-synchronization slot of the Microsoft Entra ID
// method (azure.Config.RoleSync) and of the legacy OIDCAzure. See signin.RoleSyncConfig.
type RoleSyncConfig = signin.RoleSyncConfig

// DisabledRoleSyncConfig is the type returned by DisableRoleSync. See
// signin.DisabledRoleSyncConfig.
type DisabledRoleSyncConfig = signin.DisabledRoleSyncConfig

// RoleSync enables directory-driven role synchronization. See signin.RoleSync.
func RoleSync(manager UserRoleManager) RoleSyncConfig {
	return signin.RoleSync(manager)
}

// DisableRoleSync disables role synchronization. See signin.DisableRoleSync.
func DisableRoleSync() DisabledRoleSyncConfig {
	return signin.DisableRoleSync()
}
