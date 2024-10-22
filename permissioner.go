// Handles disabling permission functions for the session package
package session

import (
	"context"

	"github.com/cccteam/ccc/accesstypes"
)

// DisabledPermissioner is a struct that implements UserPermissioner with no-op methods.
type DisabledPermissioner struct{}

// UserPermissions is a no-op implementation that an empty UserPermissionCollection.
func (n DisabledPermissioner) UserPermissions(_ context.Context, _ accesstypes.User, _ ...accesstypes.Domain) (accesstypes.UserPermissionCollection, error) {
	return make(accesstypes.UserPermissionCollection), nil
}

// DisabledPermissions returns a DisabledPermissioner for use with the session package.
func DisabledPermissions() DisabledPermissioner {
	return DisabledPermissioner{}
}
