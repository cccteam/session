// sessiontypes package contains the shared types for the session package implementations.
package sessiontypes

import (
	"time"

	"github.com/cccteam/access"
	"github.com/cccteam/ccc"
)

// SessionInfo struct contains information about a session
type SessionInfo struct {
	ID          ccc.UUID
	Username    string
	CreatedAt   time.Time
	UpdatedAt   time.Time
	Expired     bool
	Permissions map[access.Domain][]access.Permission
}
