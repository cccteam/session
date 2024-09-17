// sessioninfo package handles session information.
package sessioninfo

import (
	"time"

	"github.com/cccteam/ccc"
	"github.com/cccteam/ccc/accesstypes"
)

// SessionInfo struct contains information about a session
type SessionInfo struct {
	ID          ccc.UUID
	Username    string
	CreatedAt   time.Time
	UpdatedAt   time.Time
	Expired     bool
	Permissions map[accesstypes.Domain][]accesstypes.Permission
}
