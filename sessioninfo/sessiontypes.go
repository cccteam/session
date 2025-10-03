// Package sessioninfo handles session information.
package sessioninfo

import (
	"time"

	"github.com/cccteam/ccc"
)

// SessionInfo struct contains information about a session
type SessionInfo struct {
	ID        ccc.UUID
	Username  string
	CreatedAt time.Time
	UpdatedAt time.Time
	Expired   bool
}
