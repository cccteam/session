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

// SessionData pairs a SessionInfo with optional custom session data.
// This is stored in the request context internally; consumers should use FromCtx/FromRequest to get the SessionInfo and
// CustomDataFromCtx[T]/CustomDataFromRequest[T] to get the strongly typed custom data.
type SessionData struct {
	*SessionInfo
	CustomData any
}

// UserInfo struct contains information about a user
type UserInfo struct {
	ID       ccc.UUID `spanner:"Id"           db:"Id"`
	Username string   `spanner:"Username"     db:"Username"`
	Disabled bool     `spanner:"Disabled"     db:"Disabled"`
}

// CustomData represents a single custom column value to be stored in the custom session data table.
type CustomData struct {
	ColumnName string
	Value      any
}
