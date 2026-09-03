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
//
// CustomData is nil when no custom session data configuration is attached to the
// storage. When one is attached, it holds a *T (the configuration's struct type); a
// session without a custom data row yields a zero-value *T.
//
// Impersonation is nil for a session that is not impersonated (including every
// session when the storage has no impersonation configuration); consumers read it
// through ImpersonationFromCtx, PrincipalFromCtx, ActorFromCtx and MaskFromCtx.
type SessionData struct {
	*SessionInfo
	CustomData    any
	Impersonation *Impersonation
}

// UserInfo struct contains information about a user
type UserInfo struct {
	ID       ccc.UUID `spanner:"Id"           db:"Id"`
	Username string   `spanner:"Username"     db:"Username"`
	Disabled bool     `spanner:"Disabled"     db:"Disabled"`
}
