// Package sessioninfo handles session information.
package sessioninfo

import (
	"time"

	"github.com/cccteam/ccc"
	"github.com/cccteam/ccc/accesstypes"
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
//
// Principal is the authorization subject a configured principal resolver chose for
// this request (session.WithPrincipalResolver), set at validation and never stored. It
// is the zero Principal when no resolver is configured or the resolver kept the
// default, in which case PrincipalFromCtx derives the subject from the impersonation
// record or the username.
type SessionData struct {
	*SessionInfo
	CustomData    any
	Impersonation *Impersonation
	Principal     accesstypes.Principal
	// UserID is the user (SessionUsers.Id) the session belongs to. For a
	// user-principal impersonation it is the impersonated user. It is null for the
	// legacy session types, preauth sessions, and role-principal impersonations.
	UserID ccc.NullUUID
	// AuthenticatedAt is when the session's most recent authentication step completed.
	AuthenticatedAt time.Time
	// ProviderSessionID is the identity provider's session id the sign-in carried; ""
	// when the method has none or the session is not an Auth session.
	// ProviderSessionIssuer is the issuer that id belongs to: a provider's session id is
	// unique only within its issuer, so a provider-initiated logout names both.
	ProviderSessionID     string
	ProviderSessionIssuer string
	// AuthEvents lists how the session was authenticated, oldest first. It is empty
	// unless the storage is configured with an auth events table.
	AuthEvents []AuthEvent
}

// EstablishedBy returns how the session was established: its first auth event, the
// method and connection of the sign-in (a password; the Entra tenant id, the Google
// Workspace or the WorkOS connection of a sign-in through a directory; the actor of an
// impersonation; the application's own first event of a session it started itself).
// It is what a tenant's declaration admits or refuses when the session reaches the
// tenant (signin.TenantDeclaration.Admits). ok is false for a session that records no
// events: a legacy or preauth session, or a storage without an auth events table.
func (s *SessionData) EstablishedBy() (event AuthEvent, ok bool) {
	if s == nil || len(s.AuthEvents) == 0 {
		return AuthEvent{}, false
	}

	return s.AuthEvents[0], true
}

// UserInfo struct contains information about a user
type UserInfo struct {
	ID       ccc.UUID `spanner:"Id"           db:"Id"`
	Username string   `spanner:"Username"     db:"Username"`
	Disabled bool     `spanner:"Disabled"     db:"Disabled"`
	// PasswordChangeRequired is set while the user must change a password an operator
	// set before anything else is served; Auth sessions only.
	PasswordChangeRequired bool `spanner:"PasswordChangeRequired" db:"PasswordChangeRequired"`
	// Email is the user's email address, nil for none, and EmailVerifiedAt when the
	// person proved they read it, nil while it is unverified; Auth sessions only. An
	// unverified address is trusted for nothing.
	Email           *string    `spanner:"Email"           db:"Email"`
	EmailVerifiedAt *time.Time `spanner:"EmailVerifiedAt" db:"EmailVerifiedAt"`
}

// EmailVerified reports whether the user holds a verified address.
func (u *UserInfo) EmailVerified() bool {
	return u != nil && u.Email != nil && u.EmailVerifiedAt != nil
}
