package dbtype

import (
	"time"

	"github.com/cccteam/ccc"
	"github.com/cccteam/session/sessioninfo"
)

// PendingSignIn is a row of the pending sign-ins table: a sign-in that waits for a
// password confirmation or the application's MFA step, with everything it carried. The
// browser's pending cookie holds an opaque token; TokenHash is that token's SHA-256. The
// row is live until ExpiresAt, or until it is consumed once (ConsumedAt).
type PendingSignIn struct {
	ID        ccc.UUID
	TokenHash []byte
	// Step is why the sign-in waits.
	Step sessioninfo.PendingReason
	// Registration names the external registration the identity came through; empty
	// for a password identity.
	Registration string
	// Identity is the verified identity, with its claims.
	Identity sessioninfo.Identity
	// UserID and Username name the user the sign-in waits on.
	UserID   ccc.NullUUID
	Username string
	// Tenant is the tenant key for the link to be made.
	Tenant string
	// Events are the steps so far, the sign-in first.
	Events []sessioninfo.AuthEvent
	// RoleNames are the role names the method asserted at sign-in; nil when the method
	// synchronizes no roles.
	RoleNames []string
	// Factors are the methods the sign-in policy accepts for the MFA step; none means
	// any.
	Factors []sessioninfo.AuthMethod
	// ReturnURL is the sanitized path the sign-in returns to; empty for a password
	// sign-in.
	ReturnURL  string
	CreatedAt  time.Time
	ExpiresAt  time.Time
	ConsumedAt *time.Time
}

// MethodNames renders methods as the strings a database array holds; nil stays nil.
func MethodNames(methods []sessioninfo.AuthMethod) []string {
	if methods == nil {
		return nil
	}
	names := make([]string, len(methods))
	for i, m := range methods {
		names[i] = string(m)
	}

	return names
}

// AuthMethods reverses MethodNames.
func AuthMethods(names []string) []sessioninfo.AuthMethod {
	if names == nil {
		return nil
	}
	methods := make([]sessioninfo.AuthMethod, len(names))
	for i, n := range names {
		methods[i] = sessioninfo.AuthMethod(n)
	}

	return methods
}
