package dbtype

import (
	"time"

	"github.com/cccteam/ccc"
	"github.com/cccteam/session/sessioninfo"
	"github.com/go-playground/errors/v5"
)

// SessionIdentity is an identity link row. Its fields match
// sessionstorage.SessionIdentity, which converts from it.
type SessionIdentity struct {
	ID          ccc.UUID               `spanner:"Id"          db:"Id"`
	UserID      ccc.UUID               `spanner:"UserId"      db:"UserId"`
	Method      sessioninfo.AuthMethod `spanner:"Method"      db:"Method"`
	Connection  string                 `spanner:"Connection"  db:"Connection"`
	Subject     string                 `spanner:"Subject"     db:"Subject"`
	Tenant      *string                `spanner:"Tenant"      db:"Tenant"`
	EmailAtLink *string                `spanner:"EmailAtLink" db:"EmailAtLink"`
	CreatedAt   time.Time              `spanner:"CreatedAt"   db:"CreatedAt"`
	LastUsedAt  time.Time              `spanner:"LastUsedAt"  db:"LastUsedAt"`
}

// IsExternal reports whether identity is resolved through the identities table. A
// password identity names its user directly (req.UserID), and an impersonation
// identity belongs to the impersonation flow.
func IsExternal(identity *sessioninfo.Identity) bool {
	return identity != nil && identity.Method != sessioninfo.MethodPassword && identity.Method != sessioninfo.MethodImpersonation &&
		identity.Method != sessioninfo.MethodApplication
}

// ErrLastSignInMethod is returned when UnlinkIdentity would remove the last identity of
// a user that has no password; see sessionstorage for its documentation.
var ErrLastSignInMethod = errors.New("sessionstorage: the identity is the user's last means of sign-in")

// User is the part of a user row the sign-in flow decides on.
type User struct {
	Username    string
	HasPassword bool
	Disabled    bool
}

// SignInConflict is a driver's classification of the error a sign-in's transaction
// ended with.
type SignInConflict int

const (
	// NoSignInConflict is any other error.
	NoSignInConflict SignInConflict = iota
	// UsernameConflict is the users table refusing a provisioned user's username,
	// which another user already has.
	UsernameConflict
	// IdentityConflict is the identities table refusing a link of an identity that a
	// racing sign-in linked meanwhile.
	IdentityConflict
	// LockConflict is the database ending the transaction to break a deadlock or a
	// serialization failure between racing sign-ins; the sign-in runs once more.
	LockConflict
)
