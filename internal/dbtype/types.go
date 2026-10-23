// Package dbtype contains types used by the database driver packages for session storage.
package dbtype

import (
	"strings"
	"time"

	"github.com/cccteam/ccc"
	"github.com/cccteam/ccc/securehash"
	"github.com/cccteam/httpio"
	"github.com/cccteam/session/sessioninfo"
)

// Session defines the structure for storing session data in the database.
type Session struct {
	ID        ccc.UUID  `spanner:"Id"        db:"Id"`
	Username  string    `spanner:"Username"  db:"Username"`
	CreatedAt time.Time `spanner:"CreatedAt" db:"CreatedAt"`
	UpdatedAt time.Time `spanner:"UpdatedAt" db:"UpdatedAt"`
	Expired   bool      `spanner:"Expired"   db:"Expired"`
}

// SessionData pairs a Session with optional custom session data and, for an
// impersonated session, its impersonation record (nil otherwise). UserID and
// AuthenticatedAt are set only when the user columns are enabled, and AuthEvents
// only when there is an auth events table.
type SessionData struct {
	*Session
	CustomData      any
	Impersonation   *Impersonation
	UserID          ccc.NullUUID
	AuthenticatedAt *time.Time
	// ProviderSessionID is the provider's session id the sign-in carried, "" when none,
	// and ProviderSessionIssuer the issuer it belongs to.
	ProviderSessionID     string
	ProviderSessionIssuer string
	AuthEvents            []sessioninfo.AuthEvent
}

// InsertSession is the caller-supplied part of a new session row. The driver writes
// CreatedAt and UpdatedAt with the database's time at commit, never the application's.
type InsertSession struct {
	Username string `spanner:"Username"`
	Expired  bool   `spanner:"Expired"`
}

// InsertOIDCSession defines the structure for inserting new OIDC session data into the database.
type InsertOIDCSession struct {
	OidcSID string `spanner:"OidcSid"`
	InsertSession
}

// SessionUser is a person authorized to access the application. PasswordChangeRequired
// marks a user whose password an operator set (a new user's first password, a reset):
// the user changes it before anything else. CreatedAt is the database's time at the
// insert and LastSignInAt its time at the user's latest sign-in, nil before the first.
// Email is the user's email address, nil for none, and EmailVerifiedAt the database's
// time at which the person proved they read it, nil while it is unverified; both are
// nil on a store without the auth schema. An unverified address is trusted for
// nothing: it may be sent a link, and that is all.
type SessionUser struct {
	ID                     ccc.UUID         `spanner:"Id"                     db:"Id"`
	Username               string           `spanner:"Username"               db:"Username"`
	PasswordHash           *securehash.Hash `spanner:"PasswordHash"           db:"PasswordHash"`
	Disabled               bool             `spanner:"Disabled"               db:"Disabled"`
	PasswordChangeRequired bool             `spanner:"PasswordChangeRequired" db:"PasswordChangeRequired"`
	CreatedAt              time.Time        `spanner:"CreatedAt"              db:"CreatedAt"`
	LastSignInAt           *time.Time       `spanner:"LastSignInAt"           db:"LastSignInAt"`
	Email                  *string          `spanner:"Email"                  db:"Email"`
	EmailVerifiedAt        *time.Time       `spanner:"EmailVerifiedAt"        db:"EmailVerifiedAt"`
}

// EmailVerified reports whether the user holds a verified address.
func (u *SessionUser) EmailVerified() bool {
	return u != nil && u.Email != nil && u.EmailVerifiedAt != nil
}

// InsertSessionUser is the caller-supplied part of a new user row. The driver writes
// CreatedAt with the database's time at commit. Email, nil for none, is the user's
// address, written unverified unless EmailVerified says the person has proven it (a
// sign-up or an invitation the person completed by mail), in which case the driver
// stamps EmailVerifiedAt with the commit time. On a store whose usernames are the
// addresses (UsernameIsEmail) the address is the username and Email must be nil or
// match it.
type InsertSessionUser struct {
	Username               string           `spanner:"Username"               db:"Username"`
	PasswordHash           *securehash.Hash `spanner:"PasswordHash"           db:"PasswordHash"`
	Disabled               bool             `spanner:"Disabled"               db:"Disabled"`
	PasswordChangeRequired bool             `spanner:"PasswordChangeRequired" db:"PasswordChangeRequired"`
	Email                  *string          `spanner:"Email"                  db:"Email"`
	EmailVerified          bool             `spanner:"-"                      db:"-"`
}

// OIDCUser is a library-managed durable user record for OIDC logins, keyed by the
// immutable (Tid, Oid) claim pair with a surrogate UUID primary key. Username is a
// mutable attribute, updated in place at login when the IdP reports a new value.
type OIDCUser struct {
	ID        ccc.UUID  `spanner:"Id"        db:"Id"`
	Tid       string    `spanner:"Tid"       db:"Tid"`
	Oid       string    `spanner:"Oid"       db:"Oid"`
	Username  string    `spanner:"Username"  db:"Username"`
	CreatedAt time.Time `spanner:"CreatedAt" db:"CreatedAt"`
	UpdatedAt time.Time `spanner:"UpdatedAt" db:"UpdatedAt"`
}

// SessionIDColumn is the primary-key column of the custom session data table, referencing the session table's primary key.
const SessionIDColumn = "SessionId"

// UserIDColumn is the primary-key column of the custom user data table, referencing the
// user table's primary key (SessionUsers.Id or OIDCUsers.Id).
const UserIDColumn = "UserId"

// IsReservedCustomColumn checks if a given column name is reserved and therefore cannot be used as a custom session data column name.
func IsReservedCustomColumn(name string) bool {
	return name == SessionIDColumn
}

// IsReservedCustomUserColumn checks if a given column name is reserved and therefore cannot be used as a custom user data column name.
func IsReservedCustomUserColumn(name string) bool {
	return name == UserIDColumn
}

// ValidateInsertUser refuses a new user row the store cannot write: on a store whose
// usernames are the addresses (usernameIsEmail), an Email that is not the username,
// since the database derives the address from the username; and a verified mark
// without an address.
func ValidateInsertUser(user *InsertSessionUser, usernameIsEmail bool) error {
	switch {
	case user.Email != nil && strings.TrimSpace(*user.Email) == "":
		return httpio.NewBadRequestMessage("an email address, when given, is not empty")
	case usernameIsEmail && user.Email != nil && !strings.EqualFold(strings.TrimSpace(*user.Email), strings.TrimSpace(user.Username)):
		return httpio.NewBadRequestMessagef("the username is the user's email address: %q is not the username %q", *user.Email, user.Username)
	case user.EmailVerified && user.Email == nil && !usernameIsEmail:
		return httpio.NewBadRequestMessage("a verified mark needs an address")
	}

	return nil
}
