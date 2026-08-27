// Package dbtype contains types used by the database driver packages for session storage.
package dbtype

import (
	"time"

	"github.com/cccteam/ccc"
	"github.com/cccteam/ccc/securehash"
)

// Session defines the structure for storing session data in the database.
type Session struct {
	ID        ccc.UUID  `spanner:"Id"        db:"Id"`
	Username  string    `spanner:"Username"  db:"Username"`
	CreatedAt time.Time `spanner:"CreatedAt" db:"CreatedAt"`
	UpdatedAt time.Time `spanner:"UpdatedAt" db:"UpdatedAt"`
	Expired   bool      `spanner:"Expired"   db:"Expired"`
}

// SessionData pairs a Session with optional custom session data.
type SessionData struct {
	*Session
	CustomData any
}

// InsertSession defines the structure for inserting new session data into the database.
type InsertSession struct {
	Username  string    `spanner:"Username"`
	CreatedAt time.Time `spanner:"CreatedAt"`
	UpdatedAt time.Time `spanner:"UpdatedAt"`
	Expired   bool      `spanner:"Expired"`
}

// InsertOIDCSession defines the structure for inserting new OIDC session data into the database.
type InsertOIDCSession struct {
	OidcSID string `spanner:"OidcSid"`
	InsertSession
}

// SessionUser is a person authorized to access the application
type SessionUser struct {
	ID           ccc.UUID         `spanner:"Id"           db:"Id"`
	Username     string           `spanner:"Username"     db:"Username"`
	PasswordHash *securehash.Hash `spanner:"PasswordHash" db:"PasswordHash"`
	Disabled     bool             `spanner:"Disabled"     db:"Disabled"`
}

// InsertSessionUser defines the structure for inserting new SessionUser into the database
type InsertSessionUser struct {
	Username     string           `spanner:"Username"     db:"Username"`
	PasswordHash *securehash.Hash `spanner:"PasswordHash" db:"PasswordHash"`
	Disabled     bool             `spanner:"Disabled"     db:"Disabled"`
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

// GoogleOIDCUser is a library-managed durable user record for Google OIDC logins, keyed
// by the immutable, globally unique Sub claim with a surrogate UUID primary key. Hd and
// Username are mutable attributes, updated in place at login when the IdP reports new
// values.
type GoogleOIDCUser struct {
	ID        ccc.UUID  `spanner:"Id"        db:"Id"`
	Sub       string    `spanner:"Sub"       db:"Sub"`
	Hd        string    `spanner:"Hd"        db:"Hd"`
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
