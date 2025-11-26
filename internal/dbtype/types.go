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
