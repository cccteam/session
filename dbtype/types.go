// Package dbtype contains types used by the database driver packages for session storage.
package dbtype

import (
	"time"

	"github.com/cccteam/ccc"
)

// Session defines the structure for storing session data in the database.
type Session struct {
	ID        ccc.UUID  `spanner:"Id"        db:"Id"`
	Username  string    `spanner:"Username"  db:"Username"`
	CreatedAt time.Time `spanner:"CreatedAt" db:"CreatedAt"`
	UpdatedAt time.Time `spanner:"UpdatedAt" db:"UpdatedAt"`
	Expired   bool      `spanner:"Expired"   db:"Expired"`
}

// SessionOIDC defines the structure for storing OIDC session data in the database.
type SessionOIDC struct {
	OidcSID string `spanner:"OidcSid" db:"OidcSid"`
	Session
}

// InsertSession defines the structure for inserting new session data into the database.
type InsertSession struct {
	Username  string    `spanner:"Username"  db:"Username"`
	CreatedAt time.Time `spanner:"CreatedAt" db:"CreatedAt"`
	UpdatedAt time.Time `spanner:"UpdatedAt" db:"UpdatedAt"`
	Expired   bool      `spanner:"Expired"   db:"Expired"`
}

// InsertSessionOIDC defines the structure for inserting new OIDC session data into the database.
type InsertSessionOIDC struct {
	OidcSID string `spanner:"OidcSid" db:"OidcSid"`
	InsertSession
}
