// Package dbtype contains types used by the database driver packages for session storage.
package dbtype

import (
	"time"

	"github.com/cccteam/ccc"
	"github.com/cccteam/ccc/securehash"
	"github.com/cccteam/session/sessioninfo"
)

// Session defines the structure for storing session data in the database.
type Session struct {
	ID         ccc.UUID  `spanner:"Id"        db:"Id"`
	Username   string    `spanner:"Username"  db:"Username"`
	CreatedAt  time.Time `spanner:"CreatedAt" db:"CreatedAt"`
	UpdatedAt  time.Time `spanner:"UpdatedAt" db:"UpdatedAt"`
	Expired    bool      `spanner:"Expired"   db:"Expired"`
	CustomData map[string]any
}

// InsertSession defines the structure for inserting new session data into the database.
type InsertSession struct {
	Username  string    `spanner:"Username"`
	CreatedAt time.Time `spanner:"CreatedAt"`
	UpdatedAt time.Time `spanner:"UpdatedAt"`
	Expired   bool      `spanner:"Expired"`
}

// InsertCustomSession defines the structure for inserting new session data with custom columns into the database.
type InsertCustomSession struct {
	InsertSession
	CustomData []sessioninfo.CustomData
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

// IsReservedColumnName checks if a given column name is reserved and therefore cannot be used as a custom session column name.
func IsReservedColumnName(name string) bool {
	_, reserved := reservedColumnNames()[name]

	return reserved
}

func reservedColumnNames() map[string]struct{} {
	return map[string]struct{}{
		"Id":        {},
		"Username":  {},
		"CreatedAt": {},
		"UpdatedAt": {},
		"Expired":   {},
	}
}
