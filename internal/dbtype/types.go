// Package dbtype contains types used by the database driver packages for session storage.
package dbtype

import (
	"context"
	"time"

	"github.com/cccteam/ccc"
	"github.com/cccteam/ccc/resource"
	"github.com/cccteam/ccc/securehash"
	"github.com/cccteam/session/sessioninfo"
)

// CustomSessionDataResolver defines a function that resolves custom session data inside a txn.
// Implementations receive a read-only view of the txn so reads are consistent with the session insert happening in the txn.
type CustomSessionDataResolver func(ctx context.Context, txn resource.ReadOnlyTransaction) ([]*sessioninfo.CustomData, error)

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

// CustomSessionDataConfig holds configuration for a separate custom session data table.
type CustomSessionDataConfig struct {
	// TableName is the name of the custom session data table.
	TableName string
	// Columns is the list of column names to read from the custom table.
	Columns []string
}

// IsReservedCustomColumn checks if a given column name is reserved and therefore cannot be used as a custom session data column name.
func IsReservedCustomColumn(name string) bool {
	_, reserved := reservedCustomColumnNames()[name]

	return reserved
}

func reservedCustomColumnNames() map[string]struct{} {
	return map[string]struct{}{
		"SessionId": {},
	}
}
