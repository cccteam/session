// Package dbtype contains types used by the database driver packages for session storage.
package dbtype

import (
	"context"
	"time"

	"cloud.google.com/go/spanner"
	"github.com/cccteam/ccc"
	"github.com/cccteam/ccc/securehash"
	"github.com/cccteam/session/sessioninfo"
	"github.com/go-playground/errors/v5"
	"github.com/jackc/pgx/v5"
)

// NewSessionCustomDataResolver defines a function that resolves custom session data inside a txn.
// Implementations receive a read-only view of the txn so reads are consistent with the session insert happening in the txn.
type NewSessionCustomDataResolver func(ctx context.Context, txn ReadWriteTransaction) ([]*sessioninfo.CustomData, error)

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

// CustomSessionDataConfig holds configuration for a separate custom session data table.
type CustomSessionDataConfig struct {
	// TableName is the name of the custom session data table.
	TableName string
	// Columns is the list of column names to read from the custom table.
	Columns []string
	// Decoder converts the raw map[string]any from the database into a strongly typed value.
	// When nil, the raw map[string]any is stored directly.
	Decoder func(rawCustomData map[string]any) (any, error)
}

// DecodeRawData decodes a raw column map into the final custom data value.
// If a Decoder is configured it is used; otherwise the raw map is returned as-is.
func (c *CustomSessionDataConfig) DecodeRawData(rawCustomData map[string]any) (any, error) {
	if c.Decoder != nil {
		decoded, err := c.Decoder(rawCustomData)
		if err != nil {
			return nil, errors.Wrap(err, "CustomSessionDataConfig.Decoder()")
		}

		return decoded, nil
	}

	return rawCustomData, nil
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

// ReadWriteTransaction is an interface that abstracts over the specific read-write transaction types of supported databases (e.g. Spanner, Postgres).
type ReadWriteTransaction interface {
	SpannerReadWriteTransaction() *spanner.ReadWriteTransaction
	PostgresReadWriteTransaction() pgx.Tx
}
