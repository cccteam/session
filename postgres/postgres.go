// Package postgres implements the session storage driver for PostgreSQL.
package postgres

const name = "github.com/cccteam/session/postgres"

// SessionStorageDriver represents the session storage implementation for PostgreSQL.
type SessionStorageDriver struct {
	conn Queryer
}

// NewSessionStorageDriver creates a new SessionStorageDriver
func NewSessionStorageDriver(conn Queryer) *SessionStorageDriver {
	return &SessionStorageDriver{
		conn: conn,
	}
}
