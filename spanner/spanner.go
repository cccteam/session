// Package spanner provides the session storage driver for Spanner.
package spanner

import (
	"cloud.google.com/go/spanner"
)

const name = "github.com/AscendiumApps/ga-lite-app/spanner"

// SessionStorageDriver represents the session storage implementation for Spanner.
type SessionStorageDriver struct {
	spanner *spanner.Client
}

// NewSessionStorageDriver creates a new SessionStorageDriver
func NewSessionStorageDriver(client *spanner.Client) *SessionStorageDriver {
	return &SessionStorageDriver{
		spanner: client,
	}
}

// Close closes the spanner client
func (d *SessionStorageDriver) Close() {
	d.spanner.Close()
}
