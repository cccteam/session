package spanner

import (
	"fmt"
	"time"

	"github.com/cccteam/ccc"
)

// ConnectionSettings is used to configure the spanner package
type ConnectionSettings struct {
	// ProjectID is the project the Spanner database is in
	ProjectID string

	// InstanceID is the Spanner Instance ID
	InstanceID string

	// DatabaseName is the Spanner Database Name
	DatabaseName string
}

func (c *ConnectionSettings) DBName() string {
	return fmt.Sprintf("projects/%s/instances/%s/databases/%s", c.ProjectID, c.InstanceID, c.DatabaseName)
}

type Session struct {
	ID        ccc.UUID  `spanner:"Id"`
	OidcSID   string    `spanner:"OidcSid"`
	Username  string    `spanner:"Username"`
	CreatedAt time.Time `spanner:"CreatedAt"`
	UpdatedAt time.Time `spanner:"UpdatedAt"`
	Expired   bool      `spanner:"Expired"`
}

type InsertSession struct {
	OidcSID   string    `spanner:"OidcSid"`
	Username  string    `spanner:"Username"`
	CreatedAt time.Time `spanner:"CreatedAt"`
	UpdatedAt time.Time `spanner:"UpdatedAt"`
	Expired   bool      `spanner:"Expired"`
}
