package spanner

import (
	"fmt"
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
