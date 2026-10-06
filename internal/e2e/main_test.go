// Package e2e drives the library the way an application does: a public session type
// on a chi router, real cookies over an HTTPS test server, and a real PostgreSQL
// container behind the public sessionstorage constructors. Every other test package
// isolates itself from the layer below with a double; these scenarios cross the seams
// those doubles hide, one security invariant per scenario.
package e2e

import (
	"context"
	"crypto/sha1" //nolint:gosec // a short, stable database name, not a security primitive
	"encoding/hex"
	"fmt"
	"os"
	"testing"

	dbinitiator "github.com/cccteam/db-initiator"
)

var container *dbinitiator.PostgresContainer

func TestMain(m *testing.M) {
	ctx := context.Background()
	c, err := dbinitiator.NewPostgresContainer(ctx, "latest")
	if err != nil {
		fmt.Println(err)
		os.Exit(2)
	}
	container = c

	exitCode := m.Run()

	c.Close()
	if err := c.Terminate(ctx); err != nil {
		fmt.Println(err)
	}

	os.Exit(exitCode)
}

// The shipped migrations, not a fixture copy: the suite runs against the schema an
// application deploys.
const (
	sessionsMigrations      = "file://../../schema/postgresql/migrations"
	impersonationMigrations = "file://../../schema/postgresql/impersonation/migrations"
)

// prepareDatabase creates a database for the test and applies the shipped sessions and
// impersonation migrations to it.
func prepareDatabase(ctx context.Context, t *testing.T) *dbinitiator.PostgresDatabase {
	t.Helper()

	// Scenario names are long sentences; a digest keeps the database name short and
	// unique regardless of what the container does to invalid characters.
	sum := sha1.Sum([]byte(t.Name())) //nolint:gosec // see above
	db, err := container.CreateDatabase(ctx, "e2e_"+hex.EncodeToString(sum[:6]))
	if err != nil {
		t.Fatalf("PostgresContainer.CreateDatabase() error = %v", err)
	}
	t.Cleanup(db.Close)

	if err := db.MigrateUp(sessionsMigrations, impersonationMigrations); err != nil {
		t.Fatalf("PostgresDatabase.MigrateUp() error = %v", err)
	}

	return db
}
