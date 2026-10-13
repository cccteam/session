// Package e2e drives the library the way an application does: a public session type
// on a chi router, real cookies over an HTTPS test server, and a real database behind
// the public sessionstorage constructors, PostgreSQL and Spanner both. Every other test
// package isolates itself from the layer below with a double; these scenarios cross the
// seams those doubles hide, one security invariant per scenario.
package e2e

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"os"
	"testing"

	dbinitiator "github.com/cccteam/db-initiator"
)

var (
	postgresContainer *dbinitiator.PostgresContainer
	spannerContainer  *dbinitiator.SpannerContainer
)

func TestMain(m *testing.M) {
	ctx := context.Background()
	pg, err := dbinitiator.NewPostgresContainer(ctx, "latest")
	if err != nil {
		fmt.Println(err)
		os.Exit(2)
	}
	postgresContainer = pg
	sp, err := dbinitiator.NewSpannerContainer(ctx, "1.5.56")
	if err != nil {
		fmt.Println(err)
		pg.Close()
		_ = pg.Terminate(ctx)
		os.Exit(2)
	}
	spannerContainer = sp

	exitCode := m.Run()

	pg.Close()
	if err := pg.Terminate(ctx); err != nil {
		fmt.Println(err)
	}
	if err := sp.Terminate(ctx); err != nil {
		fmt.Println(err)
	}
	if err := sp.Close(); err != nil {
		fmt.Println(err)
	}

	os.Exit(exitCode)
}

// The shipped migrations, not a fixture copy: the suite runs against the schema an
// application deploys. The testdata sources add the application's own tables.
const (
	postgresSessions      = "file://../../schema/postgresql/migrations"
	postgresImpersonation = "file://../../schema/postgresql/impersonation/migrations"
	postgresAuth          = "file://../../schema/postgresql/auth/migrations"
	postgresAppTables     = "file://testdata/postgresql"
	spannerSessions       = "file://../../schema/spanner/migrations"
	spannerImpersonation  = "file://../../schema/spanner/impersonation/migrations"
	spannerAuth           = "file://../../schema/spanner/auth/migrations"
	spannerAppTables      = "file://testdata/spanner"
)

// databaseName is a short, unique database name for the test. Scenario names are long
// sentences; a digest keeps the name within what either database accepts.
func databaseName(t *testing.T) string {
	t.Helper()

	sum := sha256.Sum256([]byte(t.Name()))

	return "e2e" + hex.EncodeToString(sum[:6])
}

// preparePostgres creates a PostgreSQL database for the test and applies the migration
// sources to it.
func preparePostgres(ctx context.Context, t *testing.T, sources ...string) *dbinitiator.PostgresDatabase {
	t.Helper()

	db, err := postgresContainer.CreateDatabase(ctx, databaseName(t))
	if err != nil {
		t.Fatalf("PostgresContainer.CreateDatabase() error = %v", err)
	}
	t.Cleanup(db.Close)

	if err := db.MigrateUp(sources...); err != nil {
		t.Fatalf("PostgresDatabase.MigrateUp() error = %v", err)
	}

	return db
}

// prepareSpanner creates a Spanner database for the test and applies the migration
// sources to it.
func prepareSpanner(ctx context.Context, t *testing.T, sources ...string) *dbinitiator.SpannerDB {
	t.Helper()

	db, err := spannerContainer.CreateDatabase(ctx, databaseName(t))
	if err != nil {
		t.Fatalf("SpannerContainer.CreateDatabase() error = %v", err)
	}
	t.Cleanup(func() {
		if err := db.DropDatabase(context.Background()); err != nil {
			t.Error(err)
		}
		if err := db.Close(); err != nil {
			t.Error(err)
		}
	})

	if err := db.MigrateUp(sources...); err != nil {
		t.Fatalf("SpannerDB.MigrateUp() error = %v", err)
	}

	return db
}
