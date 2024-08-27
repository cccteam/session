package postgresql

import (
	"context"
	"fmt"
	"os"
	"testing"

	dbinitiator "github.com/cccteam/db-initiator"
	"github.com/go-playground/errors/v5"
)

var container *dbinitiator.PostgresContainer

// TestMain is a wrapper for the test suite. It creates a new PostgresContainer and runs the test suite.
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

// prepareDatabase creates a new database and runs migrations given a variadic param of sourceURL(s).
func prepareDatabase(ctx context.Context, t *testing.T, sourceURL ...string) (*dbinitiator.PostgresDatabase, error) {
	db, err := container.CreateDatabase(ctx, t.Name())
	if err != nil {
		return nil, errors.Wrapf(err, "postgrescontainer.PostgresContainer.CreateDatabase()")
	}

	if err := db.MigrateUp(sourceURL...); err != nil {
		return nil, errors.Wrapf(err, "postgrescontainer.DB.MigrateUp()")
	}

	t.Cleanup(db.Close)

	return db, nil
}

// runAssertions executes a series of provided assertions. Each assertion is represented by a SQL query
// that must return a boolean value. The query's result must be true for the assertion to pass.
func runAssertions(ctx context.Context, t *testing.T, q Queryer, assertions []string) {
	t.Helper()

	for i, query := range assertions {
		var isTrue bool
		if err := q.QueryRow(ctx, query).Scan(&isTrue); err != nil {
			t.Errorf("pgx.Row.Scan(): Assertion %d for test %q failed. %v", i+1, t.Name(), err)

			continue
		}
		if !isTrue {
			t.Errorf("Assertion %d for test %q failed", i+1, t.Name())
		}
	}
}
