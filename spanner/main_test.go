package spanner

import (
	"context"
	"fmt"
	"log"
	"os"
	"testing"

	"cloud.google.com/go/spanner"
	initiator "github.com/cccteam/db-initiator"
	"github.com/go-playground/errors/v5"
)

var container *initiator.SpannerContainer

func TestMain(m *testing.M) {
	ctx := context.Background()

	c, err := initiator.NewSpannerContainer(ctx, "latest")
	if err != nil {
		log.Fatal(err)
	}
	container = c

	exitCode := m.Run()

	if err := c.Terminate(ctx); err != nil {
		fmt.Println(err)
	}

	if err := c.Close(); err != nil {
		fmt.Println(err)
	}

	os.Exit(exitCode)
}

func prepareDatabase(ctx context.Context, t *testing.T, sourceURL ...string) (*initiator.SpannerDB, error) {
	db, err := container.CreateDatabase(ctx, t.Name())
	if err != nil {
		return nil, errors.Wrapf(err, "initiator.SpannerContainer.CreateTestDatabase()")
	}
	t.Cleanup(func() {
		if err := db.DropDatabase(context.Background()); err != nil {
			panic(err)
		}
		if err := db.Close(); err != nil {
			panic(err)
		}
	})

	if err := db.MigrateUp(sourceURL...); err != nil {
		return nil, errors.Wrapf(err, "initiator.SpannerContainer.FullMigrate()")
	}

	return db, nil
}

// runAssertions executes a series of assertions. Each assertion is represented by a SQL query
// that must return a single row with a single boolean column. The query's result must be true
// for the assertion to pass.
func runAssertions(ctx context.Context, t *testing.T, db *spanner.Client, assertions []string) {
	t.Helper()

	for i, query := range assertions {
		var isTrue bool
		var rows int

		err := db.Single().
			Query(ctx, spanner.NewStatement(query)).
			Do(func(row *spanner.Row) error {
				if err := row.Column(0, &isTrue); err != nil {
					return errors.Wrapf(err, "spanner.Row.Column()")
				}
				rows++

				return nil
			})
		if err != nil {
			t.Errorf("spanner.RowIterator.Do(): Assertion %d for test %q failed. %v", i+1, t.Name(), err)

			continue
		}
		if rows != 1 {
			t.Errorf("Assertion %d for test %q returned %d rows, expected 1", i+1, t.Name(), rows)

			continue
		}
		if !isTrue {
			t.Errorf("Assertion %d for test %q failed", i+1, t.Name())
		}
	}
}
