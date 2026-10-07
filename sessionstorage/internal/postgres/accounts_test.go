package postgres

import (
	"context"
	"testing"

	"github.com/cccteam/ccc"
	"github.com/cccteam/session/sessionstorage/internal/drivertest"
)

// TestAccounts runs the shared accounts conformance suite against the PostgreSQL driver,
// on the shipped accounts migration.
func TestAccounts(t *testing.T) {
	t.Parallel()

	drivertest.RunAccounts(t, &drivertest.AccountsHarness{
		New:             newAccountsInstance,
		CountAuthEvents: countAuthEvents,
		DeleteSession:   deleteSession,
	})
}

// accountsSources maps an accounts suite schema to this package's migration sources.
func accountsSources(schema drivertest.AccountsSchema) []string {
	legacy := []string{"file://../../../schema/postgresql/migrations", "file://../../../schema/postgresql/impersonation/migrations"}
	switch schema {
	case drivertest.LegacySessions:
		return legacy
	case drivertest.Accounts:
		return append(legacy, "file://../../../schema/postgresql/accounts/migrations")
	default:
		panic("unknown schema")
	}
}

func newAccountsInstance(ctx context.Context, t *testing.T, schema drivertest.AccountsSchema, cfg drivertest.AccountsConfig) *drivertest.AccountsInstance {
	t.Helper()

	conn, err := prepareDatabase(ctx, t, accountsSources(schema)...)
	if err != nil {
		t.Fatalf("prepareDatabase() error = %v", err)
	}

	d := NewSessionStorageDriver(conn.Pool)
	if cfg.Accounts {
		d.EnableAccounts()
	}
	if cfg.AuthEvents {
		d.SetAuthEvents(&AuthEventsConfig{TableName: "SessionAuthEvents"})
	}
	if cfg.Impersonation {
		d.SetImpersonation(&ImpersonationConfig{TableName: "SessionImpersonations"})
	}

	return &drivertest.AccountsInstance{Driver: d, Raw: conn.Pool}
}

func countAuthEvents(ctx context.Context, t *testing.T, raw any, sessionID ccc.UUID) int {
	t.Helper()

	var n int
	if err := queryer(t, raw).QueryRow(ctx, `SELECT COUNT(*) FROM "SessionAuthEvents" WHERE "SessionId" = $1`, sessionID).Scan(&n); err != nil {
		t.Fatalf("QueryRow().Scan() error = %v", err)
	}

	return n
}

func deleteSession(ctx context.Context, t *testing.T, raw any, sessionID ccc.UUID) {
	t.Helper()

	if _, err := queryer(t, raw).Exec(ctx, `DELETE FROM "Sessions" WHERE "Id" = $1`, sessionID); err != nil {
		t.Fatalf("Exec() error = %v", err)
	}
}
