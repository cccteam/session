package spanner

import (
	"context"
	"testing"

	"cloud.google.com/go/spanner"
	"github.com/cccteam/ccc"
	"github.com/cccteam/session/internal/dbtype"
	"github.com/cccteam/session/sessioninfo"
	"github.com/cccteam/session/sessionstorage/internal/drivertest"
	"github.com/go-playground/errors/v5"
)

// TestAccounts runs the shared accounts conformance suite against the Spanner driver,
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
	legacy := []string{"file://../../../schema/spanner/migrations", "file://../../../schema/spanner/impersonation/migrations"}
	switch schema {
	case drivertest.LegacySessions:
		return legacy
	case drivertest.Accounts:
		return append(legacy, "file://../../../schema/spanner/accounts/migrations")
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

	d := NewSessionStorageDriver(conn.Client)
	if cfg.Accounts {
		d.EnableAccounts()
	}
	if cfg.AuthEvents {
		d.SetAuthEvents(&AuthEventsConfig{TableName: "SessionAuthEvents"})
	}
	if cfg.Impersonation {
		d.SetImpersonation(&ImpersonationConfig{TableName: "SessionImpersonations"})
	}
	if cfg.Identities {
		identities := &IdentitiesConfig{
			TableName: "SessionIdentities",
			Resolve: func(ctx context.Context, _ *spanner.ReadWriteTransaction, req *sessioninfo.NewSessionRequest) (*dbtype.Resolution, error) {
				if cfg.Resolve == nil {
					return nil, nil
				}

				return cfg.Resolve(ctx, req)
			},
		}
		if cfg.Policy != nil {
			identities.Policy = func(ctx context.Context, _ *spanner.ReadWriteTransaction, req *sessioninfo.NewSessionRequest) (*dbtype.SignInDecision, error) {
				return cfg.Policy(ctx, req)
			}
		}
		d.SetIdentities(identities)
	}

	return &drivertest.AccountsInstance{Driver: d, Raw: conn.Client}
}

func countAuthEvents(ctx context.Context, t *testing.T, raw any, sessionID ccc.UUID) int {
	t.Helper()

	stmt := spanner.NewStatement("SELECT COUNT(*) FROM SessionAuthEvents WHERE SessionId = @id")
	stmt.Params["id"] = sessionID.String()
	var n int64
	if err := client(t, raw).Single().Query(ctx, stmt).Do(func(r *spanner.Row) error { return r.Column(0, &n) }); err != nil {
		t.Fatalf("Query() error = %v", err)
	}

	return int(n)
}

func deleteSession(ctx context.Context, t *testing.T, raw any, sessionID ccc.UUID) {
	t.Helper()

	_, err := client(t, raw).ReadWriteTransaction(ctx, func(ctx context.Context, txn *spanner.ReadWriteTransaction) error {
		stmt := spanner.NewStatement("DELETE FROM Sessions WHERE Id = @id")
		stmt.Params["id"] = sessionID.String()
		if _, err := txn.Update(ctx, stmt); err != nil {
			return errors.Wrap(err, "txn.Update()")
		}

		return nil
	})
	if err != nil {
		t.Fatalf("ReadWriteTransaction() error = %v", err)
	}
}
