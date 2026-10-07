package postgres

import (
	"context"
	"reflect"
	"testing"

	"github.com/cccteam/ccc"
	"github.com/cccteam/session/internal/dbtype"
	"github.com/cccteam/session/sessioninfo"
	"github.com/cccteam/session/sessionstorage/internal/drivertest"
	"github.com/go-playground/errors/v5"
	"github.com/jackc/pgx/v5"
)

// TestAccounts runs the shared accounts conformance suite against the PostgreSQL driver,
// on the shipped accounts migration.
func TestAccounts(t *testing.T) {
	t.Parallel()

	drivertest.RunAccounts(t, &drivertest.AccountsHarness{
		New:             newAccountsInstance,
		CountAuthEvents: countAuthEvents,
		DeleteSession:   deleteSession,
		Recorded:        recorded,
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
	case drivertest.AccountsWithAppTables:
		return append(legacy, "file://../../../schema/postgresql/accounts/migrations", "file://testdata/accounts_test/app_tables")
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
	if cfg.Identities {
		identities := &IdentitiesConfig{
			TableName: "SessionIdentities",
			Resolve: func(ctx context.Context, txn pgx.Tx, req *sessioninfo.NewSessionRequest) (*dbtype.Resolution, error) {
				if cfg.Resolve == nil {
					return nil, nil
				}

				return cfg.Resolve(ctx, hookTx{txn}, req)
			},
		}
		if cfg.Policy != nil {
			identities.Policy = func(ctx context.Context, txn pgx.Tx, req *sessioninfo.NewSessionRequest) (*dbtype.SignInDecision, error) {
				return cfg.Policy(ctx, hookTx{txn}, req)
			}
		}
		d.SetIdentities(identities)
	}
	if cfg.CustomData != nil {
		d.SetCustomSessionData(&CustomSessionDataConfig{
			TableName: "SessionCustomData",
			Codec:     mustCodec(reflect.TypeFor[drivertest.CustomStringData]()),
			Resolver: func(ctx context.Context, txn pgx.Tx, req *sessioninfo.NewSessionRequest) (any, error) {
				return cfg.CustomData(ctx, hookTx{txn}, req)
			},
		})
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

// hookTx is drivertest.HookTx over a hook's transaction.
type hookTx struct {
	txn pgx.Tx
}

func (x hookTx) Record(ctx context.Context, key, value string) error {
	_, err := x.txn.Exec(ctx, `INSERT INTO "HookRecords" ("RecordKey", "RecordValue") VALUES ($1, $2)
		ON CONFLICT ("RecordKey") DO UPDATE SET "RecordValue" = EXCLUDED."RecordValue"`, key, value)
	if err != nil {
		return errors.Wrap(err, "pgx.Tx.Exec()")
	}

	return nil
}

func (x hookTx) Recorded(ctx context.Context, key string) (value string, found bool, err error) {
	err = x.txn.QueryRow(ctx, `SELECT "RecordValue" FROM "HookRecords" WHERE "RecordKey" = $1`, key).Scan(&value)
	if errors.Is(err, pgx.ErrNoRows) {
		return "", false, nil
	}
	if err != nil {
		return "", false, errors.Wrap(err, "pgx.Tx.QueryRow().Scan()")
	}

	return value, true, nil
}

func (x hookTx) UserExists(ctx context.Context, userID ccc.UUID) (bool, error) {
	var exists bool
	if err := x.txn.QueryRow(ctx, `SELECT EXISTS (SELECT 1 FROM "SessionUsers" WHERE "Id" = $1)`, userID).Scan(&exists); err != nil {
		return false, errors.Wrap(err, "pgx.Tx.QueryRow().Scan()")
	}

	return exists, nil
}

func recorded(ctx context.Context, t *testing.T, raw any, key string) (string, bool) {
	t.Helper()

	var value string
	err := queryer(t, raw).QueryRow(ctx, `SELECT "RecordValue" FROM "HookRecords" WHERE "RecordKey" = $1`, key).Scan(&value)
	if errors.Is(err, pgx.ErrNoRows) {
		return "", false
	}
	if err != nil {
		t.Fatalf("QueryRow().Scan() error = %v", err)
	}

	return value, true
}
