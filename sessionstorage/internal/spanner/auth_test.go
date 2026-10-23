package spanner

import (
	"context"
	"reflect"
	"testing"
	"time"

	"cloud.google.com/go/spanner"
	"github.com/cccteam/ccc"
	"github.com/cccteam/session/sessioninfo"
	"github.com/cccteam/session/sessionstorage/internal/drivertest"
	"github.com/go-playground/errors/v5"
	"google.golang.org/grpc/codes"
)

// TestAuth runs the shared users conformance suite against the Spanner driver,
// on the shipped auth migrations.
func TestAuth(t *testing.T) {
	t.Parallel()

	drivertest.RunAuth(t, &drivertest.AuthHarness{
		New:                newAuthInstance,
		CountAuthEvents:    countAuthEvents,
		DeleteSession:      deleteSession,
		Recorded:           recorded,
		Record:             record,
		PendingConsumedAt:  pendingConsumedAt,
		MailLinkConsumedAt: mailLinkConsumedAt,
		ClockLead:          emulatorClockLead,
	})
}

// authSources maps an users suite schema to this package's migration sources.
func authSources(schema drivertest.AuthSchema) []string {
	legacy := []string{"file://../../../schema/spanner/migrations", "file://../../../schema/spanner/impersonation/migrations"}
	switch schema {
	case drivertest.LegacySessions:
		return legacy
	case drivertest.Auth:
		return append(legacy, "file://../../../schema/spanner/auth/migrations")
	case drivertest.AuthWithAppTables:
		return append(legacy, "file://../../../schema/spanner/auth/migrations", "file://testdata/auth_test/app_tables")
	case drivertest.AuthUsernameIsEmail:
		return append(legacy, "file://../../../schema/spanner/auth/migrations", "file://testdata/auth_test/app_tables", "file://testdata/auth_test/username_is_email")
	case drivertest.AuthFromOIDC:
		return []string{
			"file://../../../schema/spanner/oidc/migrations", "file://../../../schema/spanner/impersonation/migrations",
			"file://testdata/auth_test/oidc_anchor_seed", "file://../../../schema/spanner/auth-from-oidc/migrations",
		}
	default:
		panic("unknown schema")
	}
}

func newAuthInstance(ctx context.Context, t *testing.T, schema drivertest.AuthSchema, cfg drivertest.AuthConfig) *drivertest.AuthInstance {
	t.Helper()

	conn, err := prepareDatabase(ctx, t, authSources(schema)...)
	if err != nil {
		t.Fatalf("prepareDatabase() error = %v", err)
	}

	d := NewSessionStorageDriver(conn.Client)
	if cfg.Auth {
		d.EnableAuth()
	}
	if schema == drivertest.AuthUsernameIsEmail {
		d.SetUsernameIsEmail(true)
	}
	if cfg.AuthEvents {
		d.SetAuthEvents(&AuthEventsConfig{TableName: "SessionAuthEvents"})
	}
	if cfg.Impersonation {
		d.SetImpersonation(&ImpersonationConfig{TableName: "SessionImpersonations"})
	}
	if cfg.CustomData != nil {
		d.SetCustomSessionData(&CustomSessionDataConfig{
			TableName: "SessionCustomData",
			Codec:     mustCodec(reflect.TypeFor[drivertest.CustomStringData]()),
			Resolver: func(ctx context.Context, txn *spanner.ReadWriteTransaction, req *sessioninfo.NewSessionRequest) (any, error) {
				return cfg.CustomData(ctx, hookTx{txn}, req)
			},
		})
	}

	return &drivertest.AuthInstance{
		Driver: d, Raw: conn.Client,
		SignIn: drivertest.NewSignIn(d, cfg, func(txn *spanner.ReadWriteTransaction) drivertest.HookTx { return hookTx{txn} }),
		Accept: drivertest.NewAccept(d, cfg),
	}
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

func pendingConsumedAt(ctx context.Context, t *testing.T, raw any, tokenHash []byte) *time.Time {
	t.Helper()

	stmt := spanner.NewStatement("SELECT ConsumedAt FROM SessionPendingSignIns WHERE TokenHash = @tokenHash")
	stmt.Params["tokenHash"] = tokenHash
	var consumedAt spanner.NullTime
	if err := client(t, raw).Single().Query(ctx, stmt).Do(func(r *spanner.Row) error { return r.Column(0, &consumedAt) }); err != nil {
		t.Fatalf("Query() error = %v", err)
	}
	if !consumedAt.Valid {
		return nil
	}

	return &consumedAt.Time
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

// hookTx is drivertest.HookTx over a hook's read-write transaction.
type hookTx struct {
	txn *spanner.ReadWriteTransaction
}

func (x hookTx) Record(_ context.Context, key, value string) error {
	m := spanner.InsertOrUpdate("HookRecords", []string{"RecordKey", "RecordValue"}, []any{key, value})
	if err := x.txn.BufferWrite([]*spanner.Mutation{m}); err != nil {
		return errors.Wrap(err, "txn.BufferWrite()")
	}

	return nil
}

func (x hookTx) Recorded(ctx context.Context, key string) (value string, found bool, err error) {
	row, err := x.txn.ReadRow(ctx, "HookRecords", spanner.Key{key}, []string{"RecordValue"})
	if spanner.ErrCode(err) == codes.NotFound {
		return "", false, nil
	}
	if err != nil {
		return "", false, errors.Wrap(err, "txn.ReadRow()")
	}
	if err := row.Column(0, &value); err != nil {
		return "", false, errors.Wrap(err, "row.Column()")
	}

	return value, true, nil
}

func (x hookTx) UserExists(ctx context.Context, userID ccc.UUID) (bool, error) {
	_, err := x.txn.ReadRow(ctx, "SessionUsers", spanner.Key{userID.String()}, []string{idColumn})
	if spanner.ErrCode(err) == codes.NotFound {
		return false, nil
	}
	if err != nil {
		return false, errors.Wrap(err, "txn.ReadRow()")
	}

	return true, nil
}

func recorded(ctx context.Context, t *testing.T, raw any, key string) (string, bool) {
	t.Helper()

	row, err := client(t, raw).Single().ReadRow(ctx, "HookRecords", spanner.Key{key}, []string{"RecordValue"})
	if spanner.ErrCode(err) == codes.NotFound {
		return "", false
	}
	if err != nil {
		t.Fatalf("ReadRow() error = %v", err)
	}
	var value string
	if err := row.Column(0, &value); err != nil {
		t.Fatalf("Column() error = %v", err)
	}

	return value, true
}

func record(ctx context.Context, t *testing.T, raw any, key, value string) {
	t.Helper()

	m := spanner.InsertOrUpdate("HookRecords", []string{"RecordKey", "RecordValue"}, []any{key, value})
	if _, err := client(t, raw).Apply(ctx, []*spanner.Mutation{m}); err != nil {
		t.Fatalf("Apply() error = %v", err)
	}
}

func mailLinkConsumedAt(ctx context.Context, t *testing.T, raw any, tokenHash []byte) *time.Time {
	t.Helper()

	stmt := spanner.NewStatement("SELECT ConsumedAt FROM SessionMailLinks WHERE TokenHash = @tokenHash")
	stmt.Params["tokenHash"] = tokenHash
	var consumedAt spanner.NullTime
	if err := client(t, raw).Single().Query(ctx, stmt).Do(func(r *spanner.Row) error { return r.Column(0, &consumedAt) }); err != nil {
		t.Fatalf("Query() error = %v", err)
	}
	if !consumedAt.Valid {
		return nil
	}

	return &consumedAt.Time
}
