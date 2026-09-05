package spanner

import (
	"context"
	"reflect"
	"testing"
	"time"

	"cloud.google.com/go/spanner"
	"github.com/cccteam/ccc"
	"github.com/cccteam/session/sessionstorage/internal/drivertest"
	"github.com/go-playground/errors/v5"
)

// TestImpersonation runs the shared driver conformance suite against the Spanner
// driver. The cases live in drivertest so the PostgreSQL driver runs exactly the same
// ones.
func TestImpersonation(t *testing.T) {
	t.Parallel()

	drivertest.RunImpersonation(t, &drivertest.Harness{
		New:           newImpersonationInstance,
		RecordEnd:     recordEnd,
		ExpireSession: expireSession,
		OIDCSid:       oidcSid,
	})
}

// impersonationSources maps a suite schema to this package's migration sources.
func impersonationSources(schema drivertest.Schema) []string {
	switch schema {
	case drivertest.SeededImpersonation:
		return []string{"file://testdata/sessions_test/impersonation_schema"}
	case drivertest.Sessions:
		return []string{"file://../../../schema/spanner/migrations", "file://../../../schema/spanner/impersonation/migrations"}
	case drivertest.OIDC:
		return []string{"file://../../../schema/spanner/oidc/migrations", "file://../../../schema/spanner/impersonation/migrations"}
	default:
		panic("unknown schema")
	}
}

func newImpersonationInstance(ctx context.Context, t *testing.T, schema drivertest.Schema, cfg drivertest.Config) *drivertest.Instance {
	t.Helper()

	conn, err := prepareDatabase(ctx, t, impersonationSources(schema)...)
	if err != nil {
		t.Fatalf("prepareDatabase() error = %v", err)
	}

	newDriver := func(cfg drivertest.Config) drivertest.Driver {
		c := NewSessionStorageDriver(conn.Client)
		if cfg.Google {
			c = NewGoogleSessionStorageDriver(conn.Client)
		}
		if cfg.Impersonation {
			c.SetImpersonation(&ImpersonationConfig{TableName: "SessionImpersonations"})
		}
		if cfg.CustomData {
			c.SetCustomSessionData(&CustomSessionDataConfig{TableName: "SessionCustomData", Codec: mustCodec(reflect.TypeFor[drivertest.CustomStringData]())})
		}

		return c
	}

	return &drivertest.Instance{Driver: newDriver(cfg), NewDriver: newDriver, Raw: conn.Client}
}

func client(t *testing.T, raw any) *spanner.Client {
	t.Helper()

	c, ok := raw.(*spanner.Client)
	if !ok {
		t.Fatalf("raw handle is %T, want *spanner.Client", raw)
	}

	return c
}

// recordEnd reads the end columns of a record straight from the table.
func recordEnd(ctx context.Context, t *testing.T, raw any, id ccc.UUID) (endedAt *time.Time, endReason *string) {
	t.Helper()

	row, err := client(t, raw).Single().ReadRow(ctx, "SessionImpersonations", spanner.Key{id.String()}, []string{"EndedAt", "EndReason"})
	if err != nil {
		t.Fatalf("ReadRow() error = %v", err)
	}
	var ended spanner.NullTime
	var reason spanner.NullString
	if err := row.Columns(&ended, &reason); err != nil {
		t.Fatalf("row.Columns() error = %v", err)
	}
	if ended.Valid {
		endedAt = &ended.Time
	}
	if reason.Valid {
		endReason = &reason.StringVal
	}

	return endedAt, endReason
}

func expireSession(ctx context.Context, t *testing.T, raw any, id ccc.UUID) {
	t.Helper()

	_, err := client(t, raw).ReadWriteTransaction(ctx, func(ctx context.Context, txn *spanner.ReadWriteTransaction) error {
		expire := spanner.NewStatement("UPDATE Sessions SET Expired = TRUE WHERE Id = @id")
		expire.Params["id"] = id.String()
		if _, err := txn.Update(ctx, expire); err != nil {
			return errors.Wrap(err, "txn.Update()")
		}

		return nil
	})
	if err != nil {
		t.Fatalf("ReadWriteTransaction() error = %v", err)
	}
}

func oidcSid(ctx context.Context, t *testing.T, raw any, id ccc.UUID) string {
	t.Helper()

	row, err := client(t, raw).Single().ReadRow(ctx, "Sessions", spanner.Key{id.String()}, []string{"OidcSid"})
	if err != nil {
		t.Fatalf("ReadRow() error = %v", err)
	}
	var sid string
	if err := row.Columns(&sid); err != nil {
		t.Fatalf("row.Columns() error = %v", err)
	}

	return sid
}
