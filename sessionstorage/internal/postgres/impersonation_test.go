package postgres

import (
	"context"
	"reflect"
	"testing"
	"time"

	"github.com/cccteam/ccc"
	"github.com/cccteam/session/sessionstorage/internal/drivertest"
)

// TestImpersonation runs the shared driver conformance suite against the PostgreSQL
// driver. The cases live in drivertest so the Spanner driver runs exactly the same ones.
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
		return []string{"file://../../../schema/postgresql/migrations", "file://../../../schema/postgresql/impersonation/migrations"}
	case drivertest.OIDC:
		return []string{"file://../../../schema/postgresql/oidc/migrations", "file://../../../schema/postgresql/impersonation/migrations"}
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
		c := NewSessionStorageDriver(conn.Pool)
		if cfg.Google {
			c = NewGoogleSessionStorageDriver(conn.Pool)
		}
		if cfg.Impersonation {
			c.SetImpersonation(&ImpersonationConfig{TableName: "SessionImpersonations"})
		}
		if cfg.CustomData {
			c.SetCustomSessionData(&CustomSessionDataConfig{TableName: "SessionCustomData", Codec: mustCodec(reflect.TypeFor[drivertest.CustomStringData]())})
		}

		return c
	}

	return &drivertest.Instance{Driver: newDriver(cfg), NewDriver: newDriver, Raw: conn.Pool}
}

func queryer(t *testing.T, raw any) Queryer {
	t.Helper()

	q, ok := raw.(Queryer)
	if !ok {
		t.Fatalf("raw handle is %T, want Queryer", raw)
	}

	return q
}

// recordEnd reads the end columns of a record straight from the table.
func recordEnd(ctx context.Context, t *testing.T, raw any, id ccc.UUID) (endedAt *time.Time, endReason *string) {
	t.Helper()

	if err := queryer(t, raw).QueryRow(ctx, `SELECT "EndedAt", "EndReason" FROM "SessionImpersonations" WHERE "SessionId" = $1`, id).Scan(&endedAt, &endReason); err != nil {
		t.Fatalf("QueryRow().Scan() error = %v", err)
	}

	return endedAt, endReason
}

func expireSession(ctx context.Context, t *testing.T, raw any, id ccc.UUID) {
	t.Helper()

	if _, err := queryer(t, raw).Exec(ctx, `UPDATE "Sessions" SET "Expired" = TRUE WHERE "Id" = $1`, id); err != nil {
		t.Fatalf("Exec() error = %v", err)
	}
}

func oidcSid(ctx context.Context, t *testing.T, raw any, id ccc.UUID) string {
	t.Helper()

	var sid string
	if err := queryer(t, raw).QueryRow(ctx, `SELECT "OidcSid" FROM "Sessions" WHERE "Id" = $1`, id).Scan(&sid); err != nil {
		t.Fatalf("QueryRow().Scan() error = %v", err)
	}

	return sid
}
