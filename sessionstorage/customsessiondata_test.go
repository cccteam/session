package sessionstorage

import (
	"context"
	"testing"

	cloudspanner "cloud.google.com/go/spanner"
	"github.com/cccteam/session/internal/dbtype"
	"github.com/cccteam/session/sessioninfo"
	"github.com/cccteam/session/sessionstorage/internal/postgres"
	"github.com/cccteam/session/sessionstorage/internal/spanner"
	"github.com/google/go-cmp/cmp"
	"github.com/jackc/pgx/v5"
)

type testTypedData struct {
	Role   string `spanner:"SpannerRole" db:"pg_role"`
	Tenant string `spanner:"Tenant" db:"tenant"`
}

type testReservedData struct {
	SessionID string `spanner:"SessionId" db:"SessionId"`
}

type testBadIdentifierData struct {
	Role string `spanner:"bad name" db:"bad name"`
}

type testNoFieldsData struct {
	//nolint:unused // exercises the no-persistable-fields error
	role string
}

// customSessionDataView is the common read surface of the generic Spanner/Postgres
// config types, so validation cases can share one table runner.
type customSessionDataView interface {
	TableName() string
	Columns() []string
}

func TestNewCustomSessionData_Validation(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name        string
		construct   func() (customSessionDataView, error)
		wantErr     bool
		wantTable   string
		wantColumns []string
	}{
		{
			name: "spanner config derives columns from spanner tags",
			construct: func() (customSessionDataView, error) {
				return NewSpannerCustomSessionData[testTypedData]("SessionCustomData", nil)
			},
			wantTable:   "SessionCustomData",
			wantColumns: []string{"SpannerRole", "Tenant"},
		},
		{
			name: "postgres config derives columns from db tags",
			construct: func() (customSessionDataView, error) {
				return NewPostgresCustomSessionData[testTypedData]("SessionCustomData", nil)
			},
			wantTable:   "SessionCustomData",
			wantColumns: []string{"pg_role", "tenant"},
		},
		{
			name: "invalid table name",
			construct: func() (customSessionDataView, error) {
				return NewSpannerCustomSessionData[testTypedData]("Session Custom Data;", nil)
			},
			wantErr: true,
		},
		{
			name: "non-struct T",
			construct: func() (customSessionDataView, error) {
				return NewSpannerCustomSessionData[int]("SessionCustomData", nil)
			},
			wantErr: true,
		},
		{
			name: "reserved SessionId tag on spanner",
			construct: func() (customSessionDataView, error) {
				return NewSpannerCustomSessionData[testReservedData]("SessionCustomData", nil)
			},
			wantErr: true,
		},
		{
			name: "reserved SessionId tag on postgres",
			construct: func() (customSessionDataView, error) {
				return NewPostgresCustomSessionData[testReservedData]("SessionCustomData", nil)
			},
			wantErr: true,
		},
		{
			name: "tag failing identifier rules",
			construct: func() (customSessionDataView, error) {
				return NewSpannerCustomSessionData[testBadIdentifierData]("SessionCustomData", nil)
			},
			wantErr: true,
		},
		{
			name: "no persistable fields",
			construct: func() (customSessionDataView, error) {
				return NewSpannerCustomSessionData[testNoFieldsData]("SessionCustomData", nil)
			},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			cfg, err := tt.construct()
			if (err != nil) != tt.wantErr {
				t.Fatalf("construct error = %v, wantErr = %v", err, tt.wantErr)
			}
			if tt.wantErr {
				return
			}
			if cfg.TableName() != tt.wantTable {
				t.Errorf("TableName() = %q, want %q", cfg.TableName(), tt.wantTable)
			}
			if diff := cmp.Diff(tt.wantColumns, cfg.Columns()); diff != "" {
				t.Errorf("Columns() mismatch (-want +got):\n%s", diff)
			}
		})
	}
}

func TestCustomSessionData_DriverConfig(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name            string
		driverConfig    func(t *testing.T) (resolve func(ctx context.Context) (any, error), codec *dbtype.CustomDataCodec)
		wantNilResolver bool
		wantUntypedNil  bool
		wantData        *testTypedData
		wantValues      []any
	}{
		{
			name: "spanner nil resolver stays nil through the bridge",
			driverConfig: func(t *testing.T) (func(ctx context.Context) (any, error), *dbtype.CustomDataCodec) {
				t.Helper()

				cfg, err := NewSpannerCustomSessionData[testTypedData]("SessionCustomData", nil)
				if err != nil {
					t.Fatalf("NewSpannerCustomSessionData() error = %v", err)
				}

				return resolveFunc(cfg.driverConfig())
			},
			wantNilResolver: true,
		},
		{
			name: "postgres nil resolver stays nil through the bridge",
			driverConfig: func(t *testing.T) (func(ctx context.Context) (any, error), *dbtype.CustomDataCodec) {
				t.Helper()

				cfg, err := NewPostgresCustomSessionData[testTypedData]("SessionCustomData", nil)
				if err != nil {
					t.Fatalf("NewPostgresCustomSessionData() error = %v", err)
				}

				return resolvePostgresFunc(cfg.driverConfig())
			},
			wantNilResolver: true,
		},
		{
			name: "typed nil resolver result crosses as untyped nil",
			driverConfig: func(t *testing.T) (func(ctx context.Context) (any, error), *dbtype.CustomDataCodec) {
				t.Helper()

				cfg, err := NewSpannerCustomSessionData("SessionCustomData",
					func(_ context.Context, _ *cloudspanner.ReadWriteTransaction, _ sessioninfo.NewSessionRequest) (*testTypedData, error) {
						return nil, nil //nolint:nilnil // typed-nil crossing is the behavior under test
					})
				if err != nil {
					t.Fatalf("NewSpannerCustomSessionData() error = %v", err)
				}

				return resolveFunc(cfg.driverConfig())
			},
			wantUntypedNil: true,
		},
		{
			name: "resolver data and codec thread through",
			driverConfig: func(t *testing.T) (func(ctx context.Context) (any, error), *dbtype.CustomDataCodec) {
				t.Helper()

				cfg, err := NewPostgresCustomSessionData("SessionCustomData",
					func(_ context.Context, _ pgx.Tx, _ sessioninfo.NewSessionRequest) (*testTypedData, error) {
						return &testTypedData{Role: "admin", Tenant: "t1"}, nil
					})
				if err != nil {
					t.Fatalf("NewPostgresCustomSessionData() error = %v", err)
				}

				return resolvePostgresFunc(cfg.driverConfig())
			},
			wantData:   &testTypedData{Role: "admin", Tenant: "t1"},
			wantValues: []any{"admin", "t1"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			resolve, codec := tt.driverConfig(t)
			if codec == nil {
				t.Fatal("driverConfig().Codec is nil")
			}
			if tt.wantNilResolver {
				if resolve != nil {
					t.Error("driverConfig().Resolver != nil, want nil")
				}

				return
			}

			data, err := resolve(t.Context())
			if err != nil {
				t.Fatalf("Resolver() error = %v", err)
			}
			if tt.wantUntypedNil {
				if data != nil {
					t.Errorf("Resolver() = %v (%T), want untyped nil", data, data)
				}

				return
			}
			typed, ok := data.(*testTypedData)
			if !ok {
				t.Fatalf("Resolver() = %T, want *testTypedData", data)
			}
			if diff := cmp.Diff(tt.wantData, typed); diff != "" {
				t.Errorf("Resolver() mismatch (-want +got):\n%s", diff)
			}

			values, err := codec.Values(data)
			if err != nil {
				t.Fatalf("Codec.Values() error = %v", err)
			}
			if diff := cmp.Diff(tt.wantValues, values); diff != "" {
				t.Errorf("Codec.Values() mismatch (-want +got):\n%s", diff)
			}
		})
	}
}

// resolveFunc adapts a spanner driver config to the backend-neutral shape the table
// runner asserts against; a nil Resolver stays nil.
func resolveFunc(cfg *spanner.CustomSessionDataConfig) (func(ctx context.Context) (any, error), *dbtype.CustomDataCodec) {
	if cfg.Resolver == nil {
		return nil, cfg.Codec
	}

	return func(ctx context.Context) (any, error) {
		return cfg.Resolver(ctx, nil, sessioninfo.NewSessionRequest{})
	}, cfg.Codec
}

// resolvePostgresFunc is the postgres mirror of resolveFunc.
func resolvePostgresFunc(cfg *postgres.CustomSessionDataConfig) (func(ctx context.Context) (any, error), *dbtype.CustomDataCodec) {
	if cfg.Resolver == nil {
		return nil, cfg.Codec
	}

	return func(ctx context.Context) (any, error) {
		return cfg.Resolver(ctx, nil, sessioninfo.NewSessionRequest{})
	}, cfg.Codec
}
