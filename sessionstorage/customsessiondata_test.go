package sessionstorage

import (
	"context"
	"testing"

	cloudspanner "cloud.google.com/go/spanner"
	"github.com/cccteam/session/sessioninfo"
	"github.com/google/go-cmp/cmp"
	"github.com/jackc/pgx/v5"
)

type testDecodedData struct{ Role string }

func testDecoder(m map[string]any) (testDecodedData, error) {
	role, _ := m["Role"].(string)

	return testDecodedData{Role: role}, nil
}

func TestNewCustomSessionData_Validation(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name        string
		tableName   string
		nilDecoder  bool
		columns     []string
		wantErr     bool
		wantColumns []string
	}{
		{
			name:        "valid config",
			tableName:   "SessionCustomData",
			columns:     []string{"TenantId", "RoleId"},
			wantColumns: []string{"TenantId", "RoleId"},
		},
		{
			name:        "duplicate columns are deduplicated",
			tableName:   "SessionCustomData",
			columns:     []string{"TenantId", "RoleId", "TenantId"},
			wantColumns: []string{"TenantId", "RoleId"},
		},
		{
			name:        "no columns is valid",
			tableName:   "SessionCustomData",
			columns:     nil,
			wantColumns: nil,
		},
		{
			name:      "invalid table name",
			tableName: "Session Custom Data;",
			columns:   []string{"TenantId"},
			wantErr:   true,
		},
		{
			name:      "empty table name",
			tableName: "",
			columns:   []string{"TenantId"},
			wantErr:   true,
		},
		{
			name:      "invalid column name",
			tableName: "SessionCustomData",
			columns:   []string{"Tenant-Id"},
			wantErr:   true,
		},
		{
			name:      "reserved SessionId column",
			tableName: "SessionCustomData",
			columns:   []string{"SessionId"},
			wantErr:   true,
		},
		{
			name:       "nil decoder",
			tableName:  "SessionCustomData",
			nilDecoder: true,
			columns:    []string{"TenantId"},
			wantErr:    true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			decoder := testDecoder
			if tt.nilDecoder {
				decoder = nil
			}

			spannerCfg, spannerErr := NewSpannerCustomSessionData(tt.tableName, decoder, nil, tt.columns...)
			if (spannerErr != nil) != tt.wantErr {
				t.Errorf("NewSpannerCustomSessionData() error = %v, wantErr %v", spannerErr, tt.wantErr)
			}
			postgresCfg, postgresErr := NewPostgresCustomSessionData(tt.tableName, decoder, nil, tt.columns...)
			if (postgresErr != nil) != tt.wantErr {
				t.Errorf("NewPostgresCustomSessionData() error = %v, wantErr %v", postgresErr, tt.wantErr)
			}
			if tt.wantErr {
				return
			}

			if spannerCfg.TableName() != tt.tableName {
				t.Errorf("SpannerCustomSessionData.TableName() = %q, want %q", spannerCfg.TableName(), tt.tableName)
			}
			if diff := cmp.Diff(tt.wantColumns, spannerCfg.Columns()); diff != "" {
				t.Errorf("SpannerCustomSessionData.Columns() mismatch (-want +got):\n%s", diff)
			}
			if diff := cmp.Diff(tt.wantColumns, postgresCfg.Columns()); diff != "" {
				t.Errorf("PostgresCustomSessionData.Columns() mismatch (-want +got):\n%s", diff)
			}
		})
	}
}

func TestCustomSessionData_DriverConfig(t *testing.T) {
	t.Parallel()

	t.Run("nil resolver stays nil through the bridge", func(t *testing.T) {
		t.Parallel()

		spannerCfg, err := NewSpannerCustomSessionData("SessionCustomData", testDecoder, nil, "Role")
		if err != nil {
			t.Fatalf("NewSpannerCustomSessionData() error = %v", err)
		}
		if got := spannerCfg.driverConfig(); got.Resolver != nil {
			t.Error("SpannerCustomSessionData.driverConfig().Resolver != nil, want nil")
		}

		postgresCfg, err := NewPostgresCustomSessionData("SessionCustomData", testDecoder, nil, "Role")
		if err != nil {
			t.Fatalf("NewPostgresCustomSessionData() error = %v", err)
		}
		if got := postgresCfg.driverConfig(); got.Resolver != nil {
			t.Error("PostgresCustomSessionData.driverConfig().Resolver != nil, want nil")
		}
	})

	t.Run("decoder and resolver are carried through the bridge", func(t *testing.T) {
		t.Parallel()

		spannerResolver := func(_ context.Context, _ *cloudspanner.ReadWriteTransaction, _ sessioninfo.NewSessionRequest) ([]*sessioninfo.CustomData, error) {
			return []*sessioninfo.CustomData{{ColumnName: "Role", Value: "admin"}}, nil
		}
		spannerCfg, err := NewSpannerCustomSessionData("SessionCustomData", testDecoder, spannerResolver, "Role")
		if err != nil {
			t.Fatalf("NewSpannerCustomSessionData() error = %v", err)
		}
		spannerDriverCfg := spannerCfg.driverConfig()
		if spannerDriverCfg.Resolver == nil {
			t.Fatal("SpannerCustomSessionData.driverConfig().Resolver is nil, want non-nil")
		}
		decoded, err := spannerDriverCfg.Decoder(map[string]any{"Role": "admin"})
		if err != nil {
			t.Fatalf("driverConfig().Decoder() error = %v", err)
		}
		if diff := cmp.Diff(testDecodedData{Role: "admin"}, decoded); diff != "" {
			t.Errorf("driverConfig().Decoder() mismatch (-want +got):\n%s", diff)
		}

		postgresResolver := func(_ context.Context, _ pgx.Tx, _ sessioninfo.NewSessionRequest) ([]*sessioninfo.CustomData, error) {
			return []*sessioninfo.CustomData{{ColumnName: "Role", Value: "admin"}}, nil
		}
		postgresCfg, err := NewPostgresCustomSessionData("SessionCustomData", testDecoder, postgresResolver, "Role")
		if err != nil {
			t.Fatalf("NewPostgresCustomSessionData() error = %v", err)
		}
		if postgresCfg.driverConfig().Resolver == nil {
			t.Fatal("PostgresCustomSessionData.driverConfig().Resolver is nil, want non-nil")
		}
	})
}
