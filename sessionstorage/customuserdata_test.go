package sessionstorage

import (
	"context"
	"testing"

	cloudspanner "cloud.google.com/go/spanner"
	"github.com/cccteam/session/internal/dbtype"
	"github.com/cccteam/session/sessioninfo"
	"github.com/cccteam/session/sessionstorage/internal/postgres"
	"github.com/cccteam/session/sessionstorage/internal/spanner"
	"github.com/go-playground/errors/v5"
	"github.com/google/go-cmp/cmp"
	"github.com/jackc/pgx/v5"
)

type testUserData struct {
	Email string `spanner:"Email" db:"email"`
	Theme string `spanner:"Theme" db:"theme"`
}

type testReservedUserData struct {
	UserID string `spanner:"UserId" db:"UserId"`
}

// customUserDataView is the common read surface of the generic Spanner/Postgres config
// types, so validation cases can share one table runner.
type customUserDataView interface {
	TableName() string
	Columns() []string
}

func TestNewCustomUserData_Validation(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name        string
		construct   func() (customUserDataView, error)
		wantErr     bool
		wantTable   string
		wantColumns []string
	}{
		{
			name: "spanner config derives columns from spanner tags",
			construct: func() (customUserDataView, error) {
				return NewSpannerCustomUserData[testUserData]("UserCustomData", nil)
			},
			wantTable:   "UserCustomData",
			wantColumns: []string{"Email", "Theme"},
		},
		{
			name: "postgres config derives columns from db tags",
			construct: func() (customUserDataView, error) {
				return NewPostgresCustomUserData[testUserData]("UserCustomData", nil)
			},
			wantTable:   "UserCustomData",
			wantColumns: []string{"email", "theme"},
		},
		{
			name: "invalid table name",
			construct: func() (customUserDataView, error) {
				return NewSpannerCustomUserData[testUserData]("User Custom Data;", nil)
			},
			wantErr: true,
		},
		{
			name: "non-struct U",
			construct: func() (customUserDataView, error) {
				return NewSpannerCustomUserData[int]("UserCustomData", nil)
			},
			wantErr: true,
		},
		{
			name: "reserved UserId tag on spanner",
			construct: func() (customUserDataView, error) {
				return NewSpannerCustomUserData[testReservedUserData]("UserCustomData", nil)
			},
			wantErr: true,
		},
		{
			name: "reserved UserId tag on postgres",
			construct: func() (customUserDataView, error) {
				return NewPostgresCustomUserData[testReservedUserData]("UserCustomData", nil)
			},
			wantErr: true,
		},
		{
			name: "SessionId is not reserved for user data",
			construct: func() (customUserDataView, error) {
				return NewSpannerCustomUserData[testReservedData]("UserCustomData", nil)
			},
			wantTable:   "UserCustomData",
			wantColumns: []string{"SessionId"},
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

func TestCustomUserData_DriverConfigHook(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name           string
		driverHook     func(t *testing.T) (hook func(ctx context.Context, current any) (any, error), codec *dbtype.CustomDataCodec)
		current        any
		wantNilHook    bool
		wantUntypedNil bool
		wantData       *testUserData
		wantErr        bool
	}{
		{
			name: "spanner nil hook stays nil through the bridge",
			driverHook: func(t *testing.T) (func(ctx context.Context, current any) (any, error), *dbtype.CustomDataCodec) {
				t.Helper()

				cfg, err := NewSpannerCustomUserData[testUserData]("UserCustomData", nil)
				if err != nil {
					t.Fatalf("NewSpannerCustomUserData() error = %v", err)
				}

				return hookFunc(cfg.driverConfig())
			},
			wantNilHook: true,
		},
		{
			name: "postgres nil hook stays nil through the bridge",
			driverHook: func(t *testing.T) (func(ctx context.Context, current any) (any, error), *dbtype.CustomDataCodec) {
				t.Helper()

				cfg, err := NewPostgresCustomUserData[testUserData]("UserCustomData", nil)
				if err != nil {
					t.Fatalf("NewPostgresCustomUserData() error = %v", err)
				}

				return hookPostgresFunc(cfg.driverConfig())
			},
			wantNilHook: true,
		},
		{
			name: "nil current crosses as a typed nil *U",
			driverHook: func(t *testing.T) (func(ctx context.Context, current any) (any, error), *dbtype.CustomDataCodec) {
				t.Helper()

				cfg, err := NewSpannerCustomUserData("UserCustomData",
					func(_ context.Context, _ *cloudspanner.ReadWriteTransaction, _ *sessioninfo.NewSessionRequest, current *testUserData) (*testUserData, error) {
						if current != nil {
							return nil, errors.New("expected nil current")
						}

						return &testUserData{Email: "provisioned"}, nil
					})
				if err != nil {
					t.Fatalf("NewSpannerCustomUserData() error = %v", err)
				}

				return hookFunc(cfg.driverConfig())
			},
			wantData: &testUserData{Email: "provisioned"},
		},
		{
			name:    "current row threads through typed",
			current: &testUserData{Email: "old", Theme: "dark"},
			driverHook: func(t *testing.T) (func(ctx context.Context, current any) (any, error), *dbtype.CustomDataCodec) {
				t.Helper()

				cfg, err := NewPostgresCustomUserData("UserCustomData",
					func(_ context.Context, _ pgx.Tx, _ *sessioninfo.NewSessionRequest, current *testUserData) (*testUserData, error) {
						current.Email = "new"

						return current, nil
					})
				if err != nil {
					t.Fatalf("NewPostgresCustomUserData() error = %v", err)
				}

				return hookPostgresFunc(cfg.driverConfig())
			},
			wantData: &testUserData{Email: "new", Theme: "dark"},
		},
		{
			name: "typed nil hook result crosses as untyped nil",
			driverHook: func(t *testing.T) (func(ctx context.Context, current any) (any, error), *dbtype.CustomDataCodec) {
				t.Helper()

				cfg, err := NewSpannerCustomUserData("UserCustomData",
					func(_ context.Context, _ *cloudspanner.ReadWriteTransaction, _ *sessioninfo.NewSessionRequest, _ *testUserData) (*testUserData, error) {
						return nil, nil //nolint:nilnil // typed-nil crossing is the behavior under test
					})
				if err != nil {
					t.Fatalf("NewSpannerCustomUserData() error = %v", err)
				}

				return hookFunc(cfg.driverConfig())
			},
			wantUntypedNil: true,
		},
		{
			name:    "mismatched current type is a clear error",
			current: &testTypedData{},
			driverHook: func(t *testing.T) (func(ctx context.Context, current any) (any, error), *dbtype.CustomDataCodec) {
				t.Helper()

				cfg, err := NewSpannerCustomUserData("UserCustomData",
					func(_ context.Context, _ *cloudspanner.ReadWriteTransaction, _ *sessioninfo.NewSessionRequest, _ *testUserData) (*testUserData, error) {
						return nil, errors.New("hook must not run")
					})
				if err != nil {
					t.Fatalf("NewSpannerCustomUserData() error = %v", err)
				}

				return hookFunc(cfg.driverConfig())
			},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			hook, codec := tt.driverHook(t)
			if codec == nil {
				t.Fatal("driverConfig().Codec is nil")
			}
			if tt.wantNilHook {
				if hook != nil {
					t.Error("driverConfig().Hook != nil, want nil")
				}

				return
			}

			data, err := hook(t.Context(), tt.current)
			if (err != nil) != tt.wantErr {
				t.Fatalf("Hook() error = %v, wantErr = %v", err, tt.wantErr)
			}
			if tt.wantErr {
				return
			}
			if tt.wantUntypedNil {
				if data != nil {
					t.Errorf("Hook() = %v (%T), want untyped nil", data, data)
				}

				return
			}
			typed, ok := data.(*testUserData)
			if !ok {
				t.Fatalf("Hook() = %T, want *testUserData", data)
			}
			if diff := cmp.Diff(tt.wantData, typed); diff != "" {
				t.Errorf("Hook() mismatch (-want +got):\n%s", diff)
			}
		})
	}
}

// hookFunc adapts a spanner driver config to the backend-neutral shape the table runner
// asserts against; a nil Hook stays nil.
func hookFunc(cfg *spanner.CustomUserDataConfig) (func(ctx context.Context, current any) (any, error), *dbtype.CustomDataCodec) {
	if cfg.Hook == nil {
		return nil, cfg.Codec
	}

	return func(ctx context.Context, current any) (any, error) {
		return cfg.Hook(ctx, nil, &sessioninfo.NewSessionRequest{}, current)
	}, cfg.Codec
}

// hookPostgresFunc is the postgres mirror of hookFunc.
func hookPostgresFunc(cfg *postgres.CustomUserDataConfig) (func(ctx context.Context, current any) (any, error), *dbtype.CustomDataCodec) {
	if cfg.Hook == nil {
		return nil, cfg.Codec
	}

	return func(ctx context.Context, current any) (any, error) {
		return cfg.Hook(ctx, nil, &sessioninfo.NewSessionRequest{}, current)
	}, cfg.Codec
}
