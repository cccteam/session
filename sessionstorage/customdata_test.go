package sessionstorage

import (
	"context"
	"reflect"
	"strings"
	"testing"

	cloudspanner "cloud.google.com/go/spanner"
	"github.com/cccteam/session/sessioninfo"
	"github.com/google/go-cmp/cmp"
	"github.com/jackc/pgx/v5"
)

// testMixedTagUserData is reserved under its db tag only.
type testMixedTagUserData struct {
	UserID string `spanner:"Owner" db:"UserId"`
}

func TestNewCustomSessionData(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name        string
		construct   func() (customSessionDataView, error)
		wantErr     string
		wantColumns []string
	}{
		{
			name: "a resolver over pgx.Tx selects PostgreSQL and the db tags",
			construct: func() (customSessionDataView, error) {
				return NewCustomSessionData("SessionCustomData", func(context.Context, pgx.Tx, *sessioninfo.NewSessionRequest) (*testTypedData, error) {
					return nil, nil
				})
			},
			wantColumns: []string{"pg_role", "tenant"},
		},
		{
			name: "a resolver over the Spanner transaction selects Spanner and the spanner tags",
			construct: func() (customSessionDataView, error) {
				return NewCustomSessionData("SessionCustomData", func(context.Context, *cloudspanner.ReadWriteTransaction, *sessioninfo.NewSessionRequest) (*testTypedData, error) {
					return nil, nil
				})
			},
			wantColumns: []string{"SpannerRole", "Tenant"},
		},
		{
			name: "a nil resolver names both types",
			construct: func() (customSessionDataView, error) {
				return NewCustomSessionData[testTypedData, pgx.Tx]("SessionCustomData", nil)
			},
			wantColumns: []string{"pg_role", "tenant"},
		},
		{
			name: "a transaction type of neither driver is refused",
			construct: func() (customSessionDataView, error) {
				return NewCustomSessionData[testTypedData, struct{}]("SessionCustomData", nil)
			},
			wantErr: "neither pgx.Tx",
		},
		{
			name: "an invalid table name is refused",
			construct: func() (customSessionDataView, error) {
				return NewCustomSessionData[testTypedData, pgx.Tx]("Session Custom Data;", nil)
			},
			wantErr: "invalid table name",
		},
		{
			name: "the reserved SessionId column is refused",
			construct: func() (customSessionDataView, error) {
				return NewCustomSessionData[testReservedData, pgx.Tx]("SessionCustomData", nil)
			},
			wantErr: "reserved",
		},
		{
			name: "a type without a persistable field is refused",
			construct: func() (customSessionDataView, error) {
				return NewCustomSessionData[testNoFieldsData, *cloudspanner.ReadWriteTransaction]("SessionCustomData", nil)
			},
			wantErr: "dbtype.NewCustomDataCodec()",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			cfg, err := tt.construct()
			if tt.wantErr != "" {
				if err == nil || !strings.Contains(err.Error(), tt.wantErr) {
					t.Fatalf("NewCustomSessionData() error = %v, want one mentioning %q", err, tt.wantErr)
				}

				return
			}
			if err != nil {
				t.Fatalf("NewCustomSessionData() error = %v", err)
			}
			if cfg.TableName() != "SessionCustomData" || !cmp.Equal(cfg.Columns(), tt.wantColumns) {
				t.Errorf("NewCustomSessionData() = %s %v, want SessionCustomData %v", cfg.TableName(), cfg.Columns(), tt.wantColumns)
			}
		})
	}
}

func TestNewCustomUserData(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name      string
		construct func() (*CustomUserData[testUserData], error)
		wantErr   string
	}{
		{
			name: "a type tagged for both drivers is accepted",
			construct: func() (*CustomUserData[testUserData], error) {
				return NewCustomUserData[testUserData]("UserCustomData")
			},
		},
		{
			name: "an invalid table name is refused",
			construct: func() (*CustomUserData[testUserData], error) {
				return NewCustomUserData[testUserData]("User Custom Data;")
			},
			wantErr: "invalid table name",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			cfg, err := tt.construct()
			if tt.wantErr != "" {
				if err == nil || !strings.Contains(err.Error(), tt.wantErr) {
					t.Fatalf("NewCustomUserData() error = %v, want one mentioning %q", err, tt.wantErr)
				}

				return
			}
			if err != nil {
				t.Fatalf("NewCustomUserData() error = %v", err)
			}
			if cfg.TableName() != "UserCustomData" {
				t.Errorf("TableName() = %s, want UserCustomData", cfg.TableName())
			}
			pgTable, pgCodec := cfg.userData("db")
			spTable, spCodec := cfg.userData("spanner")
			if pgTable != "UserCustomData" || spTable != "UserCustomData" || !cmp.Equal(pgCodec.Columns(), []string{"email", "theme"}) || !cmp.Equal(spCodec.Columns(), []string{"Email", "Theme"}) {
				t.Errorf("userData() = %v / %v, want the db and spanner columns", pgCodec.Columns(), spCodec.Columns())
			}
		})
	}

	// A column reserved under one driver's tags is refused, naming those tags.
	t.Run("a column reserved under the db tags alone is refused", func(t *testing.T) {
		t.Parallel()

		_, err := NewCustomUserData[testMixedTagUserData]("UserCustomData")
		if err == nil || !strings.Contains(err.Error(), "db tags") || !strings.Contains(err.Error(), "reserved") {
			t.Errorf("NewCustomUserData() error = %v, want the reserved UserId refused under the db tags", err)
		}
	})
}

// TestAuth_WithCustomData proves the store's attach methods configure its driver: the
// probes the Auth session checks at construction answer the attached types, no login
// hook is configured, and the resolver reaches the driver typed to its transaction, a
// typed nil crossing as an untyped nil.
func TestAuth_WithCustomData(t *testing.T) {
	t.Parallel()

	t.Run("postgres", func(t *testing.T) {
		t.Parallel()

		var calls int
		sessionData, err := NewCustomSessionData("SessionCustomData", func(_ context.Context, _ pgx.Tx, req *sessioninfo.NewSessionRequest) (*testTypedData, error) {
			calls++
			if req.Username == "none" {
				return nil, nil
			}

			return &testTypedData{Role: "admin", Tenant: req.Username}, nil
		})
		if err != nil {
			t.Fatalf("NewCustomSessionData() error = %v", err)
		}
		userData, err := NewCustomUserData[testUserData]("UserCustomData")
		if err != nil {
			t.Fatalf("NewCustomUserData() error = %v", err)
		}

		store := NewPostgresAuth(nil).WithCustomSessionData(sessionData).WithCustomUserData(userData)
		assertProbes(t, store, reflect.TypeFor[testTypedData](), reflect.TypeFor[testUserData]())

		erased := sessionData.sessionData()
		got, err := erased.resolver(context.Background(), nil, &sessioninfo.NewSessionRequest{Username: "t1"})
		if err != nil || !cmp.Equal(got, &testTypedData{Role: "admin", Tenant: "t1"}) {
			t.Errorf("resolver = %#v, %v; want the typed row", got, err)
		}
		if got, err := erased.resolver(context.Background(), nil, &sessioninfo.NewSessionRequest{Username: "none"}); err != nil || got != nil {
			t.Errorf("resolver of no row = %#v, %v; want an untyped nil", got, err)
		}
		if calls != 2 {
			t.Errorf("resolver ran %d times, want 2", calls)
		}
	})

	t.Run("spanner", func(t *testing.T) {
		t.Parallel()

		sessionData, err := NewCustomSessionData[testTypedData, *cloudspanner.ReadWriteTransaction]("SessionCustomData", nil)
		if err != nil {
			t.Fatalf("NewCustomSessionData() error = %v", err)
		}
		userData, err := NewCustomUserData[testUserData]("UserCustomData")
		if err != nil {
			t.Fatalf("NewCustomUserData() error = %v", err)
		}

		store := NewSpannerAuth(nil).WithCustomSessionData(sessionData).WithCustomUserData(userData)
		assertProbes(t, store, reflect.TypeFor[testTypedData](), reflect.TypeFor[testUserData]())
		if erased := sessionData.sessionData(); erased.resolver != nil {
			t.Error("a nil resolver reached the driver as a function")
		}
	})
}

func assertProbes(t *testing.T, store interface {
	CustomDataType() reflect.Type
	CustomUserDataType() reflect.Type
	UserDataLoginHookConfigured() bool
}, wantSession, wantUser reflect.Type,
) {
	t.Helper()

	if store.CustomDataType() != wantSession || store.CustomUserDataType() != wantUser || store.UserDataLoginHookConfigured() {
		t.Errorf("probes = %v, %v, hook %v; want %v, %v, no hook", store.CustomDataType(), store.CustomUserDataType(), store.UserDataLoginHookConfigured(), wantSession, wantUser)
	}
}
