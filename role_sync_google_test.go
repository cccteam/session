package session

import (
	"context"
	"testing"

	"github.com/cccteam/ccc/accesstypes"
	"github.com/cccteam/session/mock/mock_session"
	"github.com/go-playground/errors/v5"
	"github.com/google/go-cmp/cmp"
	gomock "go.uber.org/mock/gomock"
)

func TestGoogleRoleSyncConfig_roleNames(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name        string
		groupPrefix string
		groups      []string
		groupsErr   error
		want        []string
		wantErr     bool
	}{
		{
			name:        "prefixed groups map to role names",
			groupPrefix: "app-myapp-",
			groups:      []string{"app-myapp-admin@example.com", "app-myapp-viewer@example.com"},
			want:        []string{"admin", "viewer"},
		},
		{
			name:        "unrelated groups are ignored",
			groupPrefix: "app-myapp-",
			groups:      []string{"team-eng@example.com", "app-otherapp-admin@example.com", "everyone@example.com"},
			want:        nil,
		},
		{
			name:        "a bare prefix with no role name is ignored",
			groupPrefix: "app-myapp-",
			groups:      []string{"app-myapp-@example.com"},
			want:        nil,
		},
		{
			name:        "matching is case-insensitive on both sides",
			groupPrefix: "App-MyApp-",
			groups:      []string{"APP-MYAPP-Admin@Example.COM"},
			want:        []string{"admin"},
		},
		{
			name:        "values without an @ are ignored",
			groupPrefix: "app-myapp-",
			groups:      []string{"app-myapp-admin"},
			want:        nil,
		},
		{
			name:        "the prefix must be a prefix of the local part, not a substring",
			groupPrefix: "app-myapp-",
			groups:      []string{"legacy-app-myapp-admin@example.com"},
			want:        nil,
		},
		{
			name:        "a lookup failure propagates",
			groupPrefix: "app-myapp-",
			groupsErr:   errors.New("groups API unavailable"),
			wantErr:     true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			ctrl := gomock.NewController(t)

			cfg := GoogleRoleSync(mock_session.NewMockUserRoleManager(ctrl), nil, tt.groupPrefix, DirectGroups()).googleConfig()
			groups := newFakeGroups()
			groups.direct["user@example.com"] = tt.groups
			groups.err = tt.groupsErr
			cfg.groups = groups

			got, err := cfg.roleNames(t.Context(), "user@example.com", "token")
			if (err != nil) != tt.wantErr {
				t.Fatalf("googleRoleSyncConfig.roleNames() error = %v, wantErr %v", err, tt.wantErr)
			}
			if diff := cmp.Diff(tt.want, got); diff != "" {
				t.Errorf("googleRoleSyncConfig.roleNames() mismatch (-want +got):\n%s", diff)
			}
		})
	}
}

func TestParseGroupLookup(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name    string
		value   string
		want    GroupLookup
		wantErr bool
	}{
		{name: "direct", value: "direct", want: DirectGroups()},
		{name: "nested", value: "nested", want: NestedGroups()},
		{name: "empty is the default, direct", value: "", want: DirectGroups()},
		{name: "case and surrounding space do not matter", value: "  Nested ", want: NestedGroups()},
		{name: "anything else is refused", value: "enterprise", wantErr: true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			got, err := ParseGroupLookup(tt.value)
			if (err != nil) != tt.wantErr {
				t.Fatalf("ParseGroupLookup(%q) error = %v, wantErr %v", tt.value, err, tt.wantErr)
			}
			if got != tt.want {
				t.Errorf("ParseGroupLookup(%q) = %v, want %v", tt.value, got, tt.want)
			}
		})
	}
}

func TestNewOIDCGoogle_validation(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name         string
		roleSync     func(manager UserRoleManager) GoogleRoleSyncConfig
		hostedDomain string
		wantErr      bool
	}{
		{
			name:         "nil role sync slot is a construction error",
			roleSync:     func(UserRoleManager) GoogleRoleSyncConfig { return nil },
			hostedDomain: "example.com",
			wantErr:      true,
		},
		{
			name: "GoogleRoleSync with a nil manager is a construction error",
			roleSync: func(UserRoleManager) GoogleRoleSyncConfig {
				return GoogleRoleSync(nil, nil, "app-myapp-", DirectGroups())
			},
			hostedDomain: "example.com",
			wantErr:      true,
		},
		{
			name: "GoogleRoleSync with an empty group prefix is a construction error",
			roleSync: func(manager UserRoleManager) GoogleRoleSyncConfig {
				return GoogleRoleSync(manager, nil, "", DirectGroups())
			},
			hostedDomain: "example.com",
			wantErr:      true,
		},
		{
			name: "GoogleRoleSync with no group lookup is a construction error",
			roleSync: func(manager UserRoleManager) GoogleRoleSyncConfig {
				return GoogleRoleSync(manager, nil, "app-myapp-", nil)
			},
			hostedDomain: "example.com",
			wantErr:      true,
		},
		{
			name: "empty hostedDomain is a construction error",
			roleSync: func(manager UserRoleManager) GoogleRoleSyncConfig {
				return GoogleRoleSync(manager, nil, "app-myapp-", DirectGroups())
			},
			hostedDomain: "",
			wantErr:      true,
		},
		{
			name: "GoogleRoleSync with manager, prefix, lookup, and domains constructs",
			roleSync: func(manager UserRoleManager) GoogleRoleSyncConfig {
				return GoogleRoleSync(manager, func(context.Context) ([]accesstypes.Domain, error) {
					return []accesstypes.Domain{"tenant1"}, nil
				}, "app-myapp-", NestedGroups())
			},
			hostedDomain: "example.com",
		},
		{
			name: "DisableRoleSync constructs",
			roleSync: func(UserRoleManager) GoogleRoleSyncConfig {
				return DisableRoleSync()
			},
			hostedDomain: "example.com",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			ctrl := gomock.NewController(t)

			storage := newGoogleOIDCStoreMock(ctrl)
			manager := mock_session.NewMockUserRoleManager(ctrl)

			_, err := NewOIDCGoogle[NoCustomData, NoCustomData](storage, tt.roleSync(manager), cookieKey, "clientID", "clientSecret", "redirectURL", tt.hostedDomain)
			if (err != nil) != tt.wantErr {
				t.Errorf("NewOIDCGoogle() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func TestGoogleRoleSyncConfig_userGroups(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name     string
		lookup   GroupLookup
		wantMode string
		want     []string
	}{
		{name: "DirectGroups reads the groups the person is directly in", lookup: DirectGroups(), wantMode: lookupNameDirect, want: []string{"app-admin@example.com"}},
		{name: "NestedGroups reads the groups of the groups too", lookup: NestedGroups(), wantMode: lookupNameNested, want: []string{"app-admin@example.com", "app-viewer@example.com"}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			cfg := GoogleRoleSync(nil, nil, "app-", tt.lookup).googleConfig()
			groups := newFakeGroups()
			groups.direct["user@example.com"] = []string{"app-admin@example.com"}
			groups.nested["user@example.com"] = []string{"app-admin@example.com", "app-viewer@example.com"}
			cfg.groups = groups

			got, err := cfg.userGroups(t.Context(), "user@example.com", "the-token")
			if err != nil {
				t.Fatalf("googleRoleSyncConfig.userGroups() error = %v", err)
			}
			if diff := cmp.Diff(tt.want, got); diff != "" {
				t.Errorf("googleRoleSyncConfig.userGroups() mismatch (-want +got):\n%s", diff)
			}
			if groups.mode != tt.wantMode {
				t.Errorf("googleRoleSyncConfig.userGroups() ran the %s lookup, want %s", groups.mode, tt.wantMode)
			}
			if groups.token != "the-token" {
				t.Errorf("googleRoleSyncConfig.userGroups() passed token %q, want the person's own token", groups.token)
			}
		})
	}
}
