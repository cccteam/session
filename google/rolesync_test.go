package google

import (
	"testing"

	"github.com/cccteam/session/mock/mock_signin"
	"github.com/cccteam/session/signin"
	"github.com/go-playground/errors/v5"
	"github.com/google/go-cmp/cmp"
	gomock "go.uber.org/mock/gomock"
)

func Test_groupSync_roleNames(t *testing.T) {
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

			cfg := RoleSync(mock_signin.NewMockUserRoleManager(ctrl), tt.groupPrefix, DirectGroups()).groupSync()
			groups := newFakeGroups()
			groups.direct["user@example.com"] = tt.groups
			groups.err = tt.groupsErr
			cfg.groups = groups

			got, err := cfg.roleNames(t.Context(), "user@example.com", "token")
			if (err != nil) != tt.wantErr {
				t.Fatalf("groupSync.roleNames() error = %v, wantErr %v", err, tt.wantErr)
			}
			if diff := cmp.Diff(tt.want, got); diff != "" {
				t.Errorf("groupSync.roleNames() mismatch (-want +got):\n%s", diff)
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

func Test_groupSyncOf_validation(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name          string
		roleSync      func(manager signin.UserRoleManager) RoleSyncConfig
		hostedDomains []string
		wantErr       bool
	}{
		{
			name:          "nil role sync slot is a construction error",
			roleSync:      func(signin.UserRoleManager) RoleSyncConfig { return nil },
			hostedDomains: []string{"example.com"},
			wantErr:       true,
		},
		{
			name: "RoleSync with a nil manager is a construction error",
			roleSync: func(signin.UserRoleManager) RoleSyncConfig {
				return RoleSync(nil, "app-myapp-", DirectGroups())
			},
			hostedDomains: []string{"example.com"},
			wantErr:       true,
		},
		{
			name: "RoleSync with an empty group prefix is a construction error",
			roleSync: func(manager signin.UserRoleManager) RoleSyncConfig {
				return RoleSync(manager, "", DirectGroups())
			},
			hostedDomains: []string{"example.com"},
			wantErr:       true,
		},
		{
			name: "RoleSync with no group lookup is a construction error",
			roleSync: func(manager signin.UserRoleManager) RoleSyncConfig {
				return RoleSync(manager, "app-myapp-", nil)
			},
			hostedDomains: []string{"example.com"},
			wantErr:       true,
		},
		{
			name: "no hostedDomains is a construction error",
			roleSync: func(manager signin.UserRoleManager) RoleSyncConfig {
				return RoleSync(manager, "app-myapp-", DirectGroups())
			},
			hostedDomains: nil,
			wantErr:       true,
		},
		{
			name: "RoleSync with manager, prefix and lookup constructs",
			roleSync: func(manager signin.UserRoleManager) RoleSyncConfig {
				return RoleSync(manager, "app-myapp-", NestedGroups())
			},
			hostedDomains: []string{"example.com"},
		},
		{
			name: "DisableRoleSync constructs",
			roleSync: func(signin.UserRoleManager) RoleSyncConfig {
				return DisableRoleSync()
			},
			hostedDomains: []string{"example.com"},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			manager := mock_signin.NewMockUserRoleManager(gomock.NewController(t))

			_, err := groupSyncOf(tt.roleSync(manager), tt.hostedDomains)
			if (err != nil) != tt.wantErr {
				t.Errorf("groupSyncOf() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func Test_groupSync_userGroups(t *testing.T) {
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

			cfg := RoleSync(nil, "app-", tt.lookup).groupSync()
			groups := newFakeGroups()
			groups.direct["user@example.com"] = []string{"app-admin@example.com"}
			groups.nested["user@example.com"] = []string{"app-admin@example.com", "app-viewer@example.com"}
			cfg.groups = groups

			got, err := cfg.userGroups(t.Context(), "user@example.com", "the-token")
			if err != nil {
				t.Fatalf("groupSync.userGroups() error = %v", err)
			}
			if diff := cmp.Diff(tt.want, got); diff != "" {
				t.Errorf("groupSync.userGroups() mismatch (-want +got):\n%s", diff)
			}
			if groups.mode != tt.wantMode {
				t.Errorf("groupSync.userGroups() ran the %s lookup, want %s", groups.mode, tt.wantMode)
			}
			if groups.token != "the-token" {
				t.Errorf("groupSync.userGroups() passed token %q, want the person's own token", groups.token)
			}
		})
	}
}
