//go:build skipAuth

package session

import (
	"testing"

	"github.com/google/go-cmp/cmp"
)

func TestGoogleRoleSyncConfig_roleNames_simulatedGroups(t *testing.T) {
	tests := []struct {
		name   string
		prefix string
		roles  string
		want   []string
	}{
		{name: "APP_ROLES names the roles outright, whatever the prefix", prefix: "app-lodestar-", roles: "admin,viewer", want: []string{"admin", "viewer"}},
		{name: "a role is read case-insensitively", prefix: "app-", roles: "Admin", want: []string{"admin"}},
		{name: "space around an entry is ignored", prefix: "app-", roles: " admin , viewer ", want: []string{"admin", "viewer"}},
		{name: "empty entries are ignored", prefix: "app-", roles: "admin,,", want: []string{"admin"}},
		{name: "no APP_ROLES, no roles", prefix: "app-", roles: "", want: nil},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Setenv("APP_ROLES", tt.roles)

			got, err := GoogleRoleSync(nil, tt.prefix, DirectGroups()).googleConfig().roleNames(t.Context(), "user@example.com", "")
			if err != nil {
				t.Fatalf("googleRoleSyncConfig.roleNames() error = %v", err)
			}
			if diff := cmp.Diff(tt.want, got); diff != "" {
				t.Errorf("googleRoleSyncConfig.roleNames() mismatch (-want +got):\n%s", diff)
			}
		})
	}
}

func TestGoogleRoleSyncConfig_roleFromGroup_simulated(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name  string
		group string
		want  string
		ok    bool
	}{
		{name: "a simulated group names its role outright", group: "viewer@skipauth.invalid", want: "viewer", ok: true},
		{name: "a real group still follows the naming convention", group: "app-admin@example.com", want: "admin", ok: true},
		{name: "a real group outside the convention is ignored", group: "team-eng@example.com"},
		{name: "an empty simulated role is ignored", group: "@skipauth.invalid"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			got, ok := GoogleRoleSync(nil, "app-", DirectGroups()).googleConfig().roleFromGroup(tt.group)
			if got != tt.want || ok != tt.ok {
				t.Errorf("googleRoleSyncConfig.roleFromGroup(%q) = %q, %v; want %q, %v", tt.group, got, ok, tt.want, tt.ok)
			}
		})
	}
}

func TestGoogleRoleSync_readsTheSimulation(t *testing.T) {
	t.Parallel()

	cfg := GoogleRoleSync(nil, "app-", DirectGroups()).googleConfig()
	if _, ok := cfg.groups.(simulatedGroups); !ok {
		t.Errorf("GoogleRoleSync() reads groups through %T, want the APP_ROLES simulation", cfg.groups)
	}
}
