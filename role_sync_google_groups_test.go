//go:build !skipAuth

package session

import (
	"testing"

	"github.com/cccteam/session/internal/cloudidentity"
	"github.com/google/go-cmp/cmp"
)

func TestGoogleRoleSyncConfig_roleNames_noSimulatedGroups(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name   string
		prefix string
		groups []string
		want   []string
	}{
		{name: "the simulated lookup's spelling is just a group without the prefix", prefix: "app-", groups: []string{"admin@skipauth.invalid"}, want: nil},
		{name: "a prefixed group at the simulated domain follows the convention like any other", prefix: "app-", groups: []string{"app-admin@skipauth.invalid"}, want: []string{"admin"}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			cfg := GoogleRoleSync(nil, nil, tt.prefix, DirectGroups()).googleConfig()
			groups := newFakeGroups()
			groups.direct["user@example.com"] = tt.groups
			cfg.groups = groups

			got, err := cfg.roleNames(t.Context(), "user@example.com", "token")
			if err != nil {
				t.Fatalf("googleRoleSyncConfig.roleNames() error = %v", err)
			}
			if diff := cmp.Diff(tt.want, got); diff != "" {
				t.Errorf("googleRoleSyncConfig.roleNames() mismatch (-want +got):\n%s", diff)
			}
		})
	}
}

func TestGoogleRoleSync_readsThroughCloudIdentity(t *testing.T) {
	t.Parallel()

	cfg := GoogleRoleSync(nil, nil, "app-", DirectGroups()).googleConfig()
	if _, ok := cfg.groups.(cloudidentity.Lookup); !ok {
		t.Errorf("GoogleRoleSync() reads groups through %T, want cloudidentity.Lookup", cfg.groups)
	}
}
