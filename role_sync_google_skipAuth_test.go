//go:build skipAuth

package session

import (
	"testing"

	"github.com/cccteam/session/mock/mock_session"
	"github.com/google/go-cmp/cmp"
	gomock "go.uber.org/mock/gomock"
)

func TestGoogleRoleSyncConfig_roleNames_simulatedGroups(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name   string
		prefix string
		groups []string
		want   []string
	}{
		{name: "a simulated group names its role outright, whatever the prefix", prefix: "app-lodestar-", groups: []string{"admin@skipauth.invalid", "viewer@skipauth.invalid"}, want: []string{"admin", "viewer"}},
		{name: "a simulated group is read case-insensitively", prefix: "app-", groups: []string{"Admin@SkipAuth.Invalid"}, want: []string{"admin"}},
		{name: "real groups still follow the naming convention", prefix: "app-", groups: []string{"app-admin@example.com", "team-eng@example.com"}, want: []string{"admin"}},
		{name: "simulated and real groups mix", prefix: "app-", groups: []string{"viewer@skipauth.invalid", "app-admin@example.com"}, want: []string{"viewer", "admin"}},
		{name: "an empty simulated role is ignored", prefix: "app-", groups: []string{"@skipauth.invalid"}, want: nil},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			ctrl := gomock.NewController(t)
			groups := mock_session.NewMockGroupsProvider(ctrl)
			groups.EXPECT().UserGroups(gomock.Any(), "user@example.com").Return(tt.groups, nil).Times(1)

			got, err := GoogleRoleSync(nil, nil, tt.prefix, groups).googleConfig().roleNames(t.Context(), "user@example.com")
			if err != nil {
				t.Fatalf("googleRoleSyncConfig.roleNames() error = %v", err)
			}
			if diff := cmp.Diff(tt.want, got); diff != "" {
				t.Errorf("googleRoleSyncConfig.roleNames() mismatch (-want +got):\n%s", diff)
			}
		})
	}
}
