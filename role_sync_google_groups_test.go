//go:build !skipAuth

package session

import (
	"testing"

	"github.com/cccteam/session/mock/mock_session"
	"github.com/google/go-cmp/cmp"
	gomock "go.uber.org/mock/gomock"
)

func TestGoogleRoleSyncConfig_roleNames_noSimulatedGroups(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name   string
		prefix string
		groups []string
		want   []string
	}{
		{name: "the simulated directory's spelling is just a group without the prefix", prefix: "app-", groups: []string{"admin@skipauth.invalid"}, want: nil},
		{name: "a prefixed group at the simulated domain follows the convention like any other", prefix: "app-", groups: []string{"app-admin@skipauth.invalid"}, want: []string{"admin"}},
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
