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
			name:        "provider errors propagate",
			groupPrefix: "app-myapp-",
			groupsErr:   errors.New("groups API unavailable"),
			wantErr:     true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			ctrl := gomock.NewController(t)

			groups := mock_session.NewMockGroupsProvider(ctrl)
			groups.EXPECT().UserGroups(gomock.Any(), "user@example.com").Return(tt.groups, tt.groupsErr).Times(1)

			cfg := GoogleRoleSync(mock_session.NewMockUserRoleManager(ctrl), nil, tt.groupPrefix, groups).googleConfig()

			got, err := cfg.roleNames(t.Context(), "user@example.com")
			if (err != nil) != tt.wantErr {
				t.Fatalf("googleRoleSyncConfig.roleNames() error = %v, wantErr %v", err, tt.wantErr)
			}
			if diff := cmp.Diff(tt.want, got); diff != "" {
				t.Errorf("googleRoleSyncConfig.roleNames() mismatch (-want +got):\n%s", diff)
			}
		})
	}
}

func TestNewOIDCGoogle_validation(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name         string
		roleSync     func(manager UserRoleManager, groups GroupsProvider) GoogleRoleSyncConfig
		hostedDomain string
		wantErr      bool
	}{
		{
			name:         "nil role sync slot is a construction error",
			roleSync:     func(UserRoleManager, GroupsProvider) GoogleRoleSyncConfig { return nil },
			hostedDomain: "example.com",
			wantErr:      true,
		},
		{
			name: "GoogleRoleSync with a nil manager is a construction error",
			roleSync: func(_ UserRoleManager, groups GroupsProvider) GoogleRoleSyncConfig {
				return GoogleRoleSync(nil, nil, "app-myapp-", groups)
			},
			hostedDomain: "example.com",
			wantErr:      true,
		},
		{
			name: "GoogleRoleSync with an empty group prefix is a construction error",
			roleSync: func(manager UserRoleManager, groups GroupsProvider) GoogleRoleSyncConfig {
				return GoogleRoleSync(manager, nil, "", groups)
			},
			hostedDomain: "example.com",
			wantErr:      true,
		},
		{
			name: "GoogleRoleSync with a nil groups provider is a construction error",
			roleSync: func(manager UserRoleManager, _ GroupsProvider) GoogleRoleSyncConfig {
				return GoogleRoleSync(manager, nil, "app-myapp-", nil)
			},
			hostedDomain: "example.com",
			wantErr:      true,
		},
		{
			name: "empty hostedDomain is a construction error",
			roleSync: func(manager UserRoleManager, groups GroupsProvider) GoogleRoleSyncConfig {
				return GoogleRoleSync(manager, nil, "app-myapp-", groups)
			},
			hostedDomain: "",
			wantErr:      true,
		},
		{
			name: "GoogleRoleSync with manager, prefix, provider, and domains constructs",
			roleSync: func(manager UserRoleManager, groups GroupsProvider) GoogleRoleSyncConfig {
				return GoogleRoleSync(manager, func(context.Context) ([]accesstypes.Domain, error) {
					return []accesstypes.Domain{"tenant1"}, nil
				}, "app-myapp-", groups)
			},
			hostedDomain: "example.com",
		},
		{
			name: "DisableRoleSync constructs",
			roleSync: func(UserRoleManager, GroupsProvider) GoogleRoleSyncConfig {
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
			groups := mock_session.NewMockGroupsProvider(ctrl)

			_, err := NewOIDCGoogle[NoCustomData, NoCustomData](storage, tt.roleSync(manager, groups), cookieKey, "clientID", "clientSecret", "redirectURL", tt.hostedDomain)
			if (err != nil) != tt.wantErr {
				t.Errorf("NewOIDCGoogle() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}
