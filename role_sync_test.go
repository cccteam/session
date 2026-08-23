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

func TestRoleSyncConfig_syncDomains(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name     string
		provider DomainsProvider
		want     []accesstypes.Domain
		wantErr  bool
	}{
		{
			name:     "nil provider sweeps the global domain only",
			provider: nil,
			want:     []accesstypes.Domain{accesstypes.GlobalDomain},
		},
		{
			name: "provider domains are appended after the implicit global domain",
			provider: func(context.Context) ([]accesstypes.Domain, error) {
				return []accesstypes.Domain{"tenant1", "tenant2"}, nil
			},
			want: []accesstypes.Domain{accesstypes.GlobalDomain, "tenant1", "tenant2"},
		},
		{
			name: "global domain returned by the provider is deduplicated",
			provider: func(context.Context) ([]accesstypes.Domain, error) {
				return []accesstypes.Domain{accesstypes.GlobalDomain, "tenant1"}, nil
			},
			want: []accesstypes.Domain{accesstypes.GlobalDomain, "tenant1"},
		},
		{
			name: "provider error is returned",
			provider: func(context.Context) ([]accesstypes.Domain, error) {
				return nil, errors.New("tenant table unavailable")
			},
			wantErr: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			r := &roleSyncConfig{domains: tt.provider}
			got, err := r.syncDomains(t.Context())
			if (err != nil) != tt.wantErr {
				t.Fatalf("roleSyncConfig.syncDomains() error = %v, wantErr %v", err, tt.wantErr)
			}
			if diff := cmp.Diff(tt.want, got); diff != "" {
				t.Errorf("roleSyncConfig.syncDomains() mismatch (-want +got):\n%s", diff)
			}
		})
	}
}

func TestNewOIDCAzure_roleSyncValidation(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name     string
		roleSync func(manager UserRoleManager) RoleSyncConfig
		wantErr  bool
	}{
		{
			name:     "nil role sync slot is a construction error",
			roleSync: func(UserRoleManager) RoleSyncConfig { return nil },
			wantErr:  true,
		},
		{
			name:     "RoleSync with a nil manager is a construction error",
			roleSync: func(UserRoleManager) RoleSyncConfig { return RoleSync(nil, nil) },
			wantErr:  true,
		},
		{
			name: "RoleSync with a manager and nil provider constructs",
			roleSync: func(manager UserRoleManager) RoleSyncConfig {
				return RoleSync(manager, nil)
			},
		},
		{
			name: "RoleSync with a manager and provider constructs",
			roleSync: func(manager UserRoleManager) RoleSyncConfig {
				return RoleSync(manager, func(context.Context) ([]accesstypes.Domain, error) {
					return []accesstypes.Domain{"tenant1"}, nil
				})
			},
		},
		{
			name:     "DisableRoleSync constructs",
			roleSync: func(UserRoleManager) RoleSyncConfig { return DisableRoleSync() },
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			ctrl := gomock.NewController(t)

			storage := newOIDCStoreMock(ctrl)
			manager := mock_session.NewMockUserRoleManager(ctrl)

			_, err := NewOIDCAzure[NoCustomData, NoCustomData](storage, tt.roleSync(manager), cookieKey, "issuerURL", "clientID", "clientSecret", "redirectURL")
			if (err != nil) != tt.wantErr {
				t.Errorf("NewOIDCAzure() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}
