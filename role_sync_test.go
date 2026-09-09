package session

import (
	"context"
	"testing"

	"github.com/cccteam/ccc/accesstypes"
	"github.com/cccteam/session/mock/mock_session"

	"github.com/go-playground/errors/v5"
	"github.com/google/go-cmp/cmp"
	"github.com/google/go-cmp/cmp/cmpopts"
	gomock "go.uber.org/mock/gomock"
)

func TestRoleSyncConfig_syncScopes(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name     string
		provider DomainsProvider
		want     []accesstypes.Scope
		wantErr  bool
	}{
		{
			name:     "nil provider sweeps the global scope only",
			provider: nil,
			want:     []accesstypes.Scope{accesstypes.GlobalScope()},
		},
		{
			name: "provider domains are appended as tenant scopes after the implicit global scope",
			provider: func(context.Context) ([]accesstypes.Domain, error) {
				return []accesstypes.Domain{"tenant1", "tenant2"}, nil
			},
			want: []accesstypes.Scope{accesstypes.GlobalScope(), accesstypes.DomainScope("tenant1"), accesstypes.DomainScope("tenant2")},
		},
		{
			// Tenant names are pure data: a provider returning the retired
			// sentinel spelling gets an ordinary tenant scope, never the
			// global partition.
			name: "sentinel-shaped names are ordinary tenant scopes",
			provider: func(context.Context) ([]accesstypes.Domain, error) {
				return []accesstypes.Domain{"global", "access:global"}, nil
			},
			want: []accesstypes.Scope{accesstypes.GlobalScope(), accesstypes.DomainScope("global"), accesstypes.DomainScope("access:global")},
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
			got, err := r.syncScopes(t.Context())
			if (err != nil) != tt.wantErr {
				t.Fatalf("roleSyncConfig.syncScopes() error = %v, wantErr %v", err, tt.wantErr)
			}
			if diff := cmp.Diff(tt.want, got, cmpopts.EquateComparable(accesstypes.Scope{})); diff != "" {
				t.Errorf("roleSyncConfig.syncScopes() mismatch (-want +got):\n%s", diff)
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
