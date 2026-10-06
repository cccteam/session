package session

import (
	"context"
	"slices"
	"testing"

	"github.com/cccteam/ccc/accesstypes"
	"github.com/cccteam/session/mock/mock_session"
	"github.com/go-playground/errors/v5"
	"github.com/google/go-cmp/cmp"
	"github.com/google/go-cmp/cmp/cmpopts"
	gomock "go.uber.org/mock/gomock"
)

// roleWrite is one membership write the fake role store received: which call, where
// the membership is held, and which roles.
type roleWrite struct {
	call  string
	scope accesstypes.PolicyScope
	roles []accesstypes.Role
}

// fakeRoleManager stands in for the role store: roles names the roles that exist in
// each place, held the memberships the user holds, and writes records every
// AddUserRoles and DeleteUserRoles in the order they arrive, so a test can see what
// the sync wrote, where, and in what order. heldErr fails UserRoles, existsErr fails
// RoleExists, addErr fails AddUserRoles and removeErr fails DeleteUserRoles.
type fakeRoleManager struct {
	roles     map[accesstypes.PolicyScope][]accesstypes.Role
	held      accesstypes.RoleCollection
	heldErr   error
	existsErr error
	addErr    error
	removeErr error
	writes    []roleWrite
}

func (f *fakeRoleManager) UserRoles(_ context.Context, _ accesstypes.User, scopes ...accesstypes.PolicyScope) (accesstypes.RoleCollection, error) {
	if len(scopes) > 0 {
		return nil, errors.Newf("the sync asks for every membership the user holds, not for %v", scopes)
	}

	return f.held, f.heldErr
}

func (f *fakeRoleManager) RoleExists(_ context.Context, scope accesstypes.PolicyScope, role accesstypes.Role) (bool, error) {
	if f.existsErr != nil {
		return false, f.existsErr
	}

	return slices.Contains(f.roles[scope], role), nil
}

func (f *fakeRoleManager) AddUserRoles(_ context.Context, scope accesstypes.PolicyScope, _ accesstypes.User, roles ...accesstypes.Role) error {
	f.writes = append(f.writes, roleWrite{call: "AddUserRoles", scope: scope, roles: roles})

	return f.addErr
}

func (f *fakeRoleManager) DeleteUserRoles(_ context.Context, scope accesstypes.PolicyScope, _ accesstypes.User, roles ...accesstypes.Role) error {
	f.writes = append(f.writes, roleWrite{call: "DeleteUserRoles", scope: scope, roles: roles})

	return f.removeErr
}

func TestRoleSyncConfig_reconcile(t *testing.T) {
	t.Parallel()

	global := accesstypes.GlobalPolicyScope()
	every := accesstypes.EveryDomainPolicyScope()
	tenantA := accesstypes.DomainPolicyScope("tenant-a")
	tenantB := accesstypes.DomainPolicyScope("tenant-b")

	tests := []struct {
		name        string
		manager     *fakeRoleManager
		roleNames   []string
		wantWrites  []roleWrite
		wantHasRole bool
		wantErr     bool
	}{
		{
			name:        "a global role is added in the global partition",
			manager:     &fakeRoleManager{roles: map[accesstypes.PolicyScope][]accesstypes.Role{global: {"admin"}}},
			roleNames:   []string{"admin"},
			wantWrites:  []roleWrite{{call: "AddUserRoles", scope: global, roles: []accesstypes.Role{"admin"}}},
			wantHasRole: true,
		},
		{
			name:        "a domain role is added in every tenant domain, not tenant by tenant",
			manager:     &fakeRoleManager{roles: map[accesstypes.PolicyScope][]accesstypes.Role{every: {"viewer"}}},
			roleNames:   []string{"viewer"},
			wantWrites:  []roleWrite{{call: "AddUserRoles", scope: every, roles: []accesstypes.Role{"viewer"}}},
			wantHasRole: true,
		},
		{
			name:      "a role that exists in both places lands in both",
			manager:   &fakeRoleManager{roles: map[accesstypes.PolicyScope][]accesstypes.Role{global: {"auditor"}, every: {"auditor"}}},
			roleNames: []string{"auditor"},
			wantWrites: []roleWrite{
				{call: "AddUserRoles", scope: global, roles: []accesstypes.Role{"auditor"}},
				{call: "AddUserRoles", scope: every, roles: []accesstypes.Role{"auditor"}},
			},
			wantHasRole: true,
		},
		{
			name:        "an unknown name is ignored",
			manager:     &fakeRoleManager{roles: map[accesstypes.PolicyScope][]accesstypes.Role{global: {"admin"}}},
			roleNames:   []string{"nobody", "admin"},
			wantWrites:  []roleWrite{{call: "AddUserRoles", scope: global, roles: []accesstypes.Role{"admin"}}},
			wantHasRole: true,
		},
		{
			name: "a membership already held is left alone",
			manager: &fakeRoleManager{
				roles: map[accesstypes.PolicyScope][]accesstypes.Role{every: {"viewer"}},
				held:  accesstypes.RoleCollection{every: {"viewer"}},
			},
			roleNames:   []string{"viewer"},
			wantHasRole: true,
		},
		{
			name: "a stale membership is removed wherever it is held, a one-domain membership included",
			manager: &fakeRoleManager{
				roles: map[accesstypes.PolicyScope][]accesstypes.Role{global: {"admin"}, every: {"viewer"}},
				held: accesstypes.RoleCollection{
					tenantB: {"viewer"},
					every:   {"stale"},
					tenantA: {"admin"},
					global:  {"admin", "stale"},
				},
			},
			roleNames: []string{"admin", "viewer"},
			// Adds first, then the removals in a fixed order: the global partition, every
			// tenant domain, then the one-domain places by domain.
			wantWrites: []roleWrite{
				{call: "AddUserRoles", scope: every, roles: []accesstypes.Role{"viewer"}},
				{call: "DeleteUserRoles", scope: global, roles: []accesstypes.Role{"stale"}},
				{call: "DeleteUserRoles", scope: every, roles: []accesstypes.Role{"stale"}},
				{call: "DeleteUserRoles", scope: tenantA, roles: []accesstypes.Role{"admin"}},
				{call: "DeleteUserRoles", scope: tenantB, roles: []accesstypes.Role{"viewer"}},
			},
			wantHasRole: true,
		},
		{
			name: "nothing recognized: no role results, and what was held goes",
			manager: &fakeRoleManager{
				roles: map[accesstypes.PolicyScope][]accesstypes.Role{global: {"admin"}},
				held:  accesstypes.RoleCollection{every: {"viewer"}},
			},
			roleNames:   []string{"nobody"},
			wantWrites:  []roleWrite{{call: "DeleteUserRoles", scope: every, roles: []accesstypes.Role{"viewer"}}},
			wantHasRole: false,
		},
		{
			name:        "no names at all is no role",
			manager:     &fakeRoleManager{roles: map[accesstypes.PolicyScope][]accesstypes.Role{global: {"admin"}}},
			roleNames:   nil,
			wantHasRole: false,
		},
		{
			name: "a UserRoles error aborts the sync",
			manager: &fakeRoleManager{
				roles:   map[accesstypes.PolicyScope][]accesstypes.Role{global: {"admin"}},
				heldErr: errors.New("store down"),
			},
			roleNames: []string{"admin"},
			wantErr:   true,
		},
		{
			name: "a RoleExists error aborts the sync before any write",
			manager: &fakeRoleManager{
				roles:     map[accesstypes.PolicyScope][]accesstypes.Role{global: {"admin"}},
				held:      accesstypes.RoleCollection{global: {"stale"}},
				existsErr: errors.New("store blip"),
			},
			roleNames: []string{"admin"},
			wantErr:   true,
		},
		{
			name: "an AddUserRoles error aborts the sync",
			manager: &fakeRoleManager{
				roles:  map[accesstypes.PolicyScope][]accesstypes.Role{global: {"admin"}},
				addErr: errors.New("write refused"),
			},
			roleNames:  []string{"admin"},
			wantWrites: []roleWrite{{call: "AddUserRoles", scope: global, roles: []accesstypes.Role{"admin"}}},
			wantErr:    true,
		},
		{
			name: "a DeleteUserRoles error aborts the sync",
			manager: &fakeRoleManager{
				held:      accesstypes.RoleCollection{every: {"stale"}},
				removeErr: errors.New("write refused"),
			},
			roleNames:  nil,
			wantWrites: []roleWrite{{call: "DeleteUserRoles", scope: every, roles: []accesstypes.Role{"stale"}}},
			wantErr:    true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			r := &roleSyncConfig{manager: tt.manager}
			gotHasRole, err := r.reconcile(t.Context(), "user", tt.roleNames)
			if (err != nil) != tt.wantErr {
				t.Fatalf("roleSyncConfig.reconcile() error = %v, wantErr %v", err, tt.wantErr)
			}
			if gotHasRole != tt.wantHasRole {
				t.Errorf("roleSyncConfig.reconcile() = %v, want %v", gotHasRole, tt.wantHasRole)
			}
			if diff := cmp.Diff(tt.wantWrites, tt.manager.writes, cmp.AllowUnexported(roleWrite{}), cmpopts.EquateComparable(accesstypes.PolicyScope{})); diff != "" {
				t.Errorf("roleSyncConfig.reconcile() writes mismatch (-want +got):\n%s", diff)
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
			name: "nil role sync slot is a construction error",
			roleSync: func(UserRoleManager) RoleSyncConfig {
				return nil
			},
			wantErr: true,
		},
		{
			name: "RoleSync with a nil manager is a construction error",
			roleSync: func(UserRoleManager) RoleSyncConfig {
				return RoleSync(nil)
			},
			wantErr: true,
		},
		{
			name:     "RoleSync with a manager constructs",
			roleSync: RoleSync,
		},
		{
			name: "DisableRoleSync constructs",
			roleSync: func(UserRoleManager) RoleSyncConfig {
				return DisableRoleSync()
			},
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
