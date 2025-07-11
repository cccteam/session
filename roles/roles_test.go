package roles

import (
	"context"
	"testing"

	"github.com/cccteam/ccc/accesstypes"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
)

// MockUserManager is a mock implementation of the UserManager interface.
type MockUserManager struct {
	mock.Mock
}

func (m *MockUserManager) Domains(ctx context.Context) ([]accesstypes.Domain, error) {
	args := m.Called(ctx)
	return args.Get(0).([]accesstypes.Domain), args.Error(1)
}

func (m *MockUserManager) UserRoles(ctx context.Context, user accesstypes.User, domains ...accesstypes.Domain) (map[accesstypes.Domain][]accesstypes.Role, error) {
	args := m.Called(ctx, user, domains)
	return args.Get(0).(map[accesstypes.Domain][]accesstypes.Role), args.Error(1)
}

func (m *MockUserManager) RoleExists(ctx context.Context, domain accesstypes.Domain, role accesstypes.Role) bool {
	args := m.Called(ctx, domain, role)
	return args.Bool(0)
}

func (m *MockUserManager) AddUserRoles(ctx context.Context, domain accesstypes.Domain, user accesstypes.User, roles ...accesstypes.Role) error {
	args := m.Called(ctx, domain, user, roles)
	return args.Error(0)
}

func (m *MockUserManager) DeleteUserRoles(ctx context.Context, domain accesstypes.Domain, user accesstypes.User, roles ...accesstypes.Role) error {
	args := m.Called(ctx, domain, user, roles)
	return args.Error(0)
}

func TestRoleAssignmentClient_AssignRoles(t *testing.T) {
	ctx := context.Background()
	username := accesstypes.User("testuser")
	domain1 := accesstypes.Domain("domain1")
	role1 := accesstypes.Role("role1")
	role2 := accesstypes.Role("role2")
	role3 := accesstypes.Role("role3")

	tests := []struct {
		name              string
		rolesToAssign     []string
		mockUserMgr       func(m *MockUserManager)
		expectedHasRole   bool
		expectedErr       bool
		expectedAdded     map[accesstypes.Domain][]accesstypes.Role
		expectedRemoved   map[accesstypes.Domain][]accesstypes.Role
	}{
		{
			name:          "assign new roles, user has no existing roles",
			rolesToAssign: []string{"role1", "role2"},
			mockUserMgr: func(m *MockUserManager) {
				m.On("Domains", mock.Anything).Return([]accesstypes.Domain{domain1}, nil).Once()
				m.On("UserRoles", mock.Anything, username, []accesstypes.Domain{domain1}).Return(map[accesstypes.Domain][]accesstypes.Role{domain1: {}}, nil).Once()
				m.On("RoleExists", mock.Anything, domain1, role1).Return(true).Once()
				m.On("RoleExists", mock.Anything, domain1, role2).Return(true).Once()
				m.On("AddUserRoles", mock.Anything, domain1, username, []accesstypes.Role{role1, role2}).Return(nil).Once()
			},
			expectedHasRole: true,
			expectedAdded:   map[accesstypes.Domain][]accesstypes.Role{domain1: {role1, role2}},
		},
		{
			name:          "assign existing roles, no changes",
			rolesToAssign: []string{"role1"},
			mockUserMgr: func(m *MockUserManager) {
				m.On("Domains", mock.Anything).Return([]accesstypes.Domain{domain1}, nil).Once()
				m.On("UserRoles", mock.Anything, username, []accesstypes.Domain{domain1}).Return(map[accesstypes.Domain][]accesstypes.Role{domain1: {role1}}, nil).Once()
				m.On("RoleExists", mock.Anything, domain1, role1).Return(true).Once()
				// No AddUserRoles or DeleteUserRoles should be called
			},
			expectedHasRole: true,
		},
		{
			name:          "remove roles, assign new ones",
			rolesToAssign: []string{"role2", "role3"},
			mockUserMgr: func(m *MockUserManager) {
				m.On("Domains", mock.Anything).Return([]accesstypes.Domain{domain1}, nil).Once()
				m.On("UserRoles", mock.Anything, username, []accesstypes.Domain{domain1}).Return(map[accesstypes.Domain][]accesstypes.Role{domain1: {role1, role2}}, nil).Once()
				m.On("RoleExists", mock.Anything, domain1, role2).Return(true).Once()
				m.On("RoleExists", mock.Anything, domain1, role3).Return(true).Once()
				m.On("AddUserRoles", mock.Anything, domain1, username, []accesstypes.Role{role3}).Return(nil).Once()
				m.On("DeleteUserRoles", mock.Anything, domain1, username, []accesstypes.Role{role1}).Return(nil).Once()
			},
			expectedHasRole: true,
			expectedAdded:   map[accesstypes.Domain][]accesstypes.Role{domain1: {role3}},
			expectedRemoved: map[accesstypes.Domain][]accesstypes.Role{domain1: {role1}},
		},
		{
			name:          "assign roles, one does not exist in domain",
			rolesToAssign: []string{"role1", "nonexistentrole"},
			mockUserMgr: func(m *MockUserManager) {
				m.On("Domains", mock.Anything).Return([]accesstypes.Domain{domain1}, nil).Once()
				m.On("UserRoles", mock.Anything, username, []accesstypes.Domain{domain1}).Return(map[accesstypes.Domain][]accesstypes.Role{domain1: {}}, nil).Once()
				m.On("RoleExists", mock.Anything, domain1, role1).Return(true).Once()
				m.On("RoleExists", mock.Anything, domain1, accesstypes.Role("nonexistentrole")).Return(false).Once()
				m.On("AddUserRoles", mock.Anything, domain1, username, []accesstypes.Role{role1}).Return(nil).Once()
			},
			expectedHasRole: true,
			expectedAdded:   map[accesstypes.Domain][]accesstypes.Role{domain1: {role1}},
		},
		{
			name:          "no roles to assign, user loses all roles",
			rolesToAssign: []string{},
			mockUserMgr: func(m *MockUserManager) {
				m.On("Domains", mock.Anything).Return([]accesstypes.Domain{domain1}, nil).Once()
				m.On("UserRoles", mock.Anything, username, []accesstypes.Domain{domain1}).Return(map[accesstypes.Domain][]accesstypes.Role{domain1: {role1}}, nil).Once()
				m.On("DeleteUserRoles", mock.Anything, domain1, username, []accesstypes.Role{role1}).Return(nil).Once()
			},
			expectedHasRole: false,
			expectedRemoved: map[accesstypes.Domain][]accesstypes.Role{domain1: {role1}},
		},
		// Add more test cases for errors, multiple domains, etc.
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mockUserMgr := new(MockUserManager)
			tt.mockUserMgr(mockUserMgr)

			client := NewRoleAssignmentClient(mockUserMgr)
			hasRole, err := client.AssignRoles(ctx, username, tt.rolesToAssign)

			assert.Equal(t, tt.expectedHasRole, hasRole)
			if tt.expectedErr {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
			}

			mockUserMgr.AssertExpectations(t)

			// Verify AddUserRoles calls
			if tt.expectedAdded != nil {
				for domain, roles := range tt.expectedAdded {
					mockUserMgr.AssertCalled(t, "AddUserRoles", mock.AnythingOfType("*context.valueCtx"), domain, username, roles)
				}
			}

			// Verify DeleteUserRoles calls
			if tt.expectedRemoved != nil {
				for domain, roles := range tt.expectedRemoved {
					mockUserMgr.AssertCalled(t, "DeleteUserRoles", mock.AnythingOfType("*context.valueCtx"), domain, username, roles)
				}
			}
		})
	}
}
