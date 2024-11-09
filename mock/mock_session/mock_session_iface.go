// Code generated by MockGen. DO NOT EDIT.
// Source: ../session_iface.go
//
// Generated by this command:
//
//	mockgen -source ../session_iface.go -destination mock_session/mock_session_iface.go
//

// Package mock_session is a generated GoMock package.
package mock_session

import (
	context "context"
	http "net/http"
	reflect "reflect"

	ccc "github.com/cccteam/ccc"
	accesstypes "github.com/cccteam/ccc/accesstypes"
	dbtypes "github.com/cccteam/session/dbtypes"
	sessioninfo "github.com/cccteam/session/sessioninfo"
	gomock "go.uber.org/mock/gomock"
)

// MockUserManager is a mock of UserManager interface.
type MockUserManager struct {
	ctrl     *gomock.Controller
	recorder *MockUserManagerMockRecorder
	isgomock struct{}
}

// MockUserManagerMockRecorder is the mock recorder for MockUserManager.
type MockUserManagerMockRecorder struct {
	mock *MockUserManager
}

// NewMockUserManager creates a new mock instance.
func NewMockUserManager(ctrl *gomock.Controller) *MockUserManager {
	mock := &MockUserManager{ctrl: ctrl}
	mock.recorder = &MockUserManagerMockRecorder{mock}
	return mock
}

// EXPECT returns an object that allows the caller to indicate expected use.
func (m *MockUserManager) EXPECT() *MockUserManagerMockRecorder {
	return m.recorder
}

// AddUserRoles mocks base method.
func (m *MockUserManager) AddUserRoles(ctx context.Context, domain accesstypes.Domain, user accesstypes.User, roles ...accesstypes.Role) error {
	m.ctrl.T.Helper()
	varargs := []any{ctx, domain, user}
	for _, a := range roles {
		varargs = append(varargs, a)
	}
	ret := m.ctrl.Call(m, "AddUserRoles", varargs...)
	ret0, _ := ret[0].(error)
	return ret0
}

// AddUserRoles indicates an expected call of AddUserRoles.
func (mr *MockUserManagerMockRecorder) AddUserRoles(ctx, domain, user any, roles ...any) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	varargs := append([]any{ctx, domain, user}, roles...)
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "AddUserRoles", reflect.TypeOf((*MockUserManager)(nil).AddUserRoles), varargs...)
}

// DeleteUserRoles mocks base method.
func (m *MockUserManager) DeleteUserRoles(ctx context.Context, domain accesstypes.Domain, user accesstypes.User, roles ...accesstypes.Role) error {
	m.ctrl.T.Helper()
	varargs := []any{ctx, domain, user}
	for _, a := range roles {
		varargs = append(varargs, a)
	}
	ret := m.ctrl.Call(m, "DeleteUserRoles", varargs...)
	ret0, _ := ret[0].(error)
	return ret0
}

// DeleteUserRoles indicates an expected call of DeleteUserRoles.
func (mr *MockUserManagerMockRecorder) DeleteUserRoles(ctx, domain, user any, roles ...any) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	varargs := append([]any{ctx, domain, user}, roles...)
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "DeleteUserRoles", reflect.TypeOf((*MockUserManager)(nil).DeleteUserRoles), varargs...)
}

// Domains mocks base method.
func (m *MockUserManager) Domains(ctx context.Context) ([]accesstypes.Domain, error) {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "Domains", ctx)
	ret0, _ := ret[0].([]accesstypes.Domain)
	ret1, _ := ret[1].(error)
	return ret0, ret1
}

// Domains indicates an expected call of Domains.
func (mr *MockUserManagerMockRecorder) Domains(ctx any) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "Domains", reflect.TypeOf((*MockUserManager)(nil).Domains), ctx)
}

// RoleExists mocks base method.
func (m *MockUserManager) RoleExists(ctx context.Context, domain accesstypes.Domain, role accesstypes.Role) bool {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "RoleExists", ctx, domain, role)
	ret0, _ := ret[0].(bool)
	return ret0
}

// RoleExists indicates an expected call of RoleExists.
func (mr *MockUserManagerMockRecorder) RoleExists(ctx, domain, role any) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "RoleExists", reflect.TypeOf((*MockUserManager)(nil).RoleExists), ctx, domain, role)
}

// UserPermissions mocks base method.
func (m *MockUserManager) UserPermissions(ctx context.Context, user accesstypes.User, domains ...accesstypes.Domain) (accesstypes.UserPermissionCollection, error) {
	m.ctrl.T.Helper()
	varargs := []any{ctx, user}
	for _, a := range domains {
		varargs = append(varargs, a)
	}
	ret := m.ctrl.Call(m, "UserPermissions", varargs...)
	ret0, _ := ret[0].(accesstypes.UserPermissionCollection)
	ret1, _ := ret[1].(error)
	return ret0, ret1
}

// UserPermissions indicates an expected call of UserPermissions.
func (mr *MockUserManagerMockRecorder) UserPermissions(ctx, user any, domains ...any) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	varargs := append([]any{ctx, user}, domains...)
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "UserPermissions", reflect.TypeOf((*MockUserManager)(nil).UserPermissions), varargs...)
}

// UserRoles mocks base method.
func (m *MockUserManager) UserRoles(ctx context.Context, user accesstypes.User, domains ...accesstypes.Domain) (accesstypes.RoleCollection, error) {
	m.ctrl.T.Helper()
	varargs := []any{ctx, user}
	for _, a := range domains {
		varargs = append(varargs, a)
	}
	ret := m.ctrl.Call(m, "UserRoles", varargs...)
	ret0, _ := ret[0].(accesstypes.RoleCollection)
	ret1, _ := ret[1].(error)
	return ret0, ret1
}

// UserRoles indicates an expected call of UserRoles.
func (mr *MockUserManagerMockRecorder) UserRoles(ctx, user any, domains ...any) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	varargs := append([]any{ctx, user}, domains...)
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "UserRoles", reflect.TypeOf((*MockUserManager)(nil).UserRoles), varargs...)
}

// MockUserPermissionManager is a mock of UserPermissionManager interface.
type MockUserPermissionManager struct {
	ctrl     *gomock.Controller
	recorder *MockUserPermissionManagerMockRecorder
	isgomock struct{}
}

// MockUserPermissionManagerMockRecorder is the mock recorder for MockUserPermissionManager.
type MockUserPermissionManagerMockRecorder struct {
	mock *MockUserPermissionManager
}

// NewMockUserPermissionManager creates a new mock instance.
func NewMockUserPermissionManager(ctrl *gomock.Controller) *MockUserPermissionManager {
	mock := &MockUserPermissionManager{ctrl: ctrl}
	mock.recorder = &MockUserPermissionManagerMockRecorder{mock}
	return mock
}

// EXPECT returns an object that allows the caller to indicate expected use.
func (m *MockUserPermissionManager) EXPECT() *MockUserPermissionManagerMockRecorder {
	return m.recorder
}

// UserPermissions mocks base method.
func (m *MockUserPermissionManager) UserPermissions(ctx context.Context, user accesstypes.User, domains ...accesstypes.Domain) (accesstypes.UserPermissionCollection, error) {
	m.ctrl.T.Helper()
	varargs := []any{ctx, user}
	for _, a := range domains {
		varargs = append(varargs, a)
	}
	ret := m.ctrl.Call(m, "UserPermissions", varargs...)
	ret0, _ := ret[0].(accesstypes.UserPermissionCollection)
	ret1, _ := ret[1].(error)
	return ret0, ret1
}

// UserPermissions indicates an expected call of UserPermissions.
func (mr *MockUserPermissionManagerMockRecorder) UserPermissions(ctx, user any, domains ...any) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	varargs := append([]any{ctx, user}, domains...)
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "UserPermissions", reflect.TypeOf((*MockUserPermissionManager)(nil).UserPermissions), varargs...)
}

// MockstorageManager is a mock of storageManager interface.
type MockstorageManager struct {
	ctrl     *gomock.Controller
	recorder *MockstorageManagerMockRecorder
	isgomock struct{}
}

// MockstorageManagerMockRecorder is the mock recorder for MockstorageManager.
type MockstorageManagerMockRecorder struct {
	mock *MockstorageManager
}

// NewMockstorageManager creates a new mock instance.
func NewMockstorageManager(ctrl *gomock.Controller) *MockstorageManager {
	mock := &MockstorageManager{ctrl: ctrl}
	mock.recorder = &MockstorageManagerMockRecorder{mock}
	return mock
}

// EXPECT returns an object that allows the caller to indicate expected use.
func (m *MockstorageManager) EXPECT() *MockstorageManagerMockRecorder {
	return m.recorder
}

// DestroySession mocks base method.
func (m *MockstorageManager) DestroySession(ctx context.Context, sessionID ccc.UUID) error {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "DestroySession", ctx, sessionID)
	ret0, _ := ret[0].(error)
	return ret0
}

// DestroySession indicates an expected call of DestroySession.
func (mr *MockstorageManagerMockRecorder) DestroySession(ctx, sessionID any) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "DestroySession", reflect.TypeOf((*MockstorageManager)(nil).DestroySession), ctx, sessionID)
}

// Session mocks base method.
func (m *MockstorageManager) Session(ctx context.Context, sessionID ccc.UUID) (*sessioninfo.SessionInfo, error) {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "Session", ctx, sessionID)
	ret0, _ := ret[0].(*sessioninfo.SessionInfo)
	ret1, _ := ret[1].(error)
	return ret0, ret1
}

// Session indicates an expected call of Session.
func (mr *MockstorageManagerMockRecorder) Session(ctx, sessionID any) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "Session", reflect.TypeOf((*MockstorageManager)(nil).Session), ctx, sessionID)
}

// UpdateSessionActivity mocks base method.
func (m *MockstorageManager) UpdateSessionActivity(ctx context.Context, sessionID ccc.UUID) error {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "UpdateSessionActivity", ctx, sessionID)
	ret0, _ := ret[0].(error)
	return ret0
}

// UpdateSessionActivity indicates an expected call of UpdateSessionActivity.
func (mr *MockstorageManagerMockRecorder) UpdateSessionActivity(ctx, sessionID any) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "UpdateSessionActivity", reflect.TypeOf((*MockstorageManager)(nil).UpdateSessionActivity), ctx, sessionID)
}

// MockOIDCAzureSessionStorage is a mock of OIDCAzureSessionStorage interface.
type MockOIDCAzureSessionStorage struct {
	ctrl     *gomock.Controller
	recorder *MockOIDCAzureSessionStorageMockRecorder
	isgomock struct{}
}

// MockOIDCAzureSessionStorageMockRecorder is the mock recorder for MockOIDCAzureSessionStorage.
type MockOIDCAzureSessionStorageMockRecorder struct {
	mock *MockOIDCAzureSessionStorage
}

// NewMockOIDCAzureSessionStorage creates a new mock instance.
func NewMockOIDCAzureSessionStorage(ctrl *gomock.Controller) *MockOIDCAzureSessionStorage {
	mock := &MockOIDCAzureSessionStorage{ctrl: ctrl}
	mock.recorder = &MockOIDCAzureSessionStorageMockRecorder{mock}
	return mock
}

// EXPECT returns an object that allows the caller to indicate expected use.
func (m *MockOIDCAzureSessionStorage) EXPECT() *MockOIDCAzureSessionStorageMockRecorder {
	return m.recorder
}

// DestroySession mocks base method.
func (m *MockOIDCAzureSessionStorage) DestroySession(ctx context.Context, sessionID ccc.UUID) error {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "DestroySession", ctx, sessionID)
	ret0, _ := ret[0].(error)
	return ret0
}

// DestroySession indicates an expected call of DestroySession.
func (mr *MockOIDCAzureSessionStorageMockRecorder) DestroySession(ctx, sessionID any) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "DestroySession", reflect.TypeOf((*MockOIDCAzureSessionStorage)(nil).DestroySession), ctx, sessionID)
}

// DestroySessionOIDC mocks base method.
func (m *MockOIDCAzureSessionStorage) DestroySessionOIDC(ctx context.Context, oidcSID string) error {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "DestroySessionOIDC", ctx, oidcSID)
	ret0, _ := ret[0].(error)
	return ret0
}

// DestroySessionOIDC indicates an expected call of DestroySessionOIDC.
func (mr *MockOIDCAzureSessionStorageMockRecorder) DestroySessionOIDC(ctx, oidcSID any) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "DestroySessionOIDC", reflect.TypeOf((*MockOIDCAzureSessionStorage)(nil).DestroySessionOIDC), ctx, oidcSID)
}

// NewSession mocks base method.
func (m *MockOIDCAzureSessionStorage) NewSession(ctx context.Context, username, oidcSID string) (ccc.UUID, error) {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "NewSession", ctx, username, oidcSID)
	ret0, _ := ret[0].(ccc.UUID)
	ret1, _ := ret[1].(error)
	return ret0, ret1
}

// NewSession indicates an expected call of NewSession.
func (mr *MockOIDCAzureSessionStorageMockRecorder) NewSession(ctx, username, oidcSID any) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "NewSession", reflect.TypeOf((*MockOIDCAzureSessionStorage)(nil).NewSession), ctx, username, oidcSID)
}

// Session mocks base method.
func (m *MockOIDCAzureSessionStorage) Session(ctx context.Context, sessionID ccc.UUID) (*sessioninfo.SessionInfo, error) {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "Session", ctx, sessionID)
	ret0, _ := ret[0].(*sessioninfo.SessionInfo)
	ret1, _ := ret[1].(error)
	return ret0, ret1
}

// Session indicates an expected call of Session.
func (mr *MockOIDCAzureSessionStorageMockRecorder) Session(ctx, sessionID any) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "Session", reflect.TypeOf((*MockOIDCAzureSessionStorage)(nil).Session), ctx, sessionID)
}

// UpdateSessionActivity mocks base method.
func (m *MockOIDCAzureSessionStorage) UpdateSessionActivity(ctx context.Context, sessionID ccc.UUID) error {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "UpdateSessionActivity", ctx, sessionID)
	ret0, _ := ret[0].(error)
	return ret0
}

// UpdateSessionActivity indicates an expected call of UpdateSessionActivity.
func (mr *MockOIDCAzureSessionStorageMockRecorder) UpdateSessionActivity(ctx, sessionID any) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "UpdateSessionActivity", reflect.TypeOf((*MockOIDCAzureSessionStorage)(nil).UpdateSessionActivity), ctx, sessionID)
}

// MockPreauthSessionStorage is a mock of PreauthSessionStorage interface.
type MockPreauthSessionStorage struct {
	ctrl     *gomock.Controller
	recorder *MockPreauthSessionStorageMockRecorder
	isgomock struct{}
}

// MockPreauthSessionStorageMockRecorder is the mock recorder for MockPreauthSessionStorage.
type MockPreauthSessionStorageMockRecorder struct {
	mock *MockPreauthSessionStorage
}

// NewMockPreauthSessionStorage creates a new mock instance.
func NewMockPreauthSessionStorage(ctrl *gomock.Controller) *MockPreauthSessionStorage {
	mock := &MockPreauthSessionStorage{ctrl: ctrl}
	mock.recorder = &MockPreauthSessionStorageMockRecorder{mock}
	return mock
}

// EXPECT returns an object that allows the caller to indicate expected use.
func (m *MockPreauthSessionStorage) EXPECT() *MockPreauthSessionStorageMockRecorder {
	return m.recorder
}

// DestroySession mocks base method.
func (m *MockPreauthSessionStorage) DestroySession(ctx context.Context, sessionID ccc.UUID) error {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "DestroySession", ctx, sessionID)
	ret0, _ := ret[0].(error)
	return ret0
}

// DestroySession indicates an expected call of DestroySession.
func (mr *MockPreauthSessionStorageMockRecorder) DestroySession(ctx, sessionID any) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "DestroySession", reflect.TypeOf((*MockPreauthSessionStorage)(nil).DestroySession), ctx, sessionID)
}

// NewSession mocks base method.
func (m *MockPreauthSessionStorage) NewSession(ctx context.Context, username string) (ccc.UUID, error) {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "NewSession", ctx, username)
	ret0, _ := ret[0].(ccc.UUID)
	ret1, _ := ret[1].(error)
	return ret0, ret1
}

// NewSession indicates an expected call of NewSession.
func (mr *MockPreauthSessionStorageMockRecorder) NewSession(ctx, username any) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "NewSession", reflect.TypeOf((*MockPreauthSessionStorage)(nil).NewSession), ctx, username)
}

// Session mocks base method.
func (m *MockPreauthSessionStorage) Session(ctx context.Context, sessionID ccc.UUID) (*sessioninfo.SessionInfo, error) {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "Session", ctx, sessionID)
	ret0, _ := ret[0].(*sessioninfo.SessionInfo)
	ret1, _ := ret[1].(error)
	return ret0, ret1
}

// Session indicates an expected call of Session.
func (mr *MockPreauthSessionStorageMockRecorder) Session(ctx, sessionID any) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "Session", reflect.TypeOf((*MockPreauthSessionStorage)(nil).Session), ctx, sessionID)
}

// UpdateSessionActivity mocks base method.
func (m *MockPreauthSessionStorage) UpdateSessionActivity(ctx context.Context, sessionID ccc.UUID) error {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "UpdateSessionActivity", ctx, sessionID)
	ret0, _ := ret[0].(error)
	return ret0
}

// UpdateSessionActivity indicates an expected call of UpdateSessionActivity.
func (mr *MockPreauthSessionStorageMockRecorder) UpdateSessionActivity(ctx, sessionID any) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "UpdateSessionActivity", reflect.TypeOf((*MockPreauthSessionStorage)(nil).UpdateSessionActivity), ctx, sessionID)
}

// MocksessionHandlers is a mock of sessionHandlers interface.
type MocksessionHandlers struct {
	ctrl     *gomock.Controller
	recorder *MocksessionHandlersMockRecorder
	isgomock struct{}
}

// MocksessionHandlersMockRecorder is the mock recorder for MocksessionHandlers.
type MocksessionHandlersMockRecorder struct {
	mock *MocksessionHandlers
}

// NewMocksessionHandlers creates a new mock instance.
func NewMocksessionHandlers(ctrl *gomock.Controller) *MocksessionHandlers {
	mock := &MocksessionHandlers{ctrl: ctrl}
	mock.recorder = &MocksessionHandlersMockRecorder{mock}
	return mock
}

// EXPECT returns an object that allows the caller to indicate expected use.
func (m *MocksessionHandlers) EXPECT() *MocksessionHandlersMockRecorder {
	return m.recorder
}

// Authenticated mocks base method.
func (m *MocksessionHandlers) Authenticated() http.HandlerFunc {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "Authenticated")
	ret0, _ := ret[0].(http.HandlerFunc)
	return ret0
}

// Authenticated indicates an expected call of Authenticated.
func (mr *MocksessionHandlersMockRecorder) Authenticated() *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "Authenticated", reflect.TypeOf((*MocksessionHandlers)(nil).Authenticated))
}

// Logout mocks base method.
func (m *MocksessionHandlers) Logout() http.HandlerFunc {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "Logout")
	ret0, _ := ret[0].(http.HandlerFunc)
	return ret0
}

// Logout indicates an expected call of Logout.
func (mr *MocksessionHandlersMockRecorder) Logout() *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "Logout", reflect.TypeOf((*MocksessionHandlers)(nil).Logout))
}

// SetSessionTimeout mocks base method.
func (m *MocksessionHandlers) SetSessionTimeout(next http.Handler) http.Handler {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "SetSessionTimeout", next)
	ret0, _ := ret[0].(http.Handler)
	return ret0
}

// SetSessionTimeout indicates an expected call of SetSessionTimeout.
func (mr *MocksessionHandlersMockRecorder) SetSessionTimeout(next any) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "SetSessionTimeout", reflect.TypeOf((*MocksessionHandlers)(nil).SetSessionTimeout), next)
}

// SetXSRFToken mocks base method.
func (m *MocksessionHandlers) SetXSRFToken(next http.Handler) http.Handler {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "SetXSRFToken", next)
	ret0, _ := ret[0].(http.Handler)
	return ret0
}

// SetXSRFToken indicates an expected call of SetXSRFToken.
func (mr *MocksessionHandlersMockRecorder) SetXSRFToken(next any) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "SetXSRFToken", reflect.TypeOf((*MocksessionHandlers)(nil).SetXSRFToken), next)
}

// StartSession mocks base method.
func (m *MocksessionHandlers) StartSession(next http.Handler) http.Handler {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "StartSession", next)
	ret0, _ := ret[0].(http.Handler)
	return ret0
}

// StartSession indicates an expected call of StartSession.
func (mr *MocksessionHandlersMockRecorder) StartSession(next any) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "StartSession", reflect.TypeOf((*MocksessionHandlers)(nil).StartSession), next)
}

// ValidateSession mocks base method.
func (m *MocksessionHandlers) ValidateSession(next http.Handler) http.Handler {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "ValidateSession", next)
	ret0, _ := ret[0].(http.Handler)
	return ret0
}

// ValidateSession indicates an expected call of ValidateSession.
func (mr *MocksessionHandlersMockRecorder) ValidateSession(next any) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "ValidateSession", reflect.TypeOf((*MocksessionHandlers)(nil).ValidateSession), next)
}

// ValidateXSRFToken mocks base method.
func (m *MocksessionHandlers) ValidateXSRFToken(next http.Handler) http.Handler {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "ValidateXSRFToken", next)
	ret0, _ := ret[0].(http.Handler)
	return ret0
}

// ValidateXSRFToken indicates an expected call of ValidateXSRFToken.
func (mr *MocksessionHandlersMockRecorder) ValidateXSRFToken(next any) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "ValidateXSRFToken", reflect.TypeOf((*MocksessionHandlers)(nil).ValidateXSRFToken), next)
}

// MockDB is a mock of DB interface.
type MockDB struct {
	ctrl     *gomock.Controller
	recorder *MockDBMockRecorder
	isgomock struct{}
}

// MockDBMockRecorder is the mock recorder for MockDB.
type MockDBMockRecorder struct {
	mock *MockDB
}

// NewMockDB creates a new mock instance.
func NewMockDB(ctrl *gomock.Controller) *MockDB {
	mock := &MockDB{ctrl: ctrl}
	mock.recorder = &MockDBMockRecorder{mock}
	return mock
}

// EXPECT returns an object that allows the caller to indicate expected use.
func (m *MockDB) EXPECT() *MockDBMockRecorder {
	return m.recorder
}

// DestroySession mocks base method.
func (m *MockDB) DestroySession(ctx context.Context, sessionID ccc.UUID) error {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "DestroySession", ctx, sessionID)
	ret0, _ := ret[0].(error)
	return ret0
}

// DestroySession indicates an expected call of DestroySession.
func (mr *MockDBMockRecorder) DestroySession(ctx, sessionID any) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "DestroySession", reflect.TypeOf((*MockDB)(nil).DestroySession), ctx, sessionID)
}

// DestroySessionOIDC mocks base method.
func (m *MockDB) DestroySessionOIDC(ctx context.Context, oidcSID string) error {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "DestroySessionOIDC", ctx, oidcSID)
	ret0, _ := ret[0].(error)
	return ret0
}

// DestroySessionOIDC indicates an expected call of DestroySessionOIDC.
func (mr *MockDBMockRecorder) DestroySessionOIDC(ctx, oidcSID any) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "DestroySessionOIDC", reflect.TypeOf((*MockDB)(nil).DestroySessionOIDC), ctx, oidcSID)
}

// InsertSession mocks base method.
func (m *MockDB) InsertSession(ctx context.Context, session *dbtypes.InsertSession) (ccc.UUID, error) {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "InsertSession", ctx, session)
	ret0, _ := ret[0].(ccc.UUID)
	ret1, _ := ret[1].(error)
	return ret0, ret1
}

// InsertSession indicates an expected call of InsertSession.
func (mr *MockDBMockRecorder) InsertSession(ctx, session any) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "InsertSession", reflect.TypeOf((*MockDB)(nil).InsertSession), ctx, session)
}

// InsertSessionOIDC mocks base method.
func (m *MockDB) InsertSessionOIDC(ctx context.Context, session *dbtypes.InsertSessionOIDC) (ccc.UUID, error) {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "InsertSessionOIDC", ctx, session)
	ret0, _ := ret[0].(ccc.UUID)
	ret1, _ := ret[1].(error)
	return ret0, ret1
}

// InsertSessionOIDC indicates an expected call of InsertSessionOIDC.
func (mr *MockDBMockRecorder) InsertSessionOIDC(ctx, session any) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "InsertSessionOIDC", reflect.TypeOf((*MockDB)(nil).InsertSessionOIDC), ctx, session)
}

// Session mocks base method.
func (m *MockDB) Session(ctx context.Context, sessionID ccc.UUID) (*dbtypes.Session, error) {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "Session", ctx, sessionID)
	ret0, _ := ret[0].(*dbtypes.Session)
	ret1, _ := ret[1].(error)
	return ret0, ret1
}

// Session indicates an expected call of Session.
func (mr *MockDBMockRecorder) Session(ctx, sessionID any) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "Session", reflect.TypeOf((*MockDB)(nil).Session), ctx, sessionID)
}

// SessionOIDC mocks base method.
func (m *MockDB) SessionOIDC(ctx context.Context, sessionID ccc.UUID) (*dbtypes.SessionOIDC, error) {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "SessionOIDC", ctx, sessionID)
	ret0, _ := ret[0].(*dbtypes.SessionOIDC)
	ret1, _ := ret[1].(error)
	return ret0, ret1
}

// SessionOIDC indicates an expected call of SessionOIDC.
func (mr *MockDBMockRecorder) SessionOIDC(ctx, sessionID any) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "SessionOIDC", reflect.TypeOf((*MockDB)(nil).SessionOIDC), ctx, sessionID)
}

// UpdateSessionActivity mocks base method.
func (m *MockDB) UpdateSessionActivity(ctx context.Context, sessionID ccc.UUID) error {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "UpdateSessionActivity", ctx, sessionID)
	ret0, _ := ret[0].(error)
	return ret0
}

// UpdateSessionActivity indicates an expected call of UpdateSessionActivity.
func (mr *MockDBMockRecorder) UpdateSessionActivity(ctx, sessionID any) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "UpdateSessionActivity", reflect.TypeOf((*MockDB)(nil).UpdateSessionActivity), ctx, sessionID)
}
