// Code generated by MockGen. DO NOT EDIT.
// Source: ../spanner/spanner_iface.go
//
// Generated by this command:
//
//	mockgen -source ../spanner/spanner_iface.go -destination mock_spanner/mock_spanner.go
//

// Package mock_spanner is a generated GoMock package.
package mock_spanner

import (
	context "context"
	reflect "reflect"

	ccc "github.com/cccteam/ccc"
	spanner "github.com/cccteam/session/spanner"
	gomock "go.uber.org/mock/gomock"
)

// MockDB is a mock of DB interface.
type MockDB struct {
	ctrl     *gomock.Controller
	recorder *MockDBMockRecorder
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
func (m *MockDB) InsertSession(ctx context.Context, session *spanner.InsertSession) (ccc.UUID, error) {
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

// Session mocks base method.
func (m *MockDB) Session(ctx context.Context, sessionID ccc.UUID) (*spanner.Session, error) {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "Session", ctx, sessionID)
	ret0, _ := ret[0].(*spanner.Session)
	ret1, _ := ret[1].(error)
	return ret0, ret1
}

// Session indicates an expected call of Session.
func (mr *MockDBMockRecorder) Session(ctx, sessionID any) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "Session", reflect.TypeOf((*MockDB)(nil).Session), ctx, sessionID)
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
