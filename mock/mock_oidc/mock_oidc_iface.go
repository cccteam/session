// Code generated by MockGen. DO NOT EDIT.
// Source: ../oidc/oidc_iface.go
//
// Generated by this command:
//
//	mockgen -source ../oidc/oidc_iface.go -destination mock_oidc/mock_oidc_iface.go
//

// Package mock_oidc is a generated GoMock package.
package mock_oidc

import (
	context "context"
	http "net/http"
	reflect "reflect"

	gomock "go.uber.org/mock/gomock"
)

// MockAuthenticator is a mock of Authenticator interface.
type MockAuthenticator struct {
	ctrl     *gomock.Controller
	recorder *MockAuthenticatorMockRecorder
	isgomock struct{}
}

// MockAuthenticatorMockRecorder is the mock recorder for MockAuthenticator.
type MockAuthenticatorMockRecorder struct {
	mock *MockAuthenticator
}

// NewMockAuthenticator creates a new mock instance.
func NewMockAuthenticator(ctrl *gomock.Controller) *MockAuthenticator {
	mock := &MockAuthenticator{ctrl: ctrl}
	mock.recorder = &MockAuthenticatorMockRecorder{mock}
	return mock
}

// EXPECT returns an object that allows the caller to indicate expected use.
func (m *MockAuthenticator) EXPECT() *MockAuthenticatorMockRecorder {
	return m.recorder
}

// AuthCodeURL mocks base method.
func (m *MockAuthenticator) AuthCodeURL(ctx context.Context, w http.ResponseWriter, returnURL string) (string, error) {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "AuthCodeURL", ctx, w, returnURL)
	ret0, _ := ret[0].(string)
	ret1, _ := ret[1].(error)
	return ret0, ret1
}

// AuthCodeURL indicates an expected call of AuthCodeURL.
func (mr *MockAuthenticatorMockRecorder) AuthCodeURL(ctx, w, returnURL any) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "AuthCodeURL", reflect.TypeOf((*MockAuthenticator)(nil).AuthCodeURL), ctx, w, returnURL)
}

// LoginURL mocks base method.
func (m *MockAuthenticator) LoginURL() string {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "LoginURL")
	ret0, _ := ret[0].(string)
	return ret0
}

// LoginURL indicates an expected call of LoginURL.
func (mr *MockAuthenticatorMockRecorder) LoginURL() *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "LoginURL", reflect.TypeOf((*MockAuthenticator)(nil).LoginURL))
}

// Verify mocks base method.
func (m *MockAuthenticator) Verify(ctx context.Context, w http.ResponseWriter, r *http.Request, claims any) (string, string, error) {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "Verify", ctx, w, r, claims)
	ret0, _ := ret[0].(string)
	ret1, _ := ret[1].(string)
	ret2, _ := ret[2].(error)
	return ret0, ret1, ret2
}

// Verify indicates an expected call of Verify.
func (mr *MockAuthenticatorMockRecorder) Verify(ctx, w, r, claims any) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "Verify", reflect.TypeOf((*MockAuthenticator)(nil).Verify), ctx, w, r, claims)
}
