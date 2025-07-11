package session

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"
	"time"

	"github.com/cccteam/ccc"
	"github.com/cccteam/ccc/accesstypes"
	"github.com/cccteam/httpio"
	"github.com/cccteam/session/mock/mock_oidc"
	"github.com/cccteam/session/mock/mock_session"
	"github.com/cccteam/session/roles" // Import roles package
	"github.com/cccteam/session/sessioninfo"
	"github.com/go-chi/chi/v5"
	"github.com/go-playground/errors/v5"
	"github.com/gorilla/securecookie"
	gomock "go.uber.org/mock/gomock"
	"github.com/stretchr/testify/mock" // For the new mock
)

var _ roles.RoleAssigner = &MockRoleAssigner{} // Verify that MockRoleAssigner implements the interface

// MockRoleAssigner is a mock implementation of the RoleAssigner interface.
type MockRoleAssigner struct {
	mock.Mock
}

func (m *MockRoleAssigner) AssignRoles(ctx context.Context, username accesstypes.User, rolesToAssign []string) (hasRole bool, err error) {
	args := m.Called(ctx, username, rolesToAssign)
	return args.Bool(0), args.Error(1)
}

func TestOIDCAzureSessionLogin(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name            string
		prepare         func(http.ResponseWriter, *mock_oidc.MockAuthenticator)
		wantErr         bool
		wantStatusCode  int
		wantRedirectURL string
	}{
		{
			name: "fails to get the auth code url",
			prepare: func(w http.ResponseWriter, oidc *mock_oidc.MockAuthenticator) {
				oidc.EXPECT().AuthCodeURL(gomock.Any(), w, "testReturnUrl").Return("", errors.New("failed to get auth code url")).Times(1)
			},
			wantErr:        true,
			wantStatusCode: http.StatusInternalServerError,
		},
		{
			name: "success initiating login",
			prepare: func(w http.ResponseWriter, oidc *mock_oidc.MockAuthenticator) {
				oidc.EXPECT().AuthCodeURL(gomock.Any(), w, "testReturnUrl").Return("testAuthCodeUrl", nil).Times(1)
			},
			wantStatusCode:  http.StatusFound,
			wantRedirectURL: "/testAuthCodeUrl",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			ctrl := gomock.NewController(t)

			authenticator := mock_oidc.NewMockAuthenticator(ctrl)
			sc := securecookie.New(securecookie.GenerateRandomKey(32), nil)
			//userManager := mock_session.NewMockUserManager(ctrl) // Not strictly needed for this test's direct logic but part of struct
			//roleAssigner := new(MockRoleAssigner) // Not needed for login test

			a := &OIDCAzureSession{ // Direct instantiation for simplicity as NewOIDCAzure has many params
				session: session{
					perms:         mock_session.NewMockUserManager(ctrl), // UserManager mock for perms
					cookieManager: &cookieClient{secureCookie: sc},
					handle: func(handler func(w http.ResponseWriter, r *http.Request) error) http.HandlerFunc {
						return func(w http.ResponseWriter, r *http.Request) {
							if err := handler(w, r); err != nil {
								_ = httpio.NewEncoder(w).ClientMessage(r.Context(), err)
							}
						}
					},
				},
				oidc: authenticator,
				// userManager: userManager, // Initialize if other methods tested here need it
				// roleAssigner: roleAssigner, // Initialize if other methods tested here need it
			}
			req := httptest.NewRequest(http.MethodPost, "/testPath?returnUrl=testReturnUrl", http.NoBody)
			rr := httptest.NewRecorder()
			if tt.prepare != nil {
				tt.prepare(rr, authenticator)
			}

			a.Login().ServeHTTP(rr, req)

			if got := rr.Code; got != tt.wantStatusCode {
				t.Errorf("response.Code = %v, want %v", got, tt.wantStatusCode)
			}
			if rr.Code != http.StatusFound {
				if tt.wantErr {
					return
				}
				var got httpio.MessageResponse
				if err := json.Unmarshal(rr.Body.Bytes(), &got); err != nil {
					t.Errorf("json.Unmarshal() error=%v", err)
				}
				t.Errorf("App.Login() error = %v, wantErr = %v", got, tt.wantErr)
			} else {
				if got := rr.Header().Get("Location"); got != tt.wantRedirectURL {
					t.Errorf("response.Location = %v, want %v", got, tt.wantRedirectURL)
				}
			}
		})
	}
}

func TestApp_CallbackOIDC(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name            string
		prepare         func(ctrl *gomock.Controller, cookieMgr *MockcookieManager, w http.ResponseWriter, r *http.Request, oidcAuth *mock_oidc.MockAuthenticator, userMgr *mock_session.MockUserManager, sessStorage *mock_session.MockOIDCAzureSessionStorage, roleAsgner *MockRoleAssigner)
		wantErr         bool
		wantRedirectURL string
	}{
		{
			name: "fails to verify callback request",
			prepare: func(ctrl *gomock.Controller, _ *MockcookieManager, w http.ResponseWriter, r *http.Request, oidcAuth *mock_oidc.MockAuthenticator, _ *mock_session.MockUserManager, _ *mock_session.MockOIDCAzureSessionStorage, _ *MockRoleAssigner) {
				oidcAuth.EXPECT().LoginURL().Return("/login").Times(1)
				oidcAuth.EXPECT().Verify(gomock.Any(), w, r, gomock.Any()).Return("", "", httpio.NewForbiddenMessage("failed to verify callback")).Times(1)
			},
			wantErr:         true,
			wantRedirectURL: fmt.Sprintf("/login?message=%s", url.QueryEscape("failed to verify callback")),
		},
		{
			name: "fails to create new session",
			prepare: func(ctrl *gomock.Controller, _ *MockcookieManager, w http.ResponseWriter, r *http.Request, oidcAuth *mock_oidc.MockAuthenticator, _ *mock_session.MockUserManager, sessStorage *mock_session.MockOIDCAzureSessionStorage, _ *MockRoleAssigner) {
				oidcAuth.EXPECT().LoginURL().Return("/login").Times(1)
				oidcAuth.EXPECT().Verify(gomock.Any(), w, r, gomock.Any()).Return("testReturnUrl", "a test SID value", nil).Times(1)
				sessStorage.EXPECT().NewSession(gomock.Any(), "", "a test SID value").Return(ccc.NilUUID, errors.New("failed to create new session")).Times(1)
			},
			wantErr:         true,
			wantRedirectURL: fmt.Sprintf("/login?message=%s", url.QueryEscape("Internal Server Error")),
		},
		{
			name: "fails to create new auth cookie",
			prepare: func(ctrl *gomock.Controller, cookieMgr *MockcookieManager, w http.ResponseWriter, r *http.Request, oidcAuth *mock_oidc.MockAuthenticator, _ *mock_session.MockUserManager, sessStorage *mock_session.MockOIDCAzureSessionStorage, _ *MockRoleAssigner) {
				oidcAuth.EXPECT().LoginURL().Return("/login").Times(1)
				oidcAuth.EXPECT().Verify(gomock.Any(), w, r, gomock.Any()).Return("testReturnUrl", "a test SID value", nil).Times(1)
				sessStorage.EXPECT().NewSession(gomock.Any(), gomock.Any(), gomock.Any()).Return(ccc.Must(ccc.UUIDFromString("de6e1a12-2d4d-4c4d-aaf1-d82cb9a9eff5")), nil).Times(1)
				cookieMgr.EXPECT().newAuthCookie(w, false, ccc.Must(ccc.UUIDFromString("de6e1a12-2d4d-4c4d-aaf1-d82cb9a9eff5"))).Return(map[scKey]string{scSessionID: "de6e1a12-2d4d-4c4d-aaf1-d82cb9a9eff5"}, errors.New("failed to create new auth cookie")).Times(1)
			},
			wantRedirectURL: fmt.Sprintf("/login?message=%s", url.QueryEscape("Internal Server Error")),
			wantErr:         true,
		},
		{
			name: "fails to assign roles",
			prepare: func(ctrl *gomock.Controller, cookieMgr *MockcookieManager, w http.ResponseWriter, r *http.Request, oidcAuth *mock_oidc.MockAuthenticator, _ *mock_session.MockUserManager, sessStorage *mock_session.MockOIDCAzureSessionStorage, roleAsgner *MockRoleAssigner) {
				oidcAuth.EXPECT().LoginURL().Return("/login").Times(1)
				oidcAuth.EXPECT().Verify(gomock.Any(), w, r, gomock.Any()).DoAndReturn(
					func(_ context.Context, _ http.ResponseWriter, _ *http.Request, claims interface{}) (string, string, error) {
						err := json.Unmarshal([]byte(`{"preferred_username": "testUser", "roles": ["roleA"]}`), claims)
						if err != nil {
							t.Fatalf("failed to unmarshal claims: %v", err)
						}
						return "testReturnUrl", "testSID", nil
					}).Times(1)
				sessStorage.EXPECT().NewSession(gomock.Any(), "testUser", "testSID").Return(ccc.Must(ccc.UUIDFromString("de6e1a12-2d4d-4c4d-aaf1-d82cb9a9eff5")), nil).Times(1)
				cookieMgr.EXPECT().newAuthCookie(w, false, ccc.Must(ccc.UUIDFromString("de6e1a12-2d4d-4c4d-aaf1-d82cb9a9eff5"))).Return(map[scKey]string{scSessionID: "de6e1a12-2d4d-4c4d-aaf1-d82cb9a9eff5"}, nil).Times(1)
				cookieMgr.EXPECT().setXSRFTokenCookie(w, r, ccc.Must(ccc.UUIDFromString("de6e1a12-2d4d-4c4d-aaf1-d82cb9a9eff5")), xsrfCookieLife).Return(true).Times(1)
				roleAsgner.On("AssignRoles", mock.Anything, accesstypes.User("testUser"), []string{"roleA"}).Return(false, errors.New("failed to assign roles")).Times(1)
			},
			wantRedirectURL: fmt.Sprintf("/login?message=%s", url.QueryEscape("Internal Server Error")),
			wantErr:         true,
		},
		{
			name: "unauthorized due to no assigned roles (from roleAssigner)",
			prepare: func(ctrl *gomock.Controller, cookieMgr *MockcookieManager, w http.ResponseWriter, r *http.Request, oidcAuth *mock_oidc.MockAuthenticator, _ *mock_session.MockUserManager, sessStorage *mock_session.MockOIDCAzureSessionStorage, roleAsgner *MockRoleAssigner) {
				oidcAuth.EXPECT().LoginURL().Return("/login").Times(1)
				oidcAuth.EXPECT().Verify(gomock.Any(), w, r, gomock.Any()).DoAndReturn(
					func(_ context.Context, _ http.ResponseWriter, _ *http.Request, claims interface{}) (string, string, error) {
						err := json.Unmarshal([]byte(`{"preferred_username": "testUser", "roles": ["roleA"]}`), claims)
						if err != nil {
							t.Fatalf("failed to unmarshal claims: %v", err)
						}
						return "testReturnUrl", "testSID", nil
					}).Times(1)
				sessStorage.EXPECT().NewSession(gomock.Any(), "testUser", "testSID").Return(ccc.Must(ccc.UUIDFromString("de6e1a12-2d4d-4c4d-aaf1-d82cb9a9eff5")), nil).Times(1)
				cookieMgr.EXPECT().newAuthCookie(w, false, ccc.Must(ccc.UUIDFromString("de6e1a12-2d4d-4c4d-aaf1-d82cb9a9eff5"))).Return(map[scKey]string{scSessionID: "de6e1a12-2d4d-4c4d-aaf1-d82cb9a9eff5"}, nil).Times(1)
				cookieMgr.EXPECT().setXSRFTokenCookie(w, r, ccc.Must(ccc.UUIDFromString("de6e1a12-2d4d-4c4d-aaf1-d82cb9a9eff5")), xsrfCookieLife).Return(true).Times(1)
				roleAsgner.On("AssignRoles", mock.Anything, accesstypes.User("testUser"), []string{"roleA"}).Return(false, nil).Times(1) // No roles assigned
			},
			wantRedirectURL: fmt.Sprintf("/login?message=%s", url.QueryEscape("Unauthorized: user has no roles")),
			wantErr:         true,
		},
		{
			name: "success authenticating via OIDC callback",
			prepare: func(ctrl *gomock.Controller, cookieMgr *MockcookieManager, w http.ResponseWriter, r *http.Request, oidcAuth *mock_oidc.MockAuthenticator, _ *mock_session.MockUserManager, sessStorage *mock_session.MockOIDCAzureSessionStorage, roleAsgner *MockRoleAssigner) {
				oidcAuth.EXPECT().Verify(gomock.Any(), w, r, gomock.Any()).DoAndReturn(
					func(_ context.Context, _ http.ResponseWriter, _ *http.Request, claims interface{}) (string, string, error) {
						err := json.Unmarshal([]byte(`{"preferred_username": "testUser", "roles": ["roleA", "roleB"]}`), claims)
						if err != nil {
							t.Fatalf("failed to unmarshal claims: %v", err)
						}
						return "testReturnUrl", "testSID", nil
					}).Times(1)
				sessStorage.EXPECT().NewSession(gomock.Any(), "testUser", "testSID").Return(ccc.Must(ccc.UUIDFromString("de6e1a12-2d4d-4c4d-aaf1-d82cb9a9eff5")), nil).Times(1)
				cookieMgr.EXPECT().newAuthCookie(w, false, ccc.Must(ccc.UUIDFromString("de6e1a12-2d4d-4c4d-aaf1-d82cb9a9eff5"))).Return(map[scKey]string{scSessionID: "de6e1a12-2d4d-4c4d-aaf1-d82cb9a9eff5"}, nil).Times(1)
				cookieMgr.EXPECT().setXSRFTokenCookie(w, r, ccc.Must(ccc.UUIDFromString("de6e1a12-2d4d-4c4d-aaf1-d82cb9a9eff5")), xsrfCookieLife).Return(true).Times(1)
				roleAsgner.On("AssignRoles", mock.Anything, accesstypes.User("testUser"), []string{"roleA", "roleB"}).Return(true, nil).Times(1) // Roles assigned
			},
			wantRedirectURL: "/testReturnUrl",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			ctrl := gomock.NewController(t)

			userMgr := mock_session.NewMockUserManager(ctrl)
			authenticator := mock_oidc.NewMockAuthenticator(ctrl)
			sessionStorage := mock_session.NewMockOIDCAzureSessionStorage(ctrl)
			cookieMgr := NewMockcookieManager(ctrl)
			roleAssigner := new(MockRoleAssigner) // Create instance of new mock
			roleAssigner.Test(t)                 // Required for testify/mock

			// Pass mocks to NewOIDCAzure
			a := NewOIDCAzure(authenticator, sessionStorage, userMgr, roleAssigner,
				func(handler func(w http.ResponseWriter, r *http.Request) error) http.HandlerFunc {
					return func(w http.ResponseWriter, r *http.Request) {
						if err := handler(w, r); err != nil {
							_ = httpio.NewEncoder(w).ClientMessage(r.Context(), err)
						}
					}
				},
				securecookie.New(securecookie.GenerateRandomKey(32), nil),
				time.Minute,
			)

			req, err := createHTTPRequest(http.MethodPost, http.NoBody, nil, nil)
			if err != nil {
				t.Error(err)
			}
			rr := httptest.NewRecorder()
			if tt.prepare != nil {
				// Updated prepare signature to include ctrl for mock setup if needed inside prepare
				tt.prepare(ctrl, cookieMgr, rr, req, authenticator, userMgr, sessionStorage, roleAssigner)
			}

			a.CallbackOIDC().ServeHTTP(rr, req)

			if got := rr.Code; got != http.StatusFound {
				// Allow for non-redirect error codes if that's part of a test
				if !(tt.wantErr && got != http.StatusFound) {
					t.Errorf("response.Code = %v, want %v (or other error if wantErr=true)", got, http.StatusFound)
				}
			}
			if loc := rr.Header().Get("Location"); loc != tt.wantRedirectURL {
				t.Errorf("response.Location = %q, want %q", loc, tt.wantRedirectURL)
			}
			roleAssigner.AssertExpectations(t) // Verify testify/mock expectations
		})
	}
}

func TestApp_FrontChannelLogout(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name           string
		reqURL         string
		prepare        func(*mock_session.MockOIDCAzureSessionStorage)
		expectedStatus int
	}{
		{
			name:           "fails to get sid from request",
			reqURL:         "/testPath",
			expectedStatus: http.StatusBadRequest,
		},
		{
			name:   "success logging out, fails to destroy session in db",
			reqURL: "/testPath?sid=testSID",
			prepare: func(storage *mock_session.MockOIDCAzureSessionStorage) {
				storage.EXPECT().DestroySessionOIDC(gomock.Any(), "testSID").Return(errors.New("failed to destroy session in db")).Times(1)
			},
			expectedStatus: http.StatusOK,
		},
		{
			name:   "success logging out",
			reqURL: "/testPath?sid=testSID",
			prepare: func(storage *mock_session.MockOIDCAzureSessionStorage) {
				storage.EXPECT().DestroySessionOIDC(gomock.Any(), "testSID").Return(nil).Times(1)
			},
			expectedStatus: http.StatusOK,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			ctrl := gomock.NewController(t)

			userMgr := mock_session.NewMockUserManager(ctrl)
			authenticator := mock_oidc.NewMockAuthenticator(ctrl)
			sessionStorage := mock_session.NewMockOIDCAzureSessionStorage(ctrl)
			// cookieMgr := NewMockcookieManager(ctrl) // Removed as it's not used by FrontChannelLogout logic being tested
			roleAssigner := new(MockRoleAssigner) // Though not used in FrontChannelLogout, NewOIDCAzure requires it
			roleAssigner.Test(t)

			a := NewOIDCAzure(authenticator, sessionStorage, userMgr, roleAssigner,
				func(handler func(w http.ResponseWriter, r *http.Request) error) http.HandlerFunc {
					return func(w http.ResponseWriter, r *http.Request) {
						if err := handler(w, r); err != nil {
							_ = httpio.NewEncoder(w).ClientMessage(r.Context(), err)
						}
					}
				},
				securecookie.New(securecookie.GenerateRandomKey(32), nil),
				time.Minute,
			)

			if tt.prepare != nil {
				tt.prepare(sessionStorage)
			}

			recorder := httptest.NewRecorder()
			req := httptest.NewRequest(http.MethodGet, tt.reqURL, http.NoBody)
			req = req.WithContext(context.WithValue(context.Background(), ctxSessionExpirationDuration, time.Minute))

			a.FrontChannelLogout().ServeHTTP(recorder, req)
			if recorder.Code != tt.expectedStatus {
				t.Errorf("App.FrontChannelLogout() = %v, want %v", recorder.Code, tt.expectedStatus)
			}
			if tt.expectedStatus != http.StatusOK {
				// If we expect an error status, body might contain an error message
				return
			}
			roleAssigner.AssertExpectations(t)
		})
	}
}

// createHTTPRequest is a helper function to create HTTP requests for tests.
func createHTTPRequest(method string, body io.Reader, sessionInfo *sessioninfo.SessionInfo, urlParams map[httpio.ParamType]string) (*http.Request, error) {
	ctx := context.Background()
	if sessionInfo != nil {
		ctx = context.WithValue(ctx, sessioninfo.CtxSessionInfo, sessionInfo)
	}
	req, err := http.NewRequestWithContext(ctx, method, "", body)
	if err != nil {
		return nil, errors.Wrap(err, "http.NewRequestWithContext()")
	}
	rctx := chi.NewRouteContext()
	for key, val := range urlParams {
		rctx.URLParams.Add(string(key), val)
	}
	req = req.WithContext(context.WithValue(req.Context(), chi.RouteCtxKey, rctx))

	return req, nil
}

// MockcookieManager is defined in mock_cookies_test.go
