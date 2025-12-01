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
	"github.com/cccteam/session/internal/basesession"
	"github.com/cccteam/session/internal/cookie"
	"github.com/cccteam/session/internal/types"
	"github.com/cccteam/session/mock/mock_azureoidc"
	"github.com/cccteam/session/mock/mock_cookie"
	"github.com/cccteam/session/mock/mock_session"
	"github.com/cccteam/session/sessioninfo"
	"github.com/cccteam/session/sessionstorage/mock/mock_sessionstorage"
	"github.com/go-chi/chi/v5"
	"github.com/go-playground/errors/v5"
	"github.com/gorilla/securecookie"
	gomock "go.uber.org/mock/gomock"
)

func TestOIDCAzureSessionLogin(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name            string
		prepare         func(http.ResponseWriter, *mock_azureoidc.MockAuthenticator)
		wantErr         bool
		wantStatusCode  int
		wantRedirectURL string
	}{
		{
			name: "fails to get the auth code url",
			prepare: func(w http.ResponseWriter, oidc *mock_azureoidc.MockAuthenticator) {
				oidc.EXPECT().AuthCodeURL(gomock.Any(), w, "testReturnUrl").Return("", errors.New("failed to get auth code url")).Times(1)
			},
			wantErr:        true,
			wantStatusCode: http.StatusInternalServerError,
		},
		{
			name: "success initiating login",
			prepare: func(w http.ResponseWriter, oidc *mock_azureoidc.MockAuthenticator) {
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

			authenticator := mock_azureoidc.NewMockAuthenticator(ctrl)
			sc := securecookie.New(securecookie.GenerateRandomKey(32), nil)
			a := &OIDCAzure{
				BaseSession: &basesession.BaseSession{
					CookieHandler: cookie.NewCookieClient(sc),
					Handle: func(handler func(w http.ResponseWriter, r *http.Request) error) http.HandlerFunc {
						return func(w http.ResponseWriter, r *http.Request) {
							if err := handler(w, r); err != nil {
								_ = httpio.NewEncoder(w).ClientMessage(r.Context(), err)
							}
						}
					},
				},
				oidc: authenticator,
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
				t.Errorf("OIDCAzure.Login() error = %v, wantErr = %v", got, tt.wantErr)
			} else {
				if got := rr.Header().Get("Location"); got != tt.wantRedirectURL {
					t.Errorf("response.Location = %v, want %v", got, tt.wantRedirectURL)
				}
			}
		})
	}
}

func TestOIDCAzure_CallbackOIDC(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name            string
		prepare         func(*mock_cookie.MockCookieHandler, http.ResponseWriter, *http.Request, *mock_azureoidc.MockAuthenticator, *mock_session.MockUserRoleManager, *mock_sessionstorage.MockOIDCStore)
		wantErr         bool
		wantRedirectURL string
	}{
		{
			name: "fails to verify callback request",
			prepare: func(_ *mock_cookie.MockCookieHandler, w http.ResponseWriter, r *http.Request, oidc *mock_azureoidc.MockAuthenticator, _ *mock_session.MockUserRoleManager, _ *mock_sessionstorage.MockOIDCStore) {
				oidc.EXPECT().LoginURL().Return("/login").Times(1)
				oidc.EXPECT().Verify(gomock.Any(), w, r, gomock.Any()).Return("", "", httpio.NewForbiddenMessage("failed to verify callback")).Times(1)
			},
			wantErr:         true,
			wantRedirectURL: fmt.Sprintf("/login?message=%s", url.QueryEscape("failed to verify callback")),
		},
		{
			name: "fails to create new session",
			prepare: func(_ *mock_cookie.MockCookieHandler, w http.ResponseWriter, r *http.Request, oidc *mock_azureoidc.MockAuthenticator, _ *mock_session.MockUserRoleManager, s *mock_sessionstorage.MockOIDCStore) {
				oidc.EXPECT().LoginURL().Return("/login").Times(1)
				oidc.EXPECT().Verify(gomock.Any(), w, r, gomock.Any()).Return("testReturnUrl", "a test SID value", nil).Times(1)
				s.EXPECT().NewSession(gomock.Any(), "", "a test SID value").Return(ccc.NilUUID, errors.New("failed to create new session")).Times(1)
			},
			wantErr:         true,
			wantRedirectURL: fmt.Sprintf("/login?message=%s", url.QueryEscape("Internal Server Error")),
		},
		{
			name: "fails to create new auth cookie",
			prepare: func(c *mock_cookie.MockCookieHandler, w http.ResponseWriter, r *http.Request, oidc *mock_azureoidc.MockAuthenticator, _ *mock_session.MockUserRoleManager, s *mock_sessionstorage.MockOIDCStore) {
				oidc.EXPECT().LoginURL().Return("/login").Times(1)
				oidc.EXPECT().Verify(gomock.Any(), w, r, gomock.Any()).Return("testReturnUrl", "a test SID value", nil).Times(1)
				s.EXPECT().NewSession(gomock.Any(), gomock.Any(), gomock.Any()).Return(ccc.Must(ccc.UUIDFromString("de6e1a12-2d4d-4c4d-aaf1-d82cb9a9eff5")), nil).Times(1)
				c.EXPECT().NewAuthCookie(w, false, ccc.Must(ccc.UUIDFromString("de6e1a12-2d4d-4c4d-aaf1-d82cb9a9eff5"))).Return(map[types.SCKey]string{types.SCSessionID: "de6e1a12-2d4d-4c4d-aaf1-d82cb9a9eff5"}, errors.New("failed to create new auth cookie")).Times(1)
			},
			wantRedirectURL: fmt.Sprintf("/login?message=%s", url.QueryEscape("Internal Server Error")),
			wantErr:         true,
		},
		{
			name: "fails to get domains",
			prepare: func(c *mock_cookie.MockCookieHandler, w http.ResponseWriter, r *http.Request, oidc *mock_azureoidc.MockAuthenticator, u *mock_session.MockUserRoleManager, s *mock_sessionstorage.MockOIDCStore) {
				oidc.EXPECT().LoginURL().Return("/login").Times(1)
				oidc.EXPECT().Verify(gomock.Any(), w, r, gomock.Any()).Return("testReturnUrl", "a test SID value", nil).Times(1)
				s.EXPECT().NewSession(gomock.Any(), gomock.Any(), gomock.Any()).Return(ccc.Must(ccc.UUIDFromString("de6e1a12-2d4d-4c4d-aaf1-d82cb9a9eff5")), nil).Times(1)
				c.EXPECT().NewAuthCookie(w, false, ccc.Must(ccc.UUIDFromString("de6e1a12-2d4d-4c4d-aaf1-d82cb9a9eff5"))).Return(map[types.SCKey]string{types.SCSessionID: "de6e1a12-2d4d-4c4d-aaf1-d82cb9a9eff5"}, nil).Times(1)
				c.EXPECT().SetXSRFTokenCookie(w, r, ccc.Must(ccc.UUIDFromString("de6e1a12-2d4d-4c4d-aaf1-d82cb9a9eff5")), types.XSRFCookieLife).Return(true).Times(1)
				u.EXPECT().Domains(gomock.Any()).Return(nil, errors.New("failed to get domains")).Times(1)
			},
			wantRedirectURL: fmt.Sprintf("/login?message=%s", url.QueryEscape("Internal Server Error")),
			wantErr:         true,
		},
		{
			name: "fails to get existing user roles",
			prepare: func(c *mock_cookie.MockCookieHandler, w http.ResponseWriter, r *http.Request, oidc *mock_azureoidc.MockAuthenticator, u *mock_session.MockUserRoleManager, s *mock_sessionstorage.MockOIDCStore) {
				oidc.EXPECT().LoginURL().Return("/login").Times(1)
				oidc.EXPECT().Verify(gomock.Any(), w, r, gomock.Any()).DoAndReturn(
					func(_ context.Context, _ http.ResponseWriter, _ *http.Request, claims interface{}) (string, string, error) {
						err := json.Unmarshal([]byte(`{"preferred_username": "test username", "roles": ["testRole1", "testRole2", "testRole3","testRole5"]}`), claims)
						if err != nil {
							t.Fatalf("failed to unmarshal claims: %v", err)
						}
						return "testReturnUrl", "a test SID value", nil
					}).Times(1)
				s.EXPECT().NewSession(gomock.Any(), gomock.Any(), gomock.Any()).Return(ccc.Must(ccc.UUIDFromString("de6e1a12-2d4d-4c4d-aaf1-d82cb9a9eff5")), nil).Times(1)
				c.EXPECT().NewAuthCookie(w, false, ccc.Must(ccc.UUIDFromString("de6e1a12-2d4d-4c4d-aaf1-d82cb9a9eff5"))).Return(map[types.SCKey]string{types.SCSessionID: "de6e1a12-2d4d-4c4d-aaf1-d82cb9a9eff5"}, nil).Times(1)
				c.EXPECT().SetXSRFTokenCookie(w, r, ccc.Must(ccc.UUIDFromString("de6e1a12-2d4d-4c4d-aaf1-d82cb9a9eff5")), types.XSRFCookieLife).Return(true).Times(1)
				u.EXPECT().Domains(gomock.Any()).Return([]accesstypes.Domain{"testDomain1", "test domain 2"}, nil).Times(1)
				u.EXPECT().UserRoles(gomock.Any(), accesstypes.User("test username"), []accesstypes.Domain{"testDomain1", "test domain 2"}).Return(nil, errors.New("failed to get user roles")).Times(1)
			},
			wantRedirectURL: fmt.Sprintf("/login?message=%s", url.QueryEscape("Internal Server Error")),
			wantErr:         true,
		},
		{
			name: "fails to add user roles",
			prepare: func(c *mock_cookie.MockCookieHandler, w http.ResponseWriter, r *http.Request, oidc *mock_azureoidc.MockAuthenticator, u *mock_session.MockUserRoleManager, s *mock_sessionstorage.MockOIDCStore) {
				oidc.EXPECT().LoginURL().Return("/login").Times(1)
				oidc.EXPECT().Verify(gomock.Any(), w, r, gomock.Any()).DoAndReturn(
					func(_ context.Context, _ http.ResponseWriter, _ *http.Request, claims interface{}) (string, string, error) {
						err := json.Unmarshal([]byte(`{"preferred_username": "test username", "roles": ["testRole1", "testRole2", "testRole3","testRole5"]}`), claims)
						if err != nil {
							t.Fatalf("failed to unmarshal claims: %v", err)
						}
						return "testReturnUrl", "a test SID value", nil
					}).Times(1)
				s.EXPECT().NewSession(gomock.Any(), gomock.Any(), gomock.Any()).Return(ccc.Must(ccc.UUIDFromString("de6e1a12-2d4d-4c4d-aaf1-d82cb9a9eff5")), nil).Times(1)
				c.EXPECT().NewAuthCookie(w, false, ccc.Must(ccc.UUIDFromString("de6e1a12-2d4d-4c4d-aaf1-d82cb9a9eff5"))).Return(map[types.SCKey]string{types.SCSessionID: "de6e1a12-2d4d-4c4d-aaf1-d82cb9a9eff5"}, nil).Times(1)
				c.EXPECT().SetXSRFTokenCookie(w, r, ccc.Must(ccc.UUIDFromString("de6e1a12-2d4d-4c4d-aaf1-d82cb9a9eff5")), types.XSRFCookieLife).Return(true).Times(1)
				u.EXPECT().Domains(gomock.Any()).Return([]accesstypes.Domain{"testDomain1", "test domain 2"}, nil).Times(1)
				u.EXPECT().UserRoles(gomock.Any(), accesstypes.User("test username"), []accesstypes.Domain{"testDomain1", "test domain 2"}).Return(map[accesstypes.Domain][]accesstypes.Role{
					"testDomain1":   {"testRole0", "testRole1", "testRole2"},
					"test domain 2": {"testRole2", "testRole4"},
				}, nil).Times(1)
				u.EXPECT().RoleExists(gomock.Any(), accesstypes.Domain("testDomain1"), gomock.Any()).Return(true).Times(4)
				u.EXPECT().AddUserRoles(gomock.Any(), accesstypes.Domain("testDomain1"), accesstypes.User("test username"), accesstypes.Role("testRole3"), accesstypes.Role("testRole5")).Return(errors.New("failed to add user roles")).Times(1)
			},
			wantRedirectURL: fmt.Sprintf("/login?message=%s", url.QueryEscape("Internal Server Error")),
			wantErr:         true,
		},
		{
			name: "fails to delete user roles",
			prepare: func(c *mock_cookie.MockCookieHandler, w http.ResponseWriter, r *http.Request, oidc *mock_azureoidc.MockAuthenticator, u *mock_session.MockUserRoleManager, s *mock_sessionstorage.MockOIDCStore) {
				oidc.EXPECT().LoginURL().Return("/login").Times(1)
				oidc.EXPECT().Verify(gomock.Any(), w, r, gomock.Any()).DoAndReturn(
					func(_ context.Context, _ http.ResponseWriter, _ *http.Request, claims interface{}) (string, string, error) {
						err := json.Unmarshal([]byte(`{"preferred_username": "test username", "roles": ["testRole1", "testRole2", "testRole3","testRole5"]}`), claims)
						if err != nil {
							t.Fatalf("failed to unmarshal claims: %v", err)
						}
						return "testReturnUrl", "a test SID value", nil
					}).Times(1)
				s.EXPECT().NewSession(gomock.Any(), gomock.Any(), gomock.Any()).Return(ccc.Must(ccc.UUIDFromString("de6e1a12-2d4d-4c4d-aaf1-d82cb9a9eff5")), nil).Times(1)
				c.EXPECT().NewAuthCookie(w, false, ccc.Must(ccc.UUIDFromString("de6e1a12-2d4d-4c4d-aaf1-d82cb9a9eff5"))).Return(map[types.SCKey]string{types.SCSessionID: "de6e1a12-2d4d-4c4d-aaf1-d82cb9a9eff5"}, nil).Times(1)
				c.EXPECT().SetXSRFTokenCookie(w, r, ccc.Must(ccc.UUIDFromString("de6e1a12-2d4d-4c4d-aaf1-d82cb9a9eff5")), types.XSRFCookieLife).Return(true).Times(1)
				u.EXPECT().Domains(gomock.Any()).Return([]accesstypes.Domain{"testDomain1", "test domain 2"}, nil).Times(1)
				u.EXPECT().UserRoles(gomock.Any(), accesstypes.User("test username"), []accesstypes.Domain{"testDomain1", "test domain 2"}).Return(map[accesstypes.Domain][]accesstypes.Role{
					"testDomain1":   {"testRole0", "testRole1", "testRole2"},
					"test domain 2": {"testRole2", "testRole4"},
				}, nil).Times(1)
				u.EXPECT().RoleExists(gomock.Any(), accesstypes.Domain("testDomain1"), gomock.Any()).Return(true).Times(4)
				u.EXPECT().AddUserRoles(gomock.Any(), accesstypes.Domain("testDomain1"), accesstypes.User("test username"), accesstypes.Role("testRole3"), accesstypes.Role("testRole5")).Return(nil).Times(1)
				u.EXPECT().DeleteUserRoles(gomock.Any(), accesstypes.Domain("testDomain1"), accesstypes.User("test username"), accesstypes.Role("testRole0")).Return(errors.New("failed to delete user roles")).Times(1)
			},
			wantRedirectURL: fmt.Sprintf("/login?message=%s", url.QueryEscape("Internal Server Error")),
			wantErr:         true,
		},
		{
			name: "unauthorized due to no assigned roles",
			prepare: func(c *mock_cookie.MockCookieHandler, w http.ResponseWriter, r *http.Request, oidc *mock_azureoidc.MockAuthenticator, u *mock_session.MockUserRoleManager, s *mock_sessionstorage.MockOIDCStore) {
				oidc.EXPECT().LoginURL().Return("/login").Times(1)
				oidc.EXPECT().Verify(gomock.Any(), w, r, gomock.Any()).DoAndReturn(
					func(_ context.Context, _ http.ResponseWriter, _ *http.Request, claims interface{}) (string, string, error) {
						err := json.Unmarshal([]byte(`{"preferred_username": "test username", "roles": ["testRole1", "testRole2", "testRole3","testRole5"]}`), claims)
						if err != nil {
							t.Fatalf("failed to unmarshal claims: %v", err)
						}
						return "testReturnUrl", "a test SID value", nil
					}).Times(1)
				s.EXPECT().NewSession(gomock.Any(), gomock.Any(), gomock.Any()).Return(ccc.Must(ccc.UUIDFromString("de6e1a12-2d4d-4c4d-aaf1-d82cb9a9eff5")), nil).Times(1)
				c.EXPECT().NewAuthCookie(w, false, ccc.Must(ccc.UUIDFromString("de6e1a12-2d4d-4c4d-aaf1-d82cb9a9eff5"))).Return(map[types.SCKey]string{types.SCSessionID: "de6e1a12-2d4d-4c4d-aaf1-d82cb9a9eff5"}, nil).Times(1)
				c.EXPECT().SetXSRFTokenCookie(w, r, ccc.Must(ccc.UUIDFromString("de6e1a12-2d4d-4c4d-aaf1-d82cb9a9eff5")), types.XSRFCookieLife).Return(true).Times(1)
				u.EXPECT().Domains(gomock.Any()).Return([]accesstypes.Domain{"testDomain1", "test domain 2"}, nil).Times(1)
				u.EXPECT().UserRoles(gomock.Any(), accesstypes.User("test username"), []accesstypes.Domain{"testDomain1", "test domain 2"}).Return(map[accesstypes.Domain][]accesstypes.Role{
					"testDomain1":   {"testRole0", "testRole1", "testRole2"},
					"test domain 2": {"testRole2", "testRole4"},
				}, nil).Times(1)
				u.EXPECT().RoleExists(gomock.Any(), gomock.Any(), gomock.Any()).Return(false).Times(8)
				u.EXPECT().DeleteUserRoles(gomock.Any(), accesstypes.Domain("testDomain1"), accesstypes.User("test username"), gomock.Any()).Return(nil).Times(1)
				u.EXPECT().DeleteUserRoles(gomock.Any(), accesstypes.Domain("test domain 2"), accesstypes.User("test username"), gomock.Any()).Return(nil).Times(1)
			},
			wantRedirectURL: fmt.Sprintf("/login?message=%s", url.QueryEscape("Unauthorized: user has no roles")),
			wantErr:         true,
		},
		{
			name: "success authenticating via OIDC callback",
			prepare: func(c *mock_cookie.MockCookieHandler, w http.ResponseWriter, r *http.Request, oidc *mock_azureoidc.MockAuthenticator, u *mock_session.MockUserRoleManager, s *mock_sessionstorage.MockOIDCStore) {
				oidc.EXPECT().Verify(gomock.Any(), w, r, gomock.Any()).DoAndReturn(
					func(_ context.Context, _ http.ResponseWriter, _ *http.Request, claims interface{}) (string, string, error) {
						err := json.Unmarshal([]byte(`{"preferred_username": "test username", "roles": ["testRole1", "testRole2", "testRole3","testRole5"]}`), claims)
						if err != nil {
							t.Fatalf("failed to unmarshal claims: %v", err)
						}
						return "testReturnUrl", "a test SID value", nil
					}).Times(1)
				s.EXPECT().NewSession(gomock.Any(), gomock.Any(), gomock.Any()).Return(ccc.Must(ccc.UUIDFromString("de6e1a12-2d4d-4c4d-aaf1-d82cb9a9eff5")), nil).Times(1)
				c.EXPECT().NewAuthCookie(w, false, ccc.Must(ccc.UUIDFromString("de6e1a12-2d4d-4c4d-aaf1-d82cb9a9eff5"))).Return(map[types.SCKey]string{types.SCSessionID: "de6e1a12-2d4d-4c4d-aaf1-d82cb9a9eff5"}, nil).Times(1)
				c.EXPECT().SetXSRFTokenCookie(w, r, ccc.Must(ccc.UUIDFromString("de6e1a12-2d4d-4c4d-aaf1-d82cb9a9eff5")), types.XSRFCookieLife).Return(true).Times(1)
				u.EXPECT().Domains(gomock.Any()).Return([]accesstypes.Domain{"testDomain1", "test domain 2"}, nil).Times(1)
				u.EXPECT().UserRoles(gomock.Any(), accesstypes.User("test username"), []accesstypes.Domain{"testDomain1", "test domain 2"}).Return(map[accesstypes.Domain][]accesstypes.Role{
					"testDomain1":   {"testRole0", "testRole1", "testRole2"},
					"test domain 2": {"testRole2", "testRole4"},
				}, nil).Times(1)

				// testDomain1
				u.EXPECT().RoleExists(gomock.Any(), accesstypes.Domain("testDomain1"), gomock.Any()).Return(true).Times(4)
				u.EXPECT().AddUserRoles(gomock.Any(), accesstypes.Domain("testDomain1"), accesstypes.User("test username"), []accesstypes.Role{"testRole3", "testRole5"}).Return(nil).Times(1)
				u.EXPECT().DeleteUserRoles(gomock.Any(), accesstypes.Domain("testDomain1"), accesstypes.User("test username"), accesstypes.Role("testRole0")).Return(nil).Times(1)

				// test domain 2
				u.EXPECT().RoleExists(gomock.Any(), accesstypes.Domain("test domain 2"), accesstypes.Role("testRole1")).Return(true).Times(1)
				u.EXPECT().RoleExists(gomock.Any(), accesstypes.Domain("test domain 2"), accesstypes.Role("testRole2")).Return(true).Times(1)
				u.EXPECT().RoleExists(gomock.Any(), accesstypes.Domain("test domain 2"), accesstypes.Role("testRole3")).Return(false).Times(1)
				u.EXPECT().RoleExists(gomock.Any(), accesstypes.Domain("test domain 2"), accesstypes.Role("testRole5")).Return(false).Times(1)
				u.EXPECT().AddUserRoles(gomock.Any(), accesstypes.Domain("test domain 2"), accesstypes.User("test username"), []accesstypes.Role{"testRole1"}).Return(nil).Times(1)
				u.EXPECT().DeleteUserRoles(gomock.Any(), accesstypes.Domain("test domain 2"), accesstypes.User("test username"), accesstypes.Role("testRole4")).Return(nil).Times(1)
			},
			wantRedirectURL: "/testReturnUrl",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			ctrl := gomock.NewController(t)

			user := mock_session.NewMockUserRoleManager(ctrl)
			authenticator := mock_azureoidc.NewMockAuthenticator(ctrl)
			sessionStorage := mock_sessionstorage.NewMockOIDCStore(ctrl)
			c := mock_cookie.NewMockCookieHandler(ctrl)
			a := &OIDCAzure{
				userRoleManager: user,
				storage:         sessionStorage,
				BaseSession: &basesession.BaseSession{
					Storage:       sessionStorage,
					CookieHandler: c,
					Handle: func(handler func(w http.ResponseWriter, r *http.Request) error) http.HandlerFunc {
						return func(w http.ResponseWriter, r *http.Request) {
							if err := handler(w, r); err != nil {
								_ = httpio.NewEncoder(w).ClientMessage(r.Context(), err)
							}
						}
					},
				},
				oidc: authenticator,
			}
			req, err := createHTTPRequest(http.MethodPost, http.NoBody, nil, nil, nil)
			if err != nil {
				t.Error(err)
			}
			rr := httptest.NewRecorder()
			if tt.prepare != nil {
				tt.prepare(c, rr, req, authenticator, user, sessionStorage)
			}

			a.CallbackOIDC().ServeHTTP(rr, req)

			if got := rr.Code; got != http.StatusFound {
				t.Errorf("response.Code = %v, want %v", got, http.StatusFound)
			}
			if got := rr.Header().Get("Location"); got != tt.wantRedirectURL {
				t.Errorf("response.Location = %v, want %v", got, tt.wantRedirectURL)
			}
		})
	}
}

func TestOIDCAzure_FrontChannelLogout(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name           string
		reqURL         string
		prepare        func(*mock_sessionstorage.MockOIDCStore)
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
			prepare: func(storage *mock_sessionstorage.MockOIDCStore) {
				storage.EXPECT().DestroySessionOIDC(gomock.Any(), "testSID").Return(errors.New("failed to destroy session in db")).Times(1)
			},
			expectedStatus: http.StatusOK,
		},
		{
			name:   "success logging out",
			reqURL: "/testPath?sid=testSID",
			prepare: func(storage *mock_sessionstorage.MockOIDCStore) {
				storage.EXPECT().DestroySessionOIDC(gomock.Any(), "testSID").Return(nil).Times(1)
			},
			expectedStatus: http.StatusOK,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			ctrl := gomock.NewController(t)
			authenticator := mock_azureoidc.NewMockAuthenticator(ctrl)
			sessionStorage := mock_sessionstorage.NewMockOIDCStore(ctrl)

			c := mock_cookie.NewMockCookieHandler(ctrl)
			a := &OIDCAzure{
				storage: sessionStorage,
				BaseSession: &basesession.BaseSession{
					SessionTimeout: time.Minute,
					Storage:        sessionStorage,
					CookieHandler:  c,
					Handle: func(handler func(w http.ResponseWriter, r *http.Request) error) http.HandlerFunc {
						return func(w http.ResponseWriter, r *http.Request) {
							if err := handler(w, r); err != nil {
								_ = httpio.NewEncoder(w).ClientMessage(r.Context(), err)
							}
						}
					},
				},
				oidc: authenticator,
			}

			if tt.prepare != nil {
				tt.prepare(sessionStorage)
			}

			recorder := httptest.NewRecorder()
			req := httptest.NewRequest(http.MethodGet, tt.reqURL, http.NoBody)

			a.FrontChannelLogout().ServeHTTP(recorder, req)
			if recorder.Code != tt.expectedStatus {
				t.Errorf("App.FrontChannelLogout() = %v, want %v", recorder.Code, tt.expectedStatus)
			}
			if tt.expectedStatus != http.StatusOK {
				return
			}
		})
	}
}

func createHTTPRequest(method string, body io.Reader, sessionInfo *sessioninfo.SessionInfo, userInfo *sessioninfo.UserInfo, urlParams map[httpio.ParamType]string) (*http.Request, error) {
	ctx := context.Background()
	if sessionInfo != nil {
		ctx = context.WithValue(ctx, sessioninfo.CtxSessionInfo, sessionInfo)
	}
	if userInfo != nil {
		ctx = context.WithValue(ctx, sessioninfo.CtxUserInfo, userInfo)
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
