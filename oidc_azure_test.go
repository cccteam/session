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
	"github.com/cccteam/session/cookie"
	"github.com/cccteam/session/internal/basesession"
	internalcookie "github.com/cccteam/session/internal/cookie"
	"github.com/cccteam/session/mock/mock_azureoidc"
	"github.com/cccteam/session/mock/mock_cookie"
	"github.com/cccteam/session/mock/mock_session"
	"github.com/cccteam/session/sessioninfo"
	"github.com/cccteam/session/sessionstorage/mock/mock_sessionstorage"
	"github.com/go-chi/chi/v5"
	"github.com/go-playground/errors/v5"
	gomock "go.uber.org/mock/gomock"
)

const cookieKey = "Rsgb6WsDvBsMQ5IJr2WJjVLCPO+o9WW6SdVktdaaq9O0WFA0Hc/EmJeOwCGV6LIqG8ue3iSZ/lycpv8ZNKvWjWU42hZnlO15vYANZG89R1ncjmu4KStldFuP/r0RFhZa"

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
				oidc.EXPECT().LoginURL().Return("/login").Times(1)
			},
			wantErr:         true,
			wantStatusCode:  http.StatusFound,
			wantRedirectURL: "/login?message=Internal+Server+Error",
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
			cookieClient, err := internalcookie.NewCookieClient(cookieKey)
			if err != nil {
				t.Errorf("cookie.NewCookieClient() error = %v", err)
			}
			a := &OIDCAzure[NoCustomData, NoCustomData]{
				baseSession: &basesession.BaseSession{
					CookieHandler: cookieClient,
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
			req := httptest.NewRequestWithContext(context.Background(), http.MethodPost, "/testPath?returnUrl=testReturnUrl", http.NoBody)
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
		domains         []accesstypes.Domain
		domainsErr      error
		disableRoleSync bool
		prepare         func(*mock_cookie.MockHandler, http.ResponseWriter, *http.Request, *mock_azureoidc.MockAuthenticator, *mock_session.MockUserRoleManager, *mock_sessionstorage.MockOIDCStore)
		wantErr         bool
		wantRedirectURL string
	}{
		{
			name: "fails to verify callback request",
			prepare: func(_ *mock_cookie.MockHandler, w http.ResponseWriter, r *http.Request, oidc *mock_azureoidc.MockAuthenticator, _ *mock_session.MockUserRoleManager, _ *mock_sessionstorage.MockOIDCStore) {
				oidc.EXPECT().LoginURL().Return("/login").Times(1)
				oidc.EXPECT().Verify(gomock.Any(), w, r, gomock.Any()).Return("", "", httpio.NewForbiddenMessage("failed to verify callback")).Times(1)
			},
			wantErr:         true,
			wantRedirectURL: fmt.Sprintf("/login?message=%s", url.QueryEscape("failed to verify callback")),
		},
		{
			name: "fails to unmarshal claims",
			prepare: func(_ *mock_cookie.MockHandler, w http.ResponseWriter, r *http.Request, oidc *mock_azureoidc.MockAuthenticator, _ *mock_session.MockUserRoleManager, _ *mock_sessionstorage.MockOIDCStore) {
				oidc.EXPECT().LoginURL().Return("/login").Times(1)
				// Verify succeeds but never populates the raw claims (nil payload).
				oidc.EXPECT().Verify(gomock.Any(), w, r, gomock.Any()).Return("testReturnUrl", "a test SID value", nil).Times(1)
			},
			wantErr:         true,
			wantRedirectURL: fmt.Sprintf("/login?message=%s", url.QueryEscape("Internal Server Error")),
		},
		{
			name:    "fails to create new session",
			domains: []accesstypes.Domain{"testDomain1"},
			prepare: func(_ *mock_cookie.MockHandler, w http.ResponseWriter, r *http.Request, oidc *mock_azureoidc.MockAuthenticator, u *mock_session.MockUserRoleManager, s *mock_sessionstorage.MockOIDCStore) {
				oidc.EXPECT().LoginURL().Return("/login").Times(1)
				oidc.EXPECT().Verify(gomock.Any(), w, r, gomock.Any()).DoAndReturn(verifyWithClaims(t, `{"preferred_username": "test username", "roles": ["testRole1"]}`)).Times(1)
				u.EXPECT().UserRoles(gomock.Any(), accesstypes.User("test username"), []accesstypes.Scope{accesstypes.GlobalScope(), accesstypes.DomainScope("testDomain1")}).Return(accesstypes.RoleCollection{accesstypes.DomainScope("testDomain1"): {}}, nil).Times(1)
				u.EXPECT().RoleExists(gomock.Any(), accesstypes.GlobalScope(), accesstypes.Role("testRole1")).Return(false, nil).Times(1)
				u.EXPECT().RoleExists(gomock.Any(), accesstypes.DomainScope("testDomain1"), accesstypes.Role("testRole1")).Return(true, nil).Times(1)
				u.EXPECT().AddUserRoles(gomock.Any(), accesstypes.DomainScope("testDomain1"), accesstypes.User("test username"), []accesstypes.Role{"testRole1"}).Return(nil).Times(1)
				s.EXPECT().NewSession(gomock.Any(), "test username", "a test SID value", gomock.Any()).Return(ccc.NilUUID, errors.New("failed to create new session")).Times(1)
			},
			wantErr:         true,
			wantRedirectURL: fmt.Sprintf("/login?message=%s", url.QueryEscape("Internal Server Error")),
		},
		{
			name:    "custom session data resolver abort surfaces its client message with no cookies",
			domains: []accesstypes.Domain{"testDomain1"},
			prepare: func(_ *mock_cookie.MockHandler, w http.ResponseWriter, r *http.Request, oidc *mock_azureoidc.MockAuthenticator, u *mock_session.MockUserRoleManager, s *mock_sessionstorage.MockOIDCStore) {
				oidc.EXPECT().LoginURL().Return("/login").Times(1)
				oidc.EXPECT().Verify(gomock.Any(), w, r, gomock.Any()).DoAndReturn(verifyWithClaims(t, `{"preferred_username": "test username", "roles": ["testRole1"]}`)).Times(1)
				u.EXPECT().UserRoles(gomock.Any(), accesstypes.User("test username"), []accesstypes.Scope{accesstypes.GlobalScope(), accesstypes.DomainScope("testDomain1")}).Return(accesstypes.RoleCollection{accesstypes.DomainScope("testDomain1"): {}}, nil).Times(1)
				u.EXPECT().RoleExists(gomock.Any(), accesstypes.GlobalScope(), accesstypes.Role("testRole1")).Return(false, nil).Times(1)
				u.EXPECT().RoleExists(gomock.Any(), accesstypes.DomainScope("testDomain1"), accesstypes.Role("testRole1")).Return(true, nil).Times(1)
				u.EXPECT().AddUserRoles(gomock.Any(), accesstypes.DomainScope("testDomain1"), accesstypes.User("test username"), []accesstypes.Role{"testRole1"}).Return(nil).Times(1)
				// No cookie-handler expectations: a resolver abort must not write cookies.
				s.EXPECT().NewSession(gomock.Any(), "test username", "a test SID value", gomock.Any()).
					Return(ccc.NilUUID, httpio.NewBadRequestMessage("user is not provisioned")).Times(1)
			},
			wantErr:         true,
			wantRedirectURL: fmt.Sprintf("/login?message=%s", url.QueryEscape("user is not provisioned")),
		},
		{
			name:       "fails to get domains from the provider",
			domainsErr: errors.New("failed to get domains"),
			prepare: func(_ *mock_cookie.MockHandler, w http.ResponseWriter, r *http.Request, oidc *mock_azureoidc.MockAuthenticator, _ *mock_session.MockUserRoleManager, _ *mock_sessionstorage.MockOIDCStore) {
				oidc.EXPECT().LoginURL().Return("/login").Times(1)
				oidc.EXPECT().Verify(gomock.Any(), w, r, gomock.Any()).DoAndReturn(verifyWithClaims(t, `{"preferred_username": "test username"}`)).Times(1)
			},
			wantRedirectURL: fmt.Sprintf("/login?message=%s", url.QueryEscape("Internal Server Error")),
			wantErr:         true,
		},
		{
			name:    "fails to get existing user roles",
			domains: []accesstypes.Domain{"testDomain1", "test domain 2"},
			prepare: func(_ *mock_cookie.MockHandler, w http.ResponseWriter, r *http.Request, oidc *mock_azureoidc.MockAuthenticator, u *mock_session.MockUserRoleManager, _ *mock_sessionstorage.MockOIDCStore) {
				oidc.EXPECT().LoginURL().Return("/login").Times(1)
				oidc.EXPECT().Verify(gomock.Any(), w, r, gomock.Any()).DoAndReturn(verifyWithClaims(t, `{"preferred_username": "test username", "roles": ["testRole1", "testRole2", "testRole3","testRole5"]}`)).Times(1)
				u.EXPECT().UserRoles(gomock.Any(), accesstypes.User("test username"), []accesstypes.Scope{accesstypes.GlobalScope(), accesstypes.DomainScope("testDomain1"), accesstypes.DomainScope("test domain 2")}).Return(nil, errors.New("failed to get user roles")).Times(1)
			},
			wantRedirectURL: fmt.Sprintf("/login?message=%s", url.QueryEscape("Internal Server Error")),
			wantErr:         true,
		},
		{
			name:    "aborts the sync when RoleExists returns an error",
			domains: []accesstypes.Domain{"testDomain1"},
			prepare: func(_ *mock_cookie.MockHandler, w http.ResponseWriter, r *http.Request, oidc *mock_azureoidc.MockAuthenticator, u *mock_session.MockUserRoleManager, _ *mock_sessionstorage.MockOIDCStore) {
				oidc.EXPECT().LoginURL().Return("/login").Times(1)
				oidc.EXPECT().Verify(gomock.Any(), w, r, gomock.Any()).DoAndReturn(verifyWithClaims(t, `{"preferred_username": "test username", "roles": ["testRole1"]}`)).Times(1)
				u.EXPECT().UserRoles(gomock.Any(), accesstypes.User("test username"), []accesstypes.Scope{accesstypes.GlobalScope(), accesstypes.DomainScope("testDomain1")}).Return(accesstypes.RoleCollection{accesstypes.DomainScope("testDomain1"): {"testRole0"}}, nil).Times(1)
				// A store error must abort the sync: no AddUserRoles/DeleteUserRoles
				// expectations — flattening the error to false would sweep testRole0.
				u.EXPECT().RoleExists(gomock.Any(), accesstypes.GlobalScope(), accesstypes.Role("testRole1")).Return(false, errors.New("store blip")).Times(1)
			},
			wantRedirectURL: fmt.Sprintf("/login?message=%s", url.QueryEscape("Internal Server Error")),
			wantErr:         true,
		},
		{
			name:    "fails to add user roles",
			domains: []accesstypes.Domain{"testDomain1", "test domain 2"},
			prepare: func(_ *mock_cookie.MockHandler, w http.ResponseWriter, r *http.Request, oidc *mock_azureoidc.MockAuthenticator, u *mock_session.MockUserRoleManager, _ *mock_sessionstorage.MockOIDCStore) {
				oidc.EXPECT().LoginURL().Return("/login").Times(1)
				oidc.EXPECT().Verify(gomock.Any(), w, r, gomock.Any()).DoAndReturn(verifyWithClaims(t, `{"preferred_username": "test username", "roles": ["testRole1", "testRole2", "testRole3","testRole5"]}`)).Times(1)
				u.EXPECT().UserRoles(gomock.Any(), accesstypes.User("test username"), []accesstypes.Scope{accesstypes.GlobalScope(), accesstypes.DomainScope("testDomain1"), accesstypes.DomainScope("test domain 2")}).Return(accesstypes.RoleCollection{
					accesstypes.DomainScope("testDomain1"):   {"testRole0", "testRole1", "testRole2"},
					accesstypes.DomainScope("test domain 2"): {"testRole2", "testRole4"},
				}, nil).Times(1)
				u.EXPECT().RoleExists(gomock.Any(), accesstypes.GlobalScope(), gomock.Any()).Return(false, nil).Times(4)
				u.EXPECT().RoleExists(gomock.Any(), accesstypes.DomainScope("testDomain1"), gomock.Any()).Return(true, nil).Times(4)
				u.EXPECT().AddUserRoles(gomock.Any(), accesstypes.DomainScope("testDomain1"), accesstypes.User("test username"), accesstypes.Role("testRole3"), accesstypes.Role("testRole5")).Return(errors.New("failed to add user roles")).Times(1)
			},
			wantRedirectURL: fmt.Sprintf("/login?message=%s", url.QueryEscape("Internal Server Error")),
			wantErr:         true,
		},
		{
			name:    "fails to delete user roles",
			domains: []accesstypes.Domain{"testDomain1", "test domain 2"},
			prepare: func(_ *mock_cookie.MockHandler, w http.ResponseWriter, r *http.Request, oidc *mock_azureoidc.MockAuthenticator, u *mock_session.MockUserRoleManager, _ *mock_sessionstorage.MockOIDCStore) {
				oidc.EXPECT().LoginURL().Return("/login").Times(1)
				oidc.EXPECT().Verify(gomock.Any(), w, r, gomock.Any()).DoAndReturn(verifyWithClaims(t, `{"preferred_username": "test username", "roles": ["testRole1", "testRole2", "testRole3","testRole5"]}`)).Times(1)
				u.EXPECT().UserRoles(gomock.Any(), accesstypes.User("test username"), []accesstypes.Scope{accesstypes.GlobalScope(), accesstypes.DomainScope("testDomain1"), accesstypes.DomainScope("test domain 2")}).Return(accesstypes.RoleCollection{
					accesstypes.DomainScope("testDomain1"):   {"testRole0", "testRole1", "testRole2"},
					accesstypes.DomainScope("test domain 2"): {"testRole2", "testRole4"},
				}, nil).Times(1)
				u.EXPECT().RoleExists(gomock.Any(), accesstypes.GlobalScope(), gomock.Any()).Return(false, nil).Times(4)
				u.EXPECT().RoleExists(gomock.Any(), accesstypes.DomainScope("testDomain1"), gomock.Any()).Return(true, nil).Times(4)
				u.EXPECT().AddUserRoles(gomock.Any(), accesstypes.DomainScope("testDomain1"), accesstypes.User("test username"), accesstypes.Role("testRole3"), accesstypes.Role("testRole5")).Return(nil).Times(1)
				u.EXPECT().DeleteUserRoles(gomock.Any(), accesstypes.DomainScope("testDomain1"), accesstypes.User("test username"), accesstypes.Role("testRole0")).Return(errors.New("failed to delete user roles")).Times(1)
			},
			wantRedirectURL: fmt.Sprintf("/login?message=%s", url.QueryEscape("Internal Server Error")),
			wantErr:         true,
		},
		{
			name:    "unauthorized due to no assigned roles",
			domains: []accesstypes.Domain{"testDomain1", "test domain 2"},
			prepare: func(_ *mock_cookie.MockHandler, w http.ResponseWriter, r *http.Request, oidc *mock_azureoidc.MockAuthenticator, u *mock_session.MockUserRoleManager, _ *mock_sessionstorage.MockOIDCStore) {
				oidc.EXPECT().LoginURL().Return("/login").Times(1)
				oidc.EXPECT().Verify(gomock.Any(), w, r, gomock.Any()).DoAndReturn(verifyWithClaims(t, `{"preferred_username": "test username", "roles": ["testRole1", "testRole2", "testRole3","testRole5"]}`)).Times(1)
				u.EXPECT().UserRoles(gomock.Any(), accesstypes.User("test username"), []accesstypes.Scope{accesstypes.GlobalScope(), accesstypes.DomainScope("testDomain1"), accesstypes.DomainScope("test domain 2")}).Return(accesstypes.RoleCollection{
					accesstypes.DomainScope("testDomain1"):   {"testRole0", "testRole1", "testRole2"},
					accesstypes.DomainScope("test domain 2"): {"testRole2", "testRole4"},
				}, nil).Times(1)
				u.EXPECT().RoleExists(gomock.Any(), gomock.Any(), gomock.Any()).Return(false, nil).Times(12)
				u.EXPECT().DeleteUserRoles(gomock.Any(), accesstypes.DomainScope("testDomain1"), accesstypes.User("test username"), gomock.Any()).Return(nil).Times(1)
				u.EXPECT().DeleteUserRoles(gomock.Any(), accesstypes.DomainScope("test domain 2"), accesstypes.User("test username"), gomock.Any()).Return(nil).Times(1)
			},
			wantRedirectURL: fmt.Sprintf("/login?message=%s", url.QueryEscape("Unauthorized: user has no roles")),
			wantErr:         true,
		},
		{
			name:            "role sync disabled: login proceeds with no role claims and no role calls",
			disableRoleSync: true,
			prepare: func(c *mock_cookie.MockHandler, w http.ResponseWriter, r *http.Request, oidc *mock_azureoidc.MockAuthenticator, _ *mock_session.MockUserRoleManager, s *mock_sessionstorage.MockOIDCStore) {
				// No UserRoleManager expectations: with role sync disabled, neither the
				// reconciliation nor the at-least-one-role gate runs.
				oidc.EXPECT().Verify(gomock.Any(), w, r, gomock.Any()).DoAndReturn(verifyWithClaims(t, `{"preferred_username": "test username"}`)).Times(1)
				s.EXPECT().NewSession(gomock.Any(), "test username", "a test SID value", gomock.Any()).Return(ccc.Must(ccc.UUIDFromString("de6e1a12-2d4d-4c4d-aaf1-d82cb9a9eff5")), nil).Times(1)
				c.EXPECT().NewAuthCookie(w, false, ccc.Must(ccc.UUIDFromString("de6e1a12-2d4d-4c4d-aaf1-d82cb9a9eff5"))).Return(cookie.NewValues().Set(internalcookie.SessionID, "de6e1a12-2d4d-4c4d-aaf1-d82cb9a9eff5")).Times(1)
				c.EXPECT().CreateXSRFTokenCookie(w, ccc.Must(ccc.UUIDFromString("de6e1a12-2d4d-4c4d-aaf1-d82cb9a9eff5"))).Return().Times(1)
			},
			wantRedirectURL: "/testReturnUrl",
		},
		{
			name:    "success authenticating via OIDC callback",
			domains: []accesstypes.Domain{"testDomain1", "test domain 2"},
			prepare: func(c *mock_cookie.MockHandler, w http.ResponseWriter, r *http.Request, oidc *mock_azureoidc.MockAuthenticator, u *mock_session.MockUserRoleManager, s *mock_sessionstorage.MockOIDCStore) {
				rawClaims := `{"preferred_username": "test username", "roles": ["testRole1", "testRole2", "testRole3","testRole5"]}`
				oidc.EXPECT().Verify(gomock.Any(), w, r, gomock.Any()).DoAndReturn(
					func(_ context.Context, _ http.ResponseWriter, _ *http.Request, claims interface{}) (string, string, error) {
						err := json.Unmarshal([]byte(rawClaims), claims)
						if err != nil {
							t.Fatalf("failed to unmarshal claims: %v", err)
						}
						return "testReturnUrl", "a test SID value", nil
					}).Times(1)
				s.EXPECT().NewSession(gomock.Any(), "test username", "a test SID value", gomock.Any()).DoAndReturn(
					func(_ context.Context, _, _ string, claims json.RawMessage) (ccc.UUID, error) {
						// The full verified claims payload must reach storage untouched.
						if string(claims) != rawClaims {
							return ccc.NilUUID, errors.Newf("unexpected claims: %s", string(claims))
						}
						return ccc.Must(ccc.UUIDFromString("de6e1a12-2d4d-4c4d-aaf1-d82cb9a9eff5")), nil
					}).Times(1)
				c.EXPECT().NewAuthCookie(w, false, ccc.Must(ccc.UUIDFromString("de6e1a12-2d4d-4c4d-aaf1-d82cb9a9eff5"))).Return(cookie.NewValues().Set(internalcookie.SessionID, "de6e1a12-2d4d-4c4d-aaf1-d82cb9a9eff5")).Times(1)
				c.EXPECT().CreateXSRFTokenCookie(w, ccc.Must(ccc.UUIDFromString("de6e1a12-2d4d-4c4d-aaf1-d82cb9a9eff5"))).Return().Times(1)
				u.EXPECT().UserRoles(gomock.Any(), accesstypes.User("test username"), []accesstypes.Scope{accesstypes.GlobalScope(), accesstypes.DomainScope("testDomain1"), accesstypes.DomainScope("test domain 2")}).Return(accesstypes.RoleCollection{
					accesstypes.DomainScope("testDomain1"):   {"testRole0", "testRole1", "testRole2"},
					accesstypes.DomainScope("test domain 2"): {"testRole2", "testRole4"},
				}, nil).Times(1)

				// global (implicitly swept; none of the token roles exist there)
				u.EXPECT().RoleExists(gomock.Any(), accesstypes.GlobalScope(), gomock.Any()).Return(false, nil).Times(4)

				// testDomain1
				u.EXPECT().RoleExists(gomock.Any(), accesstypes.DomainScope("testDomain1"), gomock.Any()).Return(true, nil).Times(4)
				u.EXPECT().AddUserRoles(gomock.Any(), accesstypes.DomainScope("testDomain1"), accesstypes.User("test username"), []accesstypes.Role{"testRole3", "testRole5"}).Return(nil).Times(1)
				u.EXPECT().DeleteUserRoles(gomock.Any(), accesstypes.DomainScope("testDomain1"), accesstypes.User("test username"), accesstypes.Role("testRole0")).Return(nil).Times(1)

				// test domain 2
				u.EXPECT().RoleExists(gomock.Any(), accesstypes.DomainScope("test domain 2"), accesstypes.Role("testRole1")).Return(true, nil).Times(1)
				u.EXPECT().RoleExists(gomock.Any(), accesstypes.DomainScope("test domain 2"), accesstypes.Role("testRole2")).Return(true, nil).Times(1)
				u.EXPECT().RoleExists(gomock.Any(), accesstypes.DomainScope("test domain 2"), accesstypes.Role("testRole3")).Return(false, nil).Times(1)
				u.EXPECT().RoleExists(gomock.Any(), accesstypes.DomainScope("test domain 2"), accesstypes.Role("testRole5")).Return(false, nil).Times(1)
				u.EXPECT().AddUserRoles(gomock.Any(), accesstypes.DomainScope("test domain 2"), accesstypes.User("test username"), []accesstypes.Role{"testRole1"}).Return(nil).Times(1)
				u.EXPECT().DeleteUserRoles(gomock.Any(), accesstypes.DomainScope("test domain 2"), accesstypes.User("test username"), accesstypes.Role("testRole4")).Return(nil).Times(1)
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
			sessionStorage := newOIDCStoreMock(ctrl)
			c := mock_cookie.NewMockHandler(ctrl)
			var rs *roleSyncConfig
			if !tt.disableRoleSync {
				rs = &roleSyncConfig{
					manager: user,
					domains: func(context.Context) ([]accesstypes.Domain, error) {
						return tt.domains, tt.domainsErr
					},
				}
			}
			a := &OIDCAzure[NoCustomData, NoCustomData]{
				roleSync: rs,
				storage:  sessionStorage,
				baseSession: &basesession.BaseSession{
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
			sessionStorage := newOIDCStoreMock(ctrl)

			c := mock_cookie.NewMockHandler(ctrl)
			a := &OIDCAzure[NoCustomData, NoCustomData]{
				storage: sessionStorage,
				baseSession: &basesession.BaseSession{
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
			req := httptest.NewRequestWithContext(context.Background(), http.MethodGet, tt.reqURL, http.NoBody)

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

// verifyWithClaims stubs Authenticator.Verify to populate the raw claims payload and
// succeed, matching the two-pass decode contract of CallbackOIDC.
func verifyWithClaims(t *testing.T, rawClaims string) func(context.Context, http.ResponseWriter, *http.Request, interface{}) (string, string, error) {
	t.Helper()

	return func(_ context.Context, _ http.ResponseWriter, _ *http.Request, claims interface{}) (string, string, error) {
		if err := json.Unmarshal([]byte(rawClaims), claims); err != nil {
			t.Fatalf("failed to unmarshal claims: %v", err)
		}

		return "testReturnUrl", "a test SID value", nil
	}
}

func createHTTPRequest(method string, body io.Reader, sessionInfo *sessioninfo.SessionInfo, userInfo *sessioninfo.UserInfo, urlParams map[httpio.ParamType]string) (*http.Request, error) {
	ctx := context.Background()
	if sessionInfo != nil {
		ctx = context.WithValue(ctx, sessioninfo.CTXSessionID, sessionInfo.ID)
		ctx = context.WithValue(ctx, sessioninfo.CtxSessionInfo, &sessioninfo.SessionData{SessionInfo: sessionInfo})
	} else {
		ctx = context.WithValue(ctx, sessioninfo.CTXSessionID, ccc.Must(ccc.NewUUID()))
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

func TestOIDCAzureAPI_UpdateCustomSessionData(t *testing.T) {
	t.Parallel()

	sessionID := ccc.Must(ccc.NewUUID())

	tests := []struct {
		name    string
		prepare func(*mock_sessionstorage.MockOIDCStore)
		wantErr bool
	}{
		{
			name: "success mutating through the erased callback",
			prepare: func(storage *mock_sessionstorage.MockOIDCStore) {
				storage.EXPECT().UpdateCustomSessionData(gomock.Any(), sessionID, gomock.Any()).
					DoAndReturn(func(_ context.Context, _ ccc.UUID, mutate func(data any) error) error {
						data := &testData{Tenant: "tenant-1"}
						if err := mutate(data); err != nil {
							return err
						}
						if data.Tenant != "tenant-2" {
							return errors.New("typed mutate callback did not apply: " + data.Tenant)
						}

						return nil
					})
			},
		},
		{
			name: "fails on storage error",
			prepare: func(storage *mock_sessionstorage.MockOIDCStore) {
				storage.EXPECT().UpdateCustomSessionData(gomock.Any(), sessionID, gomock.Any()).Return(errors.New("db error"))
			},
			wantErr: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			ctrl := gomock.NewController(t)

			storage := newOIDCStoreMock(ctrl)
			a := &OIDCAzure[testData, NoCustomData]{storage: storage, baseSession: &basesession.BaseSession{Storage: storage}}

			if tt.prepare != nil {
				tt.prepare(storage)
			}

			err := a.API().UpdateCustomSessionData(t.Context(), sessionID, func(data *testData) error {
				data.Tenant = "tenant-2"

				return nil
			})
			if (err != nil) != tt.wantErr {
				t.Errorf("OIDCAzureAPI.UpdateCustomSessionData() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}
