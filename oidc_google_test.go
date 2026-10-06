package session

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"

	"github.com/cccteam/ccc"
	"github.com/cccteam/ccc/accesstypes"
	"github.com/cccteam/httpio"
	"github.com/cccteam/session/cookie"
	"github.com/cccteam/session/internal/basesession"
	internalcookie "github.com/cccteam/session/internal/cookie"
	"github.com/cccteam/session/mock/mock_cookie"
	"github.com/cccteam/session/mock/mock_googleoidc"
	"github.com/cccteam/session/mock/mock_session"
	"github.com/cccteam/session/sessionstorage/mock/mock_sessionstorage"
	"github.com/go-playground/errors/v5"
	gomock "go.uber.org/mock/gomock"
)

func TestOIDCGoogleSessionLogin(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name            string
		prepare         func(http.ResponseWriter, *mock_googleoidc.MockAuthenticator)
		wantErr         bool
		wantStatusCode  int
		wantRedirectURL string
	}{
		{
			name: "fails to get the auth code url",
			prepare: func(w http.ResponseWriter, oidc *mock_googleoidc.MockAuthenticator) {
				oidc.EXPECT().AuthCodeURL(gomock.Any(), w, "testReturnUrl").Return("", errors.New("failed to get auth code url")).Times(1)
				oidc.EXPECT().LoginURL().Return("/login").Times(1)
			},
			wantErr:         true,
			wantStatusCode:  http.StatusFound,
			wantRedirectURL: "/login?message=Internal+Server+Error",
		},
		{
			name: "success initiating login",
			prepare: func(w http.ResponseWriter, oidc *mock_googleoidc.MockAuthenticator) {
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

			authenticator := mock_googleoidc.NewMockAuthenticator(ctrl)
			cookieClient, err := internalcookie.NewCookieClient(cookieKey)
			if err != nil {
				t.Errorf("cookie.NewCookieClient() error = %v", err)
			}
			a := &OIDCGoogle[NoCustomData, NoCustomData]{
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
				t.Errorf("OIDCGoogle.Login() error = %v, wantErr = %v", got, tt.wantErr)
			} else {
				if got := rr.Header().Get("Location"); got != tt.wantRedirectURL {
					t.Errorf("response.Location = %v, want %v", got, tt.wantRedirectURL)
				}
			}
		})
	}
}

// googleVerifyWithClaims mirrors verifyWithClaims for the Google Authenticator, whose
// Verify returns no OIDC session ID (Google issues no sid claim).
func googleVerifyWithClaims(t *testing.T, rawClaims string) func(context.Context, http.ResponseWriter, *http.Request, interface{}) (string, error) {
	t.Helper()

	return func(_ context.Context, _ http.ResponseWriter, _ *http.Request, claims interface{}) (string, error) {
		if err := json.Unmarshal([]byte(rawClaims), claims); err != nil {
			t.Fatalf("failed to unmarshal claims: %v", err)
		}

		return "testReturnUrl", nil
	}
}

func TestOIDCGoogle_CallbackOIDC(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name            string
		domains         []accesstypes.Domain
		domainsErr      error
		disableRoleSync bool
		prepare         func(*mock_cookie.MockHandler, http.ResponseWriter, *http.Request, *mock_googleoidc.MockAuthenticator, *mock_session.MockUserRoleManager, *mock_session.MockGroupsProvider, *mock_sessionstorage.MockGoogleOIDCStore)
		wantErr         bool
		wantRedirectURL string
	}{
		{
			name: "fails to verify callback request",
			prepare: func(_ *mock_cookie.MockHandler, w http.ResponseWriter, r *http.Request, oidc *mock_googleoidc.MockAuthenticator, _ *mock_session.MockUserRoleManager, _ *mock_session.MockGroupsProvider, _ *mock_sessionstorage.MockGoogleOIDCStore) {
				oidc.EXPECT().LoginURL().Return("/login").Times(1)
				oidc.EXPECT().Verify(gomock.Any(), w, r, gomock.Any()).Return("", httpio.NewForbiddenMessage("Account is not a member of the required Google Workspace domain")).Times(1)
			},
			wantErr:         true,
			wantRedirectURL: fmt.Sprintf("/login?message=%s", url.QueryEscape("Account is not a member of the required Google Workspace domain")),
		},
		{
			name: "fails to unmarshal claims",
			prepare: func(_ *mock_cookie.MockHandler, w http.ResponseWriter, r *http.Request, oidc *mock_googleoidc.MockAuthenticator, _ *mock_session.MockUserRoleManager, _ *mock_session.MockGroupsProvider, _ *mock_sessionstorage.MockGoogleOIDCStore) {
				oidc.EXPECT().LoginURL().Return("/login").Times(1)
				// Verify succeeds but never populates the raw claims (nil payload).
				oidc.EXPECT().Verify(gomock.Any(), w, r, gomock.Any()).Return("testReturnUrl", nil).Times(1)
			},
			wantErr:         true,
			wantRedirectURL: fmt.Sprintf("/login?message=%s", url.QueryEscape("Internal Server Error")),
		},
		{
			name: "missing email claim is rejected",
			prepare: func(_ *mock_cookie.MockHandler, w http.ResponseWriter, r *http.Request, oidc *mock_googleoidc.MockAuthenticator, _ *mock_session.MockUserRoleManager, _ *mock_session.MockGroupsProvider, _ *mock_sessionstorage.MockGoogleOIDCStore) {
				oidc.EXPECT().LoginURL().Return("/login").Times(1)
				oidc.EXPECT().Verify(gomock.Any(), w, r, gomock.Any()).DoAndReturn(googleVerifyWithClaims(t, `{"sub": "sub-1"}`)).Times(1)
			},
			wantErr:         true,
			wantRedirectURL: fmt.Sprintf("/login?message=%s", url.QueryEscape("Unauthorized: token carries no email claim")),
		},
		{
			name: "groups lookup failure fails the login before any role calls",
			prepare: func(_ *mock_cookie.MockHandler, w http.ResponseWriter, r *http.Request, oidc *mock_googleoidc.MockAuthenticator, _ *mock_session.MockUserRoleManager, g *mock_session.MockGroupsProvider, _ *mock_sessionstorage.MockGoogleOIDCStore) {
				oidc.EXPECT().LoginURL().Return("/login").Times(1)
				oidc.EXPECT().Verify(gomock.Any(), w, r, gomock.Any()).DoAndReturn(googleVerifyWithClaims(t, `{"email": "user@example.com"}`)).Times(1)
				// No UserRoleManager expectations: a groups failure must abort before the sweep.
				g.EXPECT().UserGroups(gomock.Any(), "user@example.com").Return(nil, errors.New("groups API unavailable")).Times(1)
			},
			wantErr:         true,
			wantRedirectURL: fmt.Sprintf("/login?message=%s", url.QueryEscape("Internal Server Error")),
		},
		{
			name:    "unauthorized when no group maps to a recognized role",
			domains: []accesstypes.Domain{"testDomain1"},
			prepare: func(_ *mock_cookie.MockHandler, w http.ResponseWriter, r *http.Request, oidc *mock_googleoidc.MockAuthenticator, u *mock_session.MockUserRoleManager, g *mock_session.MockGroupsProvider, _ *mock_sessionstorage.MockGoogleOIDCStore) {
				oidc.EXPECT().LoginURL().Return("/login").Times(1)
				oidc.EXPECT().Verify(gomock.Any(), w, r, gomock.Any()).DoAndReturn(googleVerifyWithClaims(t, `{"email": "user@example.com"}`)).Times(1)
				// Only unrelated groups: no candidate role names, so no RoleExists calls.
				g.EXPECT().UserGroups(gomock.Any(), "user@example.com").Return([]string{"team-eng@example.com"}, nil).Times(1)
				u.EXPECT().UserRoles(gomock.Any(), accesstypes.User("user@example.com"), []accesstypes.Scope{accesstypes.GlobalScope(), accesstypes.DomainScope("testDomain1")}).Return(accesstypes.RoleCollection{}, nil).Times(1)
			},
			wantErr:         true,
			wantRedirectURL: fmt.Sprintf("/login?message=%s", url.QueryEscape("Unauthorized: user has no roles")),
		},
		{
			name:    "aborts the sync when RoleExists returns an error",
			domains: []accesstypes.Domain{"testDomain1"},
			prepare: func(_ *mock_cookie.MockHandler, w http.ResponseWriter, r *http.Request, oidc *mock_googleoidc.MockAuthenticator, u *mock_session.MockUserRoleManager, g *mock_session.MockGroupsProvider, _ *mock_sessionstorage.MockGoogleOIDCStore) {
				oidc.EXPECT().LoginURL().Return("/login").Times(1)
				oidc.EXPECT().Verify(gomock.Any(), w, r, gomock.Any()).DoAndReturn(googleVerifyWithClaims(t, `{"email": "user@example.com"}`)).Times(1)
				g.EXPECT().UserGroups(gomock.Any(), "user@example.com").Return([]string{"app-myapp-admin@example.com"}, nil).Times(1)
				u.EXPECT().UserRoles(gomock.Any(), accesstypes.User("user@example.com"), []accesstypes.Scope{accesstypes.GlobalScope(), accesstypes.DomainScope("testDomain1")}).Return(accesstypes.RoleCollection{accesstypes.DomainScope("testDomain1"): {"admin"}}, nil).Times(1)
				// A store error must abort the sync: no AddUserRoles/DeleteUserRoles
				// expectations — flattening the error to false would sweep the admin role.
				u.EXPECT().RoleExists(gomock.Any(), accesstypes.GlobalScope(), accesstypes.Role("admin")).Return(false, errors.New("store blip")).Times(1)
			},
			wantErr:         true,
			wantRedirectURL: fmt.Sprintf("/login?message=%s", url.QueryEscape("Internal Server Error")),
		},
		{
			name:    "fails to create new session",
			domains: []accesstypes.Domain{"testDomain1"},
			prepare: func(_ *mock_cookie.MockHandler, w http.ResponseWriter, r *http.Request, oidc *mock_googleoidc.MockAuthenticator, u *mock_session.MockUserRoleManager, g *mock_session.MockGroupsProvider, s *mock_sessionstorage.MockGoogleOIDCStore) {
				oidc.EXPECT().LoginURL().Return("/login").Times(1)
				oidc.EXPECT().Verify(gomock.Any(), w, r, gomock.Any()).DoAndReturn(googleVerifyWithClaims(t, `{"email": "user@example.com"}`)).Times(1)
				g.EXPECT().UserGroups(gomock.Any(), "user@example.com").Return([]string{"app-myapp-admin@example.com"}, nil).Times(1)
				u.EXPECT().UserRoles(gomock.Any(), accesstypes.User("user@example.com"), []accesstypes.Scope{accesstypes.GlobalScope(), accesstypes.DomainScope("testDomain1")}).Return(accesstypes.RoleCollection{accesstypes.DomainScope("testDomain1"): {}}, nil).Times(1)
				u.EXPECT().RoleExists(gomock.Any(), accesstypes.GlobalScope(), accesstypes.Role("admin")).Return(false, nil).Times(1)
				u.EXPECT().RoleExists(gomock.Any(), accesstypes.DomainScope("testDomain1"), accesstypes.Role("admin")).Return(true, nil).Times(1)
				u.EXPECT().AddUserRoles(gomock.Any(), accesstypes.DomainScope("testDomain1"), accesstypes.User("user@example.com"), []accesstypes.Role{"admin"}).Return(nil).Times(1)
				s.EXPECT().NewSession(gomock.Any(), "user@example.com", gomock.Any()).Return(ccc.NilUUID, errors.New("failed to create new session")).Times(1)
			},
			wantErr:         true,
			wantRedirectURL: fmt.Sprintf("/login?message=%s", url.QueryEscape("Internal Server Error")),
		},
		{
			name:            "role sync disabled: login proceeds with no groups or role calls",
			disableRoleSync: true,
			prepare: func(c *mock_cookie.MockHandler, w http.ResponseWriter, r *http.Request, oidc *mock_googleoidc.MockAuthenticator, _ *mock_session.MockUserRoleManager, _ *mock_session.MockGroupsProvider, s *mock_sessionstorage.MockGoogleOIDCStore) {
				// No GroupsProvider or UserRoleManager expectations: with role sync
				// disabled, neither the lookup nor the reconciliation runs.
				oidc.EXPECT().Verify(gomock.Any(), w, r, gomock.Any()).DoAndReturn(googleVerifyWithClaims(t, `{"email": "user@example.com"}`)).Times(1)
				s.EXPECT().NewSession(gomock.Any(), "user@example.com", gomock.Any()).Return(ccc.Must(ccc.UUIDFromString("de6e1a12-2d4d-4c4d-aaf1-d82cb9a9eff5")), nil).Times(1)
				c.EXPECT().NewAuthCookie(w, false, ccc.Must(ccc.UUIDFromString("de6e1a12-2d4d-4c4d-aaf1-d82cb9a9eff5"))).Return(cookie.NewValues().Set(internalcookie.SessionID, "de6e1a12-2d4d-4c4d-aaf1-d82cb9a9eff5")).Times(1)
				c.EXPECT().CreateXSRFTokenCookie(w, ccc.Must(ccc.UUIDFromString("de6e1a12-2d4d-4c4d-aaf1-d82cb9a9eff5"))).Return().Times(1)
			},
			wantRedirectURL: "/testReturnUrl",
		},
		{
			name:    "success authenticating via OIDC callback",
			domains: []accesstypes.Domain{"testDomain1", "test domain 2"},
			prepare: func(c *mock_cookie.MockHandler, w http.ResponseWriter, r *http.Request, oidc *mock_googleoidc.MockAuthenticator, u *mock_session.MockUserRoleManager, g *mock_session.MockGroupsProvider, s *mock_sessionstorage.MockGoogleOIDCStore) {
				rawClaims := `{"email": "user@example.com", "sub": "sub-1", "hd": "example.com"}`
				oidc.EXPECT().Verify(gomock.Any(), w, r, gomock.Any()).DoAndReturn(googleVerifyWithClaims(t, rawClaims)).Times(1)
				// Two role groups and one unrelated group: candidates are admin, viewer.
				g.EXPECT().UserGroups(gomock.Any(), "user@example.com").Return([]string{"app-myapp-admin@example.com", "app-myapp-viewer@example.com", "team-eng@example.com"}, nil).Times(1)
				s.EXPECT().NewSession(gomock.Any(), "user@example.com", gomock.Any()).DoAndReturn(
					func(_ context.Context, _ string, claims json.RawMessage) (ccc.UUID, error) {
						// The full verified claims payload must reach storage untouched.
						if string(claims) != rawClaims {
							return ccc.NilUUID, errors.Newf("unexpected claims: %s", string(claims))
						}
						return ccc.Must(ccc.UUIDFromString("de6e1a12-2d4d-4c4d-aaf1-d82cb9a9eff5")), nil
					}).Times(1)
				c.EXPECT().NewAuthCookie(w, false, ccc.Must(ccc.UUIDFromString("de6e1a12-2d4d-4c4d-aaf1-d82cb9a9eff5"))).Return(cookie.NewValues().Set(internalcookie.SessionID, "de6e1a12-2d4d-4c4d-aaf1-d82cb9a9eff5")).Times(1)
				c.EXPECT().CreateXSRFTokenCookie(w, ccc.Must(ccc.UUIDFromString("de6e1a12-2d4d-4c4d-aaf1-d82cb9a9eff5"))).Return().Times(1)
				u.EXPECT().UserRoles(gomock.Any(), accesstypes.User("user@example.com"), []accesstypes.Scope{accesstypes.GlobalScope(), accesstypes.DomainScope("testDomain1"), accesstypes.DomainScope("test domain 2")}).Return(accesstypes.RoleCollection{
					accesstypes.DomainScope("testDomain1"):   {"stale", "admin"},
					accesstypes.DomainScope("test domain 2"): {"viewer"},
				}, nil).Times(1)

				// global (implicitly swept; none of the mapped roles exist there)
				u.EXPECT().RoleExists(gomock.Any(), accesstypes.GlobalScope(), gomock.Any()).Return(false, nil).Times(2)

				// testDomain1: admin and viewer exist; admin already held, stale removed
				u.EXPECT().RoleExists(gomock.Any(), accesstypes.DomainScope("testDomain1"), gomock.Any()).Return(true, nil).Times(2)
				u.EXPECT().AddUserRoles(gomock.Any(), accesstypes.DomainScope("testDomain1"), accesstypes.User("user@example.com"), []accesstypes.Role{"viewer"}).Return(nil).Times(1)
				u.EXPECT().DeleteUserRoles(gomock.Any(), accesstypes.DomainScope("testDomain1"), accesstypes.User("user@example.com"), accesstypes.Role("stale")).Return(nil).Times(1)

				// test domain 2: only viewer exists and is already held
				u.EXPECT().RoleExists(gomock.Any(), accesstypes.DomainScope("test domain 2"), accesstypes.Role("admin")).Return(false, nil).Times(1)
				u.EXPECT().RoleExists(gomock.Any(), accesstypes.DomainScope("test domain 2"), accesstypes.Role("viewer")).Return(true, nil).Times(1)
			},
			wantRedirectURL: "/testReturnUrl",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			ctrl := gomock.NewController(t)

			user := mock_session.NewMockUserRoleManager(ctrl)
			groups := mock_session.NewMockGroupsProvider(ctrl)
			authenticator := mock_googleoidc.NewMockAuthenticator(ctrl)
			sessionStorage := newGoogleOIDCStoreMock(ctrl)
			c := mock_cookie.NewMockHandler(ctrl)
			var rs *googleRoleSyncConfig
			if !tt.disableRoleSync {
				rs = &googleRoleSyncConfig{
					roleSyncConfig: roleSyncConfig{
						manager: user,
						domains: func(context.Context) ([]accesstypes.Domain, error) {
							return tt.domains, tt.domainsErr
						},
					},
					groupPrefix: "app-myapp-",
					groups:      groups,
				}
			}
			a := &OIDCGoogle[NoCustomData, NoCustomData]{
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
				tt.prepare(c, rr, req, authenticator, user, groups, sessionStorage)
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
