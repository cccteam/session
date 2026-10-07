package session

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/cccteam/ccc"
	"github.com/cccteam/ccc/accesstypes"
	"github.com/cccteam/ccc/securehash"
	"github.com/cccteam/httpio"
	internalcookie "github.com/cccteam/session/internal/cookie"
	"github.com/cccteam/session/internal/dbtype"
	"github.com/cccteam/session/mock/mock_azureoidc"
	"github.com/cccteam/session/mock/mock_googleoidc"
	"github.com/cccteam/session/mock/mock_session"
	"github.com/cccteam/session/sessioninfo"
	"github.com/cccteam/session/sessionstorage"
	"github.com/cccteam/session/sessionstorage/mock/mock_sessionstorage"
	"github.com/go-playground/errors/v5"
	"github.com/google/go-cmp/cmp"
	"github.com/google/go-cmp/cmp/cmpopts"
	gomock "go.uber.org/mock/gomock"
)

// newAccountStoreMock is an AccountStore mock with the constructor's probes answered:
// no custom data, no OIDC-only features, identities as given.
func newAccountStoreMock(ctrl *gomock.Controller, identities bool) *mock_sessionstorage.MockAccountStore {
	storage := mock_sessionstorage.NewMockAccountStore(ctrl)
	storage.EXPECT().CustomUserDataType().Return(nil).AnyTimes()
	storage.EXPECT().UserDataLoginHookConfigured().Return(false).AnyTimes()
	storage.EXPECT().OIDCUsersEnabled().Return(false).AnyTimes()
	storage.EXPECT().IdentitiesEnabled().Return(identities).AnyTimes()

	return storage
}

// authFixture is an Auth over a mocked store.
type authFixture struct {
	auth  *Auth[NoCustomData, NoCustomData]
	store *mock_sessionstorage.MockAccountStore
	// linked records the IdentityLinked hook's calls.
	linked []ccc.UUID
}

func newAuthFixture(t *testing.T, ctrl *gomock.Controller, methods ...SignInMethod) *authFixture {
	t.Helper()

	f := &authFixture{store: newAccountStoreMock(ctrl, true)}
	hook := func(_ context.Context, userID ccc.UUID, _ *sessioninfo.Identity) error {
		f.linked = append(f.linked, userID)

		return errors.New("notification failed: logged, and the link stands")
	}
	a, err := NewAuth[NoCustomData, NoCustomData](f.store, cookieKey, methods, WithIdentityLinked(hook))
	if err != nil {
		t.Fatalf("NewAuth() error = %v", err)
	}
	f.auth = a

	return f
}

// serve runs h behind the Auth's StartSession with cookies, as a mounted route would.
func (f *authFixture) serve(h http.Handler, method, target string, body any, cookies []*http.Cookie) *httptest.ResponseRecorder {
	var payload *strings.Reader
	if body != nil {
		raw, _ := json.Marshal(body)
		payload = strings.NewReader(string(raw))
	} else {
		payload = strings.NewReader("")
	}
	r := httptest.NewRequestWithContext(context.Background(), method, target, payload)
	r.Header.Set("Content-Type", "application/json")
	for _, c := range cookies {
		r.AddCookie(c)
	}
	rr := httptest.NewRecorder()
	f.auth.StartSession(h).ServeHTTP(rr, r)

	return rr
}

// hold makes a pending identity as a sign-in would and returns the cookies that carry
// it, with the stepping-stone row's ID.
func (f *authFixture) hold(t *testing.T, at *signInAttempt, wait *sessionstorage.PendingSignInError) ([]*http.Cookie, ccc.UUID) {
	t.Helper()

	pendingID := ccc.Must(ccc.NewUUID())
	f.store.EXPECT().CreateSession(gomock.Any(), pendingRow(wait.Username)).Return(pendingID, nil)
	rr := httptest.NewRecorder()
	if _, err := f.auth.holdPending(context.Background(), rr, at, wait); err != nil {
		t.Fatalf("holdPending() error = %v", err)
	}

	return rr.Result().Cookies(), pendingID
}

// pendingRow matches the insert of a pending identity's stepping-stone row for
// username: ReasonPendingIdentity, which the storage never resolves custom session data
// for, and no identity, account or custom data.
func pendingRow(username string) gomock.Matcher {
	return gomock.Eq(&sessioninfo.NewSessionRequest{Reason: sessioninfo.ReasonPendingIdentity, Username: username})
}

// livePending expects the stepping-stone row id to be read, live and accountless.
func (f *authFixture) livePending(id ccc.UUID) {
	f.store.EXPECT().Session(gomock.Any(), id).Return(&sessioninfo.SessionData{SessionInfo: &sessioninfo.SessionInfo{ID: id, UpdatedAt: time.Now()}}, nil).AnyTimes()
}

// cookieNamed is the last cookie named name the response set: the one the browser keeps.
func cookieNamed(rr *httptest.ResponseRecorder, name string) *http.Cookie {
	var last *http.Cookie
	for _, c := range rr.Result().Cookies() {
		if c.Name == name {
			last = c
		}
	}

	return last
}

// pendingDeleted reports whether the response deleted the pending cookie.
func pendingDeleted(rr *httptest.ResponseRecorder) bool {
	c := cookieNamed(rr, defaultPendingCookieName)

	return c != nil && c.Value == "" && c.Expires.Before(time.Now())
}

// refusalCode decodes a JSON sign-in refusal's code.
func refusalCode(t *testing.T, rr *httptest.ResponseRecorder) sessioninfo.LoginRefusalCode {
	t.Helper()

	var body refusalResponse
	_ = json.Unmarshal(rr.Body.Bytes(), &body)

	return body.Code
}

func hashed(t *testing.T, password string) *securehash.Hash {
	t.Helper()

	hash, err := securehash.New(securehash.Argon2()).Hash(password)
	if err != nil {
		t.Fatal(err)
	}

	return hash
}

// createSession expects one session insert, checks the request with check, lets resolve
// play the driver's part (set the account, or fail), and answers id.
func createSession(store *mock_sessionstorage.MockAccountStore, id ccc.UUID, check func(req *sessioninfo.NewSessionRequest), resolve func(req *sessioninfo.NewSessionRequest) error) {
	store.EXPECT().CreateSession(gomock.Any(), gomock.Any()).DoAndReturn(func(_ context.Context, req *sessioninfo.NewSessionRequest) (ccc.UUID, error) {
		if check != nil {
			check(req)
		}
		if resolve != nil {
			if err := resolve(req); err != nil {
				return ccc.NilUUID, err
			}
		}

		return id, nil
	})
}

var eventOpts = cmp.Options{cmpopts.IgnoreFields(sessioninfo.AuthEvent{}, "At"), cmpopts.EquateEmpty()}

func TestNewAuth(t *testing.T) {
	t.Parallel()

	manager := func(ctrl *gomock.Controller) UserRoleManager { return mock_session.NewMockUserRoleManager(ctrl) }
	workos := WorkOSSignIn("sk", "client", "https://app/sso/callback")

	tests := []struct {
		name       string
		storage    func(ctrl *gomock.Controller) sessionstorage.AccountStore
		methods    func(ctrl *gomock.Controller) []SignInMethod
		options    []AuthOption
		wantErrIs  error
		wantErrHas string
	}{
		{
			name:    "password sign-in alone needs no identities configuration",
			storage: func(ctrl *gomock.Controller) sessionstorage.AccountStore { return newAccountStoreMock(ctrl, false) },
			methods: func(*gomock.Controller) []SignInMethod {
				return []SignInMethod{PasswordSignIn(AutoUpgradeHashes(false))}
			},
		},
		{
			name:      "an external method needs an identities configuration",
			storage:   func(ctrl *gomock.Controller) sessionstorage.AccountStore { return newAccountStoreMock(ctrl, false) },
			methods:   func(*gomock.Controller) []SignInMethod { return []SignInMethod{PasswordSignIn(), workos} },
			wantErrIs: sessionstorage.ErrIdentitiesNotConfigured,
		},
		{
			name:    "every method on one Auth",
			storage: func(ctrl *gomock.Controller) sessionstorage.AccountStore { return newAccountStoreMock(ctrl, true) },
			methods: func(ctrl *gomock.Controller) []SignInMethod {
				return []SignInMethod{
					PasswordSignIn(), workos,
					AzureSignIn(RoleSync(manager(ctrl)), "https://issuer", "client", "secret", "https://app/azure/callback", WithLoginURL("/signin")),
					GoogleSignIn(DisableRoleSync(), "client", "secret", "https://app/google/callback", "example.com"),
				}
			},
			options: []AuthOption{WithPendingTimeout(time.Minute), WithPendingCookieName("pending"), WithCookieName("app"), WithSessionTimeout(time.Hour)},
		},
		{
			name:       "no sign-in method",
			storage:    func(ctrl *gomock.Controller) sessionstorage.AccountStore { return newAccountStoreMock(ctrl, true) },
			methods:    func(*gomock.Controller) []SignInMethod { return nil },
			wantErrHas: "at least one sign-in method",
		},
		{
			name:       "a method configured twice",
			storage:    func(ctrl *gomock.Controller) sessionstorage.AccountStore { return newAccountStoreMock(ctrl, true) },
			methods:    func(*gomock.Controller) []SignInMethod { return []SignInMethod{workos, workos} },
			wantErrHas: "configured twice",
		},
		{
			name:       "a cookie option given to the password method instead of NewAuth",
			storage:    func(ctrl *gomock.Controller) sessionstorage.AccountStore { return newAccountStoreMock(ctrl, true) },
			methods:    func(*gomock.Controller) []SignInMethod { return []SignInMethod{PasswordSignIn(WithCookieName("x"))} },
			wantErrHas: "pass cookie and session options to NewAuth",
		},
		{
			name:    "an Azure method without its role sync slot",
			storage: func(ctrl *gomock.Controller) sessionstorage.AccountStore { return newAccountStoreMock(ctrl, true) },
			methods: func(*gomock.Controller) []SignInMethod {
				return []SignInMethod{AzureSignIn(nil, "https://issuer", "client", "secret", "https://app/azure/callback")}
			},
			wantErrHas: "roleSync is required",
		},
		{
			name:    "a Google method without its hosted domain",
			storage: func(ctrl *gomock.Controller) sessionstorage.AccountStore { return newAccountStoreMock(ctrl, true) },
			methods: func(*gomock.Controller) []SignInMethod {
				return []SignInMethod{GoogleSignIn(DisableRoleSync(), "client", "secret", "https://app/google/callback", "")}
			},
			wantErrHas: "hostedDomain is required",
		},
		{
			name:       "a pending cookie named like the session cookie",
			storage:    func(ctrl *gomock.Controller) sessionstorage.AccountStore { return newAccountStoreMock(ctrl, true) },
			methods:    func(*gomock.Controller) []SignInMethod { return []SignInMethod{PasswordSignIn()} },
			options:    []AuthOption{WithCookieName("same"), WithPendingCookieName("same")},
			wantErrHas: "differ from the session cookie name",
		},
		{
			name:       "a pending timeout that is not positive",
			storage:    func(ctrl *gomock.Controller) sessionstorage.AccountStore { return newAccountStoreMock(ctrl, true) },
			methods:    func(*gomock.Controller) []SignInMethod { return []SignInMethod{PasswordSignIn()} },
			options:    []AuthOption{WithPendingTimeout(0)},
			wantErrHas: "pending timeout",
		},
		{
			name: "storage with the OIDC user anchor",
			storage: func(ctrl *gomock.Controller) sessionstorage.AccountStore {
				s := mock_sessionstorage.NewMockAccountStore(ctrl)
				s.EXPECT().UserDataLoginHookConfigured().Return(false).AnyTimes()
				s.EXPECT().OIDCUsersEnabled().Return(true).AnyTimes()

				return s
			},
			methods:    func(*gomock.Controller) []SignInMethod { return []SignInMethod{PasswordSignIn()} },
			wantErrHas: "OIDC-only",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			ctrl := gomock.NewController(t)

			a, err := NewAuth[NoCustomData, NoCustomData](tt.storage(ctrl), cookieKey, tt.methods(ctrl), tt.options...)
			switch {
			case tt.wantErrIs != nil:
				if !errors.Is(err, tt.wantErrIs) {
					t.Errorf("NewAuth() error = %v, want %v", err, tt.wantErrIs)
				}
			case tt.wantErrHas != "":
				if err == nil || !strings.Contains(err.Error(), tt.wantErrHas) {
					t.Errorf("NewAuth() error = %v, want one saying %q", err, tt.wantErrHas)
				}
			case err != nil:
				t.Errorf("NewAuth() error = %v", err)
			case a == nil:
				t.Error("NewAuth() = nil")
			}
		})
	}
}

func TestAuth_UnconfiguredMethodHandlersPanic(t *testing.T) {
	t.Parallel()
	ctrl := gomock.NewController(t)

	passwordOnly := newAuthFixture(t, ctrl, PasswordSignIn()).auth
	workOSOnly := newAuthFixture(t, ctrl, WorkOSSignIn("sk", "client", "https://app/sso/callback")).auth

	for name, call := range map[string]func(){
		"Password() without PasswordSignIn": func() { workOSOnly.Password() },
		"WorkOS() without WorkOSSignIn":     func() { passwordOnly.WorkOS() },
		"Azure() without AzureSignIn":       func() { passwordOnly.Azure() },
		"Google() without GoogleSignIn":     func() { workOSOnly.Google() },
	} {
		func() {
			defer func() {
				if recover() == nil {
					t.Errorf("%s did not panic", name)
				}
			}()
			call()
		}()
	}
}

func TestAuth_PasswordLogin(t *testing.T) {
	t.Parallel()

	userID := ccc.Must(ccc.NewUUID())
	sessionID := ccc.Must(ccc.NewUUID())

	tests := []struct {
		name        string
		password    string
		user        *sessionstorage.SessionUser
		prepare     func(f *authFixture)
		wantStatus  int
		wantMFA     bool
		wantCode    sessioninfo.LoginRefusalCode
		wantSession bool
		wantPending bool
	}{
		{
			name:     "the right password starts a session for the account, recording the password method",
			password: "pw",
			prepare: func(f *authFixture) {
				createSession(f.store, sessionID, func(req *sessioninfo.NewSessionRequest) {
					want := &sessioninfo.Identity{Method: sessioninfo.MethodPassword, Subject: userID.String()}
					if req.Reason != sessioninfo.ReasonLogin || req.UserID != userID || req.Username != "pat" || !cmp.Equal(req.Identity, want) || req.AuthEvents != nil {
						t.Errorf("CreateSession() request = %+v", req)
					}
				}, nil)
			},
			wantStatus:  http.StatusOK,
			wantSession: true,
		},
		{
			name:       "a wrong password is invalid credentials and asks the store for no session",
			password:   "wrong",
			wantStatus: http.StatusUnauthorized,
		},
		{
			name:       "a password-less account fails every password",
			password:   "",
			user:       &sessionstorage.SessionUser{ID: userID, Username: "pat"},
			wantStatus: http.StatusUnauthorized,
		},
		{
			name:       "a disabled account is refused with its code",
			password:   "pw",
			user:       &sessionstorage.SessionUser{ID: userID, Username: "pat", PasswordHash: hashed(t, "pw"), Disabled: true},
			wantStatus: http.StatusUnauthorized,
			wantCode:   sessioninfo.RefusedAccountDisabled,
		},
		{
			name:     "a policy denial is refused with the policy's code and writes no session cookie",
			password: "pw",
			prepare: func(f *authFixture) {
				createSession(f.store, sessionID, nil, func(*sessioninfo.NewSessionRequest) error {
					return dbtype.Refusal("sso_required", sessioninfo.RefusedByPolicy, sessionstorage.ErrSignInDenied, "sign-in denied")
				})
			},
			wantStatus: http.StatusUnauthorized,
			wantCode:   "sso_required",
		},
		{
			name:     "a policy that requires MFA holds the sign-in as a pending identity and starts no session",
			password: "pw",
			prepare: func(f *authFixture) {
				createSession(f.store, sessionID, nil, func(*sessioninfo.NewSessionRequest) error {
					return &sessionstorage.PendingSignInError{Reason: sessioninfo.PendingMFA, UserID: ccc.NullUUIDFromUUID(userID), Username: "pat"}
				})
				f.store.EXPECT().CreateSession(gomock.Any(), pendingRow("pat")).Return(ccc.Must(ccc.NewUUID()), nil)
			},
			wantStatus:  http.StatusOK,
			wantMFA:     true,
			wantPending: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			ctrl := gomock.NewController(t)
			f := newAuthFixture(t, ctrl, PasswordSignIn())

			user := tt.user
			if user == nil {
				user = &sessionstorage.SessionUser{ID: userID, Username: "pat", PasswordHash: hashed(t, "pw")}
			}
			f.store.EXPECT().UserByUserName(gomock.Any(), "pat").Return(user, nil)
			f.store.EXPECT().User(gomock.Any(), userID).Return(user, nil).AnyTimes()
			if tt.prepare != nil {
				tt.prepare(f)
			}

			rr := f.serve(f.auth.Password().Login(), http.MethodPost, "/login", map[string]string{"username": "pat", "password": tt.password}, nil)

			if rr.Code != tt.wantStatus {
				t.Fatalf("status = %d, want %d: %s", rr.Code, tt.wantStatus, rr.Body.String())
			}
			if tt.wantStatus == http.StatusOK {
				var body mfaResponse
				if err := json.Unmarshal(rr.Body.Bytes(), &body); err != nil || body.MFAIsRequired != tt.wantMFA {
					t.Errorf("body = %s, want mfaIsRequired %v", rr.Body.String(), tt.wantMFA)
				}
			}
			if got := refusalCode(t, rr); got != tt.wantCode {
				t.Errorf("refusal code = %q, want %q", got, tt.wantCode)
			}
			auth := cookieNamed(rr, internalcookie.AuthCookieName)
			if gotSession := auth != nil && auth.SameSite == http.SameSiteStrictMode && cookieNamed(rr, internalcookie.XSRFCookieName) != nil; gotSession != tt.wantSession {
				// StartSession writes an auth cookie for the anonymous session too, so a
				// session is told apart by the XSRF cookie the sign-in writes with it.
				t.Errorf("session cookies written = %v, want %v", gotSession, tt.wantSession)
			}
			if gotPending := cookieNamed(rr, defaultPendingCookieName) != nil; gotPending != tt.wantPending {
				t.Errorf("pending cookie written = %v, want %v", gotPending, tt.wantPending)
			}
		})
	}
}

func TestAuth_ExternalLogin(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name         string
		target       string
		prepare      func(authn *mock_azureoidc.MockAuthenticator)
		wantStatus   int
		wantLocation string
	}{
		{
			name:   "a local return path rides to the provider",
			target: "/azure/login?returnUrl=" + url.QueryEscape("/reports?id=1"),
			prepare: func(authn *mock_azureoidc.MockAuthenticator) {
				authn.EXPECT().AuthCodeURL(gomock.Any(), gomock.Any(), "/reports?id=1").Return("https://idp/authorize?state=s", nil)
			},
			wantStatus:   http.StatusFound,
			wantLocation: "https://idp/authorize?state=s",
		},
		{
			name:       "an absolute return URL is refused, not carried",
			target:     "/azure/login?returnUrl=" + url.QueryEscape("https://evil.example/"),
			wantStatus: http.StatusBadRequest,
		},
		{
			name:       "a scheme-relative return URL is refused",
			target:     "/azure/login?returnUrl=" + url.QueryEscape("//evil.example/"),
			wantStatus: http.StatusBadRequest,
		},
		{
			name:   "a provider that cannot start the login sends the browser back with a code",
			target: "/azure/login",
			prepare: func(authn *mock_azureoidc.MockAuthenticator) {
				authn.EXPECT().AuthCodeURL(gomock.Any(), gomock.Any(), "").Return("", errors.New("discovery failed"))
			},
			wantStatus:   http.StatusFound,
			wantLocation: "/login?code=internal_error",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			ctrl := gomock.NewController(t)
			f := newAuthFixture(t, ctrl, PasswordSignIn())
			authn := mock_azureoidc.NewMockAuthenticator(ctrl)
			authn.EXPECT().LoginURL().Return("/login").AnyTimes()
			f.auth.external[sessioninfo.MethodAzure] = azureMethod(authn, nil)
			if tt.prepare != nil {
				tt.prepare(authn)
			}

			rr := f.serve(f.auth.Azure().Login(), http.MethodGet, tt.target, nil, nil)

			if rr.Code != tt.wantStatus || rr.Header().Get("Location") != tt.wantLocation {
				t.Errorf("response = %d %q, want %d %q", rr.Code, rr.Header().Get("Location"), tt.wantStatus, tt.wantLocation)
			}
		})
	}
}

func TestAuth_AzureCallback(t *testing.T) {
	t.Parallel()

	userID := ccc.Must(ccc.NewUUID())
	sessionID := ccc.Must(ccc.NewUUID())
	global := accesstypes.GlobalPolicyScope()
	every := accesstypes.EveryDomainPolicyScope()
	claims := `{"tid":"tenant-1","oid":"oid-1","preferred_username":"p.lee@lakeside.edu","email":"pat@lakeside.edu","roles":["Editor"],"amr":["pwd","mfa"]}`

	// resolved plays the driver: the identity resolves to the account pat.
	resolved := func(req *sessioninfo.NewSessionRequest) error { //nolint:unparam // the driver's signature
		req.UserID, req.Username = userID, "pat"

		return nil
	}

	tests := []struct {
		name         string
		claims       string
		prepare      func(f *authFixture, roles *mock_session.MockUserRoleManager)
		wantLocation string
		wantSession  bool
		wantPending  bool
	}{
		{
			name:   "a linked identity signs in by (tid, oid), and roles are reconciled for the account it resolved to",
			claims: claims,
			prepare: func(f *authFixture, roles *mock_session.MockUserRoleManager) {
				f.store.EXPECT().Identity(gomock.Any(), sessioninfo.MethodAzure, "tenant-1", "oid-1").Return(&sessionstorage.SessionIdentity{UserID: userID}, nil)
				createSession(f.store, sessionID, func(req *sessioninfo.NewSessionRequest) {
					want := &sessioninfo.Identity{Method: sessioninfo.MethodAzure, Connection: "tenant-1", Subject: "oid-1", Email: "pat@lakeside.edu", IdPAMR: []string{"pwd", "mfa"}}
					if diff := cmp.Diff(want, req.Identity, cmpopts.IgnoreFields(sessioninfo.Identity{}, "Claims")); diff != "" || req.Reason != sessioninfo.ReasonLogin || string(req.Claims) != claims {
						t.Errorf("CreateSession() request mismatch (-want +got):\n%s", diff)
					}
				}, resolved)
				roles.EXPECT().UserRoles(gomock.Any(), accesstypes.User("pat")).Return(accesstypes.RoleCollection{}, nil)
				roles.EXPECT().RoleExists(gomock.Any(), global, accesstypes.Role("Editor")).Return(false, nil)
				roles.EXPECT().RoleExists(gomock.Any(), every, accesstypes.Role("Editor")).Return(true, nil)
				roles.EXPECT().AddUserRoles(gomock.Any(), every, accesstypes.User("pat"), []accesstypes.Role{"Editor"}).Return(nil)
			},
			wantLocation: "/next",
			wantSession:  true,
		},
		{
			name:   "role sync that leaves no recognized role refuses the sign-in and expires the session it had inserted",
			claims: claims,
			prepare: func(f *authFixture, roles *mock_session.MockUserRoleManager) {
				f.store.EXPECT().Identity(gomock.Any(), sessioninfo.MethodAzure, "tenant-1", "oid-1").Return(&sessionstorage.SessionIdentity{UserID: userID}, nil)
				createSession(f.store, sessionID, nil, resolved)
				roles.EXPECT().UserRoles(gomock.Any(), accesstypes.User("pat")).Return(accesstypes.RoleCollection{}, nil)
				roles.EXPECT().RoleExists(gomock.Any(), gomock.Any(), accesstypes.Role("Editor")).Return(false, nil).Times(2)
				f.store.EXPECT().DestroySession(gomock.Any(), sessionID).Return(nil)
			},
			wantLocation: "/login?code=no_roles",
		},
		{
			name:         "an ID token without tid and oid is refused before any account is resolved",
			claims:       `{"preferred_username":"pat"}`,
			wantLocation: "/login?code=parse_claims_failed",
		},
		{
			name:   "an identity waiting for its account's password becomes a pending identity, and no roles are touched",
			claims: claims,
			prepare: func(f *authFixture, _ *mock_session.MockUserRoleManager) {
				f.store.EXPECT().Identity(gomock.Any(), sessioninfo.MethodAzure, "tenant-1", "oid-1").Return(nil, httpio.NewNotFoundMessage("not linked"))
				createSession(f.store, sessionID, nil, func(*sessioninfo.NewSessionRequest) error {
					return errors.Wrap(&sessionstorage.PendingSignInError{Reason: sessioninfo.PendingConfirmation, UserID: ccc.NullUUIDFromUUID(userID), Username: "pat"}, "db.InsertSession()")
				})
				f.store.EXPECT().CreateSession(gomock.Any(), pendingRow("pat")).Return(ccc.Must(ccc.NewUUID()), nil)
			},
			wantLocation: "/login?pending=confirmation&returnUrl=%2Fnext",
			wantPending:  true,
		},
		{
			name:   "a resolver's refusal sends its code to the login page",
			claims: claims,
			prepare: func(f *authFixture, _ *mock_session.MockUserRoleManager) {
				f.store.EXPECT().Identity(gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any()).Return(nil, httpio.NewNotFoundMessage("not linked"))
				createSession(f.store, sessionID, nil, func(*sessioninfo.NewSessionRequest) error {
					return dbtype.Refusal("", sessioninfo.RefusedIdentityRejected, sessionstorage.ErrIdentityRejected, "identity rejected")
				})
			},
			wantLocation: "/login?code=identity_rejected",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			ctrl := gomock.NewController(t)
			f := newAuthFixture(t, ctrl, PasswordSignIn())
			roles := mock_session.NewMockUserRoleManager(ctrl)
			authn := mock_azureoidc.NewMockAuthenticator(ctrl)
			authn.EXPECT().LoginURL().Return("/login").AnyTimes()
			authn.EXPECT().Verify(gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any()).DoAndReturn(
				func(_ context.Context, _ http.ResponseWriter, _ *http.Request, claims any) (string, string, error) {
					if err := json.Unmarshal([]byte(tt.claims), claims); err != nil {
						t.Fatal(err)
					}

					return "/next", "sid", nil
				})
			f.auth.external[sessioninfo.MethodAzure] = azureMethod(authn, &roleSyncConfig{manager: roles})
			if tt.prepare != nil {
				tt.prepare(f, roles)
			}

			rr := f.serve(f.auth.Azure().Callback(), http.MethodGet, "/azure/callback?code=c&state=s", nil, nil)

			if rr.Code != http.StatusFound || rr.Header().Get("Location") != tt.wantLocation {
				t.Errorf("response = %d %q, want 302 %q", rr.Code, rr.Header().Get("Location"), tt.wantLocation)
			}
			auth := cookieNamed(rr, internalcookie.AuthCookieName)
			// The callback is a cross-site redirect: the new session's cookie is
			// SameSite=None until StartSession upgrades it.
			if gotSession := auth != nil && auth.SameSite == http.SameSiteNoneMode; gotSession != tt.wantSession {
				t.Errorf("session cookie written = %v, want %v", gotSession, tt.wantSession)
			}
			if gotPending := cookieNamed(rr, defaultPendingCookieName) != nil; gotPending != tt.wantPending {
				t.Errorf("pending cookie written = %v, want %v", gotPending, tt.wantPending)
			}
		})
	}
}

func TestAuth_GoogleCallback(t *testing.T) {
	t.Parallel()

	sessionID := ccc.Must(ccc.NewUUID())

	tests := []struct {
		name         string
		claims       string
		prepare      func(f *authFixture)
		wantLocation string
	}{
		{
			name:   "a Google identity is keyed by sub alone",
			claims: `{"sub":"sub-1","email":"pat@example.com","email_verified":true,"hd":"example.com"}`,
			prepare: func(f *authFixture) {
				f.store.EXPECT().Identity(gomock.Any(), sessioninfo.MethodGoogle, "", "sub-1").Return(&sessionstorage.SessionIdentity{}, nil)
				createSession(f.store, sessionID, func(req *sessioninfo.NewSessionRequest) {
					want := &sessioninfo.Identity{Method: sessioninfo.MethodGoogle, Subject: "sub-1", Email: "pat@example.com", EmailVerified: true}
					if diff := cmp.Diff(want, req.Identity, cmpopts.IgnoreFields(sessioninfo.Identity{}, "Claims")); diff != "" {
						t.Errorf("CreateSession() identity mismatch (-want +got):\n%s", diff)
					}
				}, func(req *sessioninfo.NewSessionRequest) error {
					req.UserID, req.Username = ccc.Must(ccc.NewUUID()), "pat"

					return nil
				})
			},
			wantLocation: "/home",
		},
		{
			name:         "an ID token without an email is refused with its code",
			claims:       `{"sub":"sub-1"}`,
			wantLocation: "/login?code=no_email_claim",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			ctrl := gomock.NewController(t)
			f := newAuthFixture(t, ctrl, PasswordSignIn())
			authn := mock_googleoidc.NewMockAuthenticator(ctrl)
			authn.EXPECT().LoginURL().Return("/login").AnyTimes()
			authn.EXPECT().Verify(gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any()).DoAndReturn(
				func(_ context.Context, _ http.ResponseWriter, _ *http.Request, claims any) (string, string, error) {
					if err := json.Unmarshal([]byte(tt.claims), claims); err != nil {
						t.Fatal(err)
					}

					return "/home", "access-token", nil
				})
			f.auth.external[sessioninfo.MethodGoogle] = googleMethod(authn, nil)
			if tt.prepare != nil {
				tt.prepare(f)
			}

			rr := f.serve(f.auth.Google().Callback(), http.MethodGet, "/google/callback", nil, nil)

			if rr.Code != http.StatusFound || rr.Header().Get("Location") != tt.wantLocation {
				t.Errorf("response = %d %q, want 302 %q", rr.Code, rr.Header().Get("Location"), tt.wantLocation)
			}
		})
	}
}

func TestAuth_IdentityLinkedHook(t *testing.T) {
	t.Parallel()

	userID := ccc.Must(ccc.NewUUID())
	sessionID := ccc.Must(ccc.NewUUID())
	identity := &sessioninfo.Identity{Method: sessioninfo.MethodWorkOS, Connection: "conn", Subject: "idp"}

	tests := []struct {
		name       string
		linkBefore error
		wantLinked []ccc.UUID
	}{
		{name: "a sign-in that linked a new identity reports the link, and the hook's error does not undo it", linkBefore: httpio.NewNotFoundMessage("not linked"), wantLinked: []ccc.UUID{userID}},
		{name: "a sign-in through an existing link reports nothing"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			ctrl := gomock.NewController(t)
			f := newAuthFixture(t, ctrl, PasswordSignIn())
			f.store.EXPECT().Identity(gomock.Any(), identity.Method, identity.Connection, identity.Subject).Return(&sessionstorage.SessionIdentity{}, tt.linkBefore)
			createSession(f.store, sessionID, nil, func(req *sessioninfo.NewSessionRequest) error {
				req.UserID, req.Username = userID, "pat"

				return nil
			})

			outcome, err := f.auth.signIn(context.Background(), httptest.NewRecorder(), &signInAttempt{identity: identity, reason: sessioninfo.ReasonLogin, sameSite: sameSiteNone})
			if err != nil || outcome.sessionID != sessionID {
				t.Fatalf("signIn() = %+v, %v; want session %s", outcome, err, sessionID)
			}
			if diff := cmp.Diff(tt.wantLinked, f.linked, cmpopts.EquateEmpty()); diff != "" {
				t.Errorf("IdentityLinked reports mismatch (-want +got):\n%s", diff)
			}
		})
	}
}

func TestAuth_PendingConfirmWithPassword(t *testing.T) {
	t.Parallel()

	userID := ccc.Must(ccc.NewUUID())
	otherID := ccc.Must(ccc.NewUUID())
	sessionID := ccc.Must(ccc.NewUUID())
	identity := &sessioninfo.Identity{Method: sessioninfo.MethodWorkOS, Connection: "conn", Subject: "idp", Email: "pat@lakeside.edu"}
	confirmation := &sessionstorage.PendingSignInError{Reason: sessioninfo.PendingConfirmation, UserID: ccc.NullUUIDFromUUID(userID), Username: "pat", Tenant: "lakeside"}

	tests := []struct {
		name          string
		wait          *sessionstorage.PendingSignInError
		pendingRow    func(f *authFixture, id ccc.UUID)
		password      string
		prepare       func(f *authFixture, pendingID ccc.UUID)
		wantStatus    int
		wantMFA       bool
		wantCode      sessioninfo.LoginRefusalCode
		wantLinked    int
		wantConsumed  bool
		wantReplaced  bool
		noPendingSent bool
	}{
		{
			name:     "the right password links the identity, reports it and starts the session with both steps, consuming the pending identity",
			wait:     confirmation,
			password: "pw",
			prepare: func(f *authFixture, pendingID ccc.UUID) {
				f.store.EXPECT().LinkIdentity(gomock.Any(), userID, identity, "lakeside").Return(&sessionstorage.SessionIdentity{}, nil)
				createSession(f.store, sessionID, func(req *sessioninfo.NewSessionRequest) {
					want := []sessioninfo.AuthEvent{{Method: sessioninfo.MethodWorkOS, Connection: "conn"}, {Method: sessioninfo.MethodLinkConfirmation}}
					if diff := cmp.Diff(want, req.AuthEvents, eventOpts); diff != "" || req.Reason != sessioninfo.ReasonIdentityLinked || !cmp.Equal(req.Identity, identity) {
						t.Errorf("CreateSession() request = %+v, events mismatch (-want +got):\n%s", req, diff)
					}
				}, func(req *sessioninfo.NewSessionRequest) error {
					req.UserID, req.Username = userID, "pat"

					return nil
				})
				f.store.EXPECT().DestroySession(gomock.Any(), pendingID).Return(nil)
			},
			wantStatus:   http.StatusOK,
			wantLinked:   1,
			wantConsumed: true,
		},
		{
			name:     "the policy still requiring MFA after the link keeps the identity pending, now for MFA, under a new row",
			wait:     confirmation,
			password: "pw",
			prepare: func(f *authFixture, pendingID ccc.UUID) {
				f.store.EXPECT().LinkIdentity(gomock.Any(), userID, identity, "lakeside").Return(&sessionstorage.SessionIdentity{}, nil)
				createSession(f.store, sessionID, nil, func(*sessioninfo.NewSessionRequest) error {
					return &sessionstorage.PendingSignInError{Reason: sessioninfo.PendingMFA, UserID: ccc.NullUUIDFromUUID(userID), Username: "pat"}
				})
				f.store.EXPECT().CreateSession(gomock.Any(), pendingRow("pat")).Return(ccc.Must(ccc.NewUUID()), nil)
				f.store.EXPECT().DestroySession(gomock.Any(), pendingID).Return(nil)
			},
			wantStatus:   http.StatusOK,
			wantMFA:      true,
			wantLinked:   1,
			wantReplaced: true,
		},
		{
			name:       "a wrong password is invalid credentials, links nothing and leaves the pending identity",
			wait:       confirmation,
			password:   "wrong",
			wantStatus: http.StatusUnauthorized,
		},
		{
			name:     "an identity linked meanwhile to another account is refused",
			wait:     confirmation,
			password: "pw",
			prepare: func(f *authFixture, _ ccc.UUID) {
				f.store.EXPECT().LinkIdentity(gomock.Any(), userID, identity, "lakeside").Return(nil, httpio.NewConflictMessage("already linked"))
				f.store.EXPECT().Identity(gomock.Any(), identity.Method, identity.Connection, identity.Subject).Return(&sessionstorage.SessionIdentity{UserID: otherID}, nil)
			},
			wantStatus: http.StatusUnauthorized,
			wantCode:   sessioninfo.RefusedIdentityRejected,
		},
		{
			name:       "an identity waiting for MFA has nothing to confirm",
			wait:       &sessionstorage.PendingSignInError{Reason: sessioninfo.PendingMFA, UserID: ccc.NullUUIDFromUUID(userID), Username: "pat"},
			password:   "pw",
			wantStatus: http.StatusConflict,
		},
		{
			name: "a pending identity whose row is no longer live has expired",
			wait: confirmation,
			pendingRow: func(f *authFixture, id ccc.UUID) {
				f.store.EXPECT().Session(gomock.Any(), id).Return(&sessioninfo.SessionData{SessionInfo: &sessioninfo.SessionInfo{ID: id, Expired: true}}, nil)
			},
			password:   "pw",
			wantStatus: http.StatusUnauthorized,
			wantCode:   sessioninfo.RefusedPendingExpired,
		},
		{
			name:          "a browser without a pending identity has none to confirm",
			password:      "pw",
			wantStatus:    http.StatusNotFound,
			noPendingSent: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			ctrl := gomock.NewController(t)
			f := newAuthFixture(t, ctrl, PasswordSignIn())
			f.store.EXPECT().User(gomock.Any(), userID).Return(&sessionstorage.SessionUser{ID: userID, Username: "pat", PasswordHash: hashed(t, "pw")}, nil).AnyTimes()

			var cookies []*http.Cookie
			var pendingID ccc.UUID
			if !tt.noPendingSent {
				cookies, pendingID = f.hold(t, &signInAttempt{identity: identity, reason: sessioninfo.ReasonLogin}, tt.wait)
				if tt.pendingRow != nil {
					tt.pendingRow(f, pendingID)
				} else {
					f.livePending(pendingID)
				}
			}
			if tt.prepare != nil {
				tt.prepare(f, pendingID)
			}

			rr := f.serve(f.auth.Pending().ConfirmWithPassword(), http.MethodPost, "/pending/confirm", map[string]string{"password": tt.password}, cookies)

			if rr.Code != tt.wantStatus {
				t.Fatalf("status = %d, want %d: %s", rr.Code, tt.wantStatus, rr.Body.String())
			}
			if tt.wantStatus == http.StatusOK && strings.Contains(rr.Body.String(), `"mfaIsRequired":true`) != tt.wantMFA {
				t.Errorf("body = %s, want mfaIsRequired %v", rr.Body.String(), tt.wantMFA)
			}
			if got := refusalCode(t, rr); got != tt.wantCode {
				t.Errorf("refusal code = %q, want %q", got, tt.wantCode)
			}
			if len(f.linked) != tt.wantLinked {
				t.Errorf("IdentityLinked reports = %d, want %d", len(f.linked), tt.wantLinked)
			}
			if got := pendingDeleted(rr); got != tt.wantConsumed {
				t.Errorf("pending cookie deleted = %v, want %v", got, tt.wantConsumed)
			}
			if c := cookieNamed(rr, defaultPendingCookieName); (c != nil && c.Value != "") != tt.wantReplaced {
				t.Errorf("pending cookie replaced = %v, want %v", c != nil && c.Value != "", tt.wantReplaced)
			}
		})
	}
}

func TestAuthAPI_CompletePending(t *testing.T) {
	t.Parallel()

	userID := ccc.Must(ccc.NewUUID())
	sessionID := ccc.Must(ccc.NewUUID())
	password := &sessioninfo.Identity{Method: sessioninfo.MethodPassword, Subject: userID.String()}
	mfa := &sessionstorage.PendingSignInError{Reason: sessioninfo.PendingMFA, UserID: ccc.NullUUIDFromUUID(userID), Username: "pat"}

	tests := []struct {
		name        string
		wait        *sessionstorage.PendingSignInError
		prepare     func(f *authFixture, pendingID ccc.UUID)
		wantSession bool
		wantErr     func(err error) bool
	}{
		{
			name: "the MFA step completes the sign-in under a new session ID that records both steps, and is not decided again",
			wait: mfa,
			prepare: func(f *authFixture, pendingID ccc.UUID) {
				createSession(f.store, sessionID, func(req *sessioninfo.NewSessionRequest) {
					want := []sessioninfo.AuthEvent{{Method: sessioninfo.MethodPassword}, {Method: "email-otp", IdPAMR: []string{"otp"}}}
					if diff := cmp.Diff(want, req.AuthEvents, eventOpts); diff != "" || req.Reason != sessioninfo.ReasonStepUp || req.UserID != userID || !cmp.Equal(req.Identity, password) {
						t.Errorf("CreateSession() request = %+v, events mismatch (-want +got):\n%s", req, diff)
					}
				}, nil)
				f.store.EXPECT().DestroySession(gomock.Any(), pendingID).Return(nil)
			},
			wantSession: true,
		},
		{
			name: "an identity resolving to another account than it waited on is refused and its session expired",
			wait: mfa,
			prepare: func(f *authFixture, _ ccc.UUID) {
				createSession(f.store, sessionID, nil, func(req *sessioninfo.NewSessionRequest) error {
					req.UserID = ccc.Must(ccc.NewUUID())

					return nil
				})
				f.store.EXPECT().DestroySession(gomock.Any(), sessionID).Return(nil)
			},
			wantErr: func(err error) bool {
				return sessioninfo.LoginRefusalCodeOf(err) == sessioninfo.RefusedIdentityRejected
			},
		},
		{
			name:    "an identity waiting for a password confirmation can't be completed by MFA",
			wait:    &sessionstorage.PendingSignInError{Reason: sessioninfo.PendingConfirmation, UserID: ccc.NullUUIDFromUUID(userID), Username: "pat"},
			wantErr: httpio.HasConflict,
		},
		{
			name: "a disabled account is refused at completion",
			wait: mfa,
			prepare: func(f *authFixture, _ ccc.UUID) {
				f.store.EXPECT().User(gomock.Any(), userID).Return(&sessionstorage.SessionUser{ID: userID, Username: "pat", Disabled: true}, nil)
			},
			wantErr: func(err error) bool { return errors.Is(err, sessionstorage.ErrAccountDisabled) },
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			ctrl := gomock.NewController(t)
			f := newAuthFixture(t, ctrl, PasswordSignIn())
			cookies, pendingID := f.hold(t, &signInAttempt{identity: password, reason: sessioninfo.ReasonLogin, userID: userID}, tt.wait)
			f.livePending(pendingID)
			if tt.prepare != nil {
				tt.prepare(f, pendingID)
			}
			f.store.EXPECT().User(gomock.Any(), userID).Return(&sessionstorage.SessionUser{ID: userID, Username: "pat"}, nil).AnyTimes()

			var (
				got ccc.UUID
				err error
			)
			rr := f.serve(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				got, err = f.auth.API().CompletePending(r.Context(), w, sessioninfo.AuthEvent{Method: "email-otp", IdPAMR: []string{"otp"}})
			}), http.MethodPost, "/mfa", nil, cookies)

			if tt.wantErr != nil {
				if !tt.wantErr(err) {
					t.Errorf("CompletePending() error = %v", err)
				}
				if cookieNamed(rr, internalcookie.XSRFCookieName) != nil {
					t.Error("session cookies written for a refused completion")
				}

				return
			}
			if err != nil || got != sessionID {
				t.Fatalf("CompletePending() = %s, %v; want %s", got, err, sessionID)
			}
			if !pendingDeleted(rr) || cookieNamed(rr, internalcookie.XSRFCookieName) == nil {
				t.Error("want the session's cookies written and the pending cookie deleted")
			}
		})
	}
}

func TestAuth_PendingStatusAndCancel(t *testing.T) {
	t.Parallel()
	ctrl := gomock.NewController(t)
	f := newAuthFixture(t, ctrl, PasswordSignIn())
	identity := &sessioninfo.Identity{Method: sessioninfo.MethodWorkOS, Connection: "conn", Subject: "idp", Email: "pat@lakeside.edu"}
	cookies, pendingID := f.hold(t, &signInAttempt{identity: identity, reason: sessioninfo.ReasonLogin, returnURL: "/next"},
		&sessionstorage.PendingSignInError{Reason: sessioninfo.PendingConfirmation, UserID: ccc.NullUUIDFromUUID(ccc.Must(ccc.NewUUID())), Username: "pat"})
	f.livePending(pendingID)

	rr := f.serve(f.auth.Pending().Status(), http.MethodGet, "/pending", nil, cookies)
	var status struct {
		Reason    string    `json:"reason"`
		Email     string    `json:"email"`
		ExpiresAt time.Time `json:"expiresAt"`
		ReturnURL string    `json:"returnUrl"`
	}
	if err := json.Unmarshal(rr.Body.Bytes(), &status); err != nil || rr.Code != http.StatusOK {
		t.Fatalf("Status() = %d %s", rr.Code, rr.Body.String())
	}
	if status.Reason != "confirmation" || status.Email != "pat@lakeside.edu" || status.ReturnURL != "/next" || time.Until(status.ExpiresAt) <= 0 {
		t.Errorf("Status() = %+v", status)
	}
	if strings.Contains(rr.Body.String(), "pat\"") {
		t.Errorf("Status() = %s, want no account username", rr.Body.String())
	}

	f.store.EXPECT().DestroySession(gomock.Any(), pendingID).Return(nil)
	rr = f.serve(f.auth.Pending().Cancel(), http.MethodPost, "/pending/cancel", nil, cookies)
	if rr.Code != http.StatusOK || !pendingDeleted(rr) {
		t.Errorf("Cancel() = %d, pending cookie deleted %v; want 200 and deleted", rr.Code, pendingDeleted(rr))
	}

	// A cookie that is not the pending identity's is ignored.
	rr = f.serve(f.auth.Pending().Status(), http.MethodGet, "/pending", nil, []*http.Cookie{{Name: defaultPendingCookieName, Value: "forged", Secure: true, HttpOnly: true, SameSite: http.SameSiteLaxMode}})
	if rr.Code != http.StatusNotFound {
		t.Errorf("Status() with a forged cookie = %d, want 404", rr.Code)
	}
}

func TestPendingState_Encoding(t *testing.T) {
	t.Parallel()

	state := &pendingState{
		ID:        ccc.Must(ccc.NewUUID()),
		Identity:  sessioninfo.Identity{Method: sessioninfo.MethodWorkOS, Connection: "conn", Subject: "idp", Claims: json.RawMessage(`{"raw_attributes":{"a":"b"}}`)},
		Reason:    sessioninfo.PendingMFA,
		UserID:    ccc.NullUUIDFromUUID(ccc.Must(ccc.NewUUID())),
		ExpiresAt: time.Now().Add(time.Minute).Truncate(time.Second),
		Events:    []sessioninfo.AuthEvent{{Method: sessioninfo.MethodWorkOS, Connection: "conn"}},
		RoleNames: []string{},
	}
	encoded, err := encodePending(state)
	if err != nil {
		t.Fatalf("encodePending() error = %v", err)
	}
	got, err := decodePending(encoded)
	if err != nil {
		t.Fatalf("decodePending() error = %v", err)
	}
	if diff := cmp.Diff(state, got, cmpopts.EquateApproxTime(time.Second)); diff != "" {
		t.Errorf("round trip mismatch (-want +got):\n%s", diff)
	}

	// Claims too large for a cookie are refused rather than truncated.
	huge := *state
	noise := make([]byte, 4096)
	if _, err := rand.Read(noise); err != nil {
		t.Fatal(err)
	}
	huge.Identity.Claims = json.RawMessage(`"` + hex.EncodeToString(noise) + `"`)
	if _, err := encodePending(&huge); err == nil {
		t.Error("encodePending() of oversized claims error = nil, want a refusal")
	}
}

func TestAuthAPI_StartAuthenticatedSession(t *testing.T) {
	t.Parallel()

	userID := ccc.Must(ccc.NewUUID())
	sessionID := ccc.Must(ccc.NewUUID())
	events := []sessioninfo.AuthEvent{{Method: "magic-link"}, {Method: "email-otp"}}

	tests := []struct {
		name    string
		events  []sessioninfo.AuthEvent
		user    *sessionstorage.SessionUser
		wantErr func(error) bool
	}{
		{name: "the application's own steps are recorded and no sign-in policy is asked", events: events, user: &sessionstorage.SessionUser{ID: userID, Username: "pat"}},
		{name: "a disabled account is refused", events: events, user: &sessionstorage.SessionUser{ID: userID, Username: "pat", Disabled: true}, wantErr: httpio.HasUnauthorized},
		{name: "an event without a method is refused", events: []sessioninfo.AuthEvent{{}}, wantErr: httpio.HasBadRequest},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			ctrl := gomock.NewController(t)
			f := newAuthFixture(t, ctrl, PasswordSignIn())
			if tt.user != nil {
				f.store.EXPECT().User(gomock.Any(), userID).Return(tt.user, nil)
			}
			if tt.wantErr == nil {
				createSession(f.store, sessionID, func(req *sessioninfo.NewSessionRequest) {
					if req.Reason != sessioninfo.ReasonExternalAuth || req.Identity != nil || req.UserID != userID || !cmp.Equal(req.AuthEvents, events) {
						t.Errorf("CreateSession() request = %+v", req)
					}
				}, nil)
			}

			rr := httptest.NewRecorder()
			got, err := f.auth.API().StartAuthenticatedSession(context.Background(), rr, userID, tt.events)
			if tt.wantErr != nil {
				if !tt.wantErr(err) {
					t.Errorf("StartAuthenticatedSession() error = %v", err)
				}

				return
			}
			if err != nil || got != sessionID || cookieNamed(rr, internalcookie.AuthCookieName) == nil {
				t.Errorf("StartAuthenticatedSession() = %s, %v; want %s with its cookies", got, err, sessionID)
			}
		})
	}
}

func TestAuthAPI_StartImpersonatedSession(t *testing.T) {
	t.Parallel()

	bobID := ccc.Must(ccc.NewUUID())
	tests := []struct {
		name       string
		principal  accesstypes.Principal
		prepare    func(store *mock_sessionstorage.MockAccountStore)
		wantUserID ccc.UUID
	}{
		{
			name:      "a user principal's session belongs to the impersonated account",
			principal: accesstypes.UserPrincipal("bob"),
			prepare: func(store *mock_sessionstorage.MockAccountStore) {
				store.EXPECT().UserByUserName(gomock.Any(), "bob").Return(&sessionstorage.SessionUser{ID: bobID, Username: "bob"}, nil)
			},
			wantUserID: bobID,
		},
		{
			name:      "a role principal's session belongs to no account",
			principal: accesstypes.RolePrincipal("Viewer"),
			prepare: func(store *mock_sessionstorage.MockAccountStore) {
				store.EXPECT().UserByUserName(gomock.Any(), "alice").Return(nil, httpio.NewNotFoundMessage("no such user"))
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			ctrl := gomock.NewController(t)
			f := newAuthFixture(t, ctrl, PasswordSignIn())
			f.store.EXPECT().ImpersonationEnabled().Return(true)
			tt.prepare(f.store)
			f.store.EXPECT().CreateImpersonatedSession(gomock.Any(), gomock.Any(), gomock.Any()).DoAndReturn(
				func(_ context.Context, req *sessioninfo.NewSessionRequest, _ *sessioninfo.Impersonation) (ccc.UUID, error) {
					if req.UserID != tt.wantUserID || req.Reason != sessioninfo.ReasonImpersonation {
						t.Errorf("CreateImpersonatedSession() request = %+v, want UserID %s", req, tt.wantUserID)
					}

					return ccc.Must(ccc.NewUUID()), nil
				})

			req := &ImpersonationRequest{Actor: "alice", ActorRealm: "admin-portal", Principal: tt.principal}
			if _, err := f.auth.API().StartImpersonatedSession(context.Background(), httptest.NewRecorder(), req); err != nil {
				t.Errorf("StartImpersonatedSession() error = %v", err)
			}
		})
	}
}

func TestAuth_ValidateSession(t *testing.T) {
	t.Parallel()

	userID := ccc.Must(ccc.NewUUID())
	sessionID := ccc.Must(ccc.NewUUID())
	session := func(userID ccc.NullUUID, imp *sessioninfo.Impersonation) *sessioninfo.SessionData {
		return &sessioninfo.SessionData{SessionInfo: &sessioninfo.SessionInfo{ID: sessionID, Username: "pat", UpdatedAt: time.Now()}, UserID: userID, Impersonation: imp}
	}

	tests := []struct {
		name        string
		session     *sessioninfo.SessionData
		user        *sessionstorage.SessionUser
		userErr     error
		wantNext    bool
		wantAccount ccc.UUID
	}{
		{name: "a session is admitted with the account it belongs to, loaded by UserId", session: session(ccc.NullUUIDFromUUID(userID), nil), user: &sessionstorage.SessionUser{ID: userID, Username: "pat"}, wantNext: true, wantAccount: userID},
		{name: "a session whose account is disabled is refused", session: session(ccc.NullUUIDFromUUID(userID), nil), user: &sessionstorage.SessionUser{ID: userID, Username: "pat", Disabled: true}},
		{name: "a session whose account is gone is refused", session: session(ccc.NullUUIDFromUUID(userID), nil), userErr: httpio.NewNotFoundMessage("gone")},
		{name: "a session that belongs to no account (a pending identity's row) is refused", session: session(ccc.NullUUID{}, nil)},
		{
			name:     "a foreign actor's role-principal impersonation has no account to load",
			session:  session(ccc.NullUUID{}, &sessioninfo.Impersonation{Actor: "alice", ActorRealm: "admin", Principal: accesstypes.RolePrincipal("Viewer"), ExpiresAt: time.Now().Add(time.Hour)}),
			wantNext: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			ctrl := gomock.NewController(t)
			f := newAuthFixture(t, ctrl, PasswordSignIn())
			f.store.EXPECT().Session(gomock.Any(), sessionID).Return(tt.session, nil)
			if tt.user != nil || tt.userErr != nil {
				f.store.EXPECT().User(gomock.Any(), userID).Return(tt.user, tt.userErr)
			}

			rec := &nextRecorder{}
			rr := httptest.NewRecorder()
			r := httptest.NewRequestWithContext(context.WithValue(context.Background(), sessioninfo.CTXSessionID, sessionID), http.MethodGet, "/", http.NoBody)
			f.auth.ValidateSession(rec.handler()).ServeHTTP(rr, r)

			if rec.called != tt.wantNext {
				t.Fatalf("next called = %v, want %v (status %d)", rec.called, tt.wantNext, rr.Code)
			}
			if !tt.wantNext && rr.Code != http.StatusUnauthorized {
				t.Errorf("status = %d, want 401", rr.Code)
			}
			if tt.wantNext && sessioninfo.UserFromCtx(rec.ctx).ID != tt.wantAccount {
				t.Errorf("account in context = %s, want %s", sessioninfo.UserFromCtx(rec.ctx).ID, tt.wantAccount)
			}
		})
	}
}

func TestAuthAPI_AccountManagement(t *testing.T) {
	t.Parallel()

	userID := ccc.Must(ccc.NewUUID())

	t.Run("changing the password destroys the account's sessions by UserId and continues in a new one that records the password", func(t *testing.T) {
		t.Parallel()
		ctrl := gomock.NewController(t)
		f := newAuthFixture(t, ctrl, PasswordSignIn())
		f.store.EXPECT().User(gomock.Any(), userID).Return(&sessionstorage.SessionUser{ID: userID, Username: "pat", PasswordHash: hashed(t, "old")}, nil)
		gomock.InOrder(
			f.store.EXPECT().DestroyUserSessions(gomock.Any(), userID).Return(nil),
			f.store.EXPECT().SetUserPasswordHash(gomock.Any(), userID, gomock.Any()).Return(nil),
		)
		createSession(f.store, ccc.Must(ccc.NewUUID()), func(req *sessioninfo.NewSessionRequest) {
			if req.Reason != sessioninfo.ReasonRegeneration || req.UserID != userID || !cmp.Equal(req.AuthEvents, []sessioninfo.AuthEvent{{Method: sessioninfo.MethodPassword}}) {
				t.Errorf("CreateSession() request = %+v", req)
			}
		}, nil)

		if err := f.auth.API().ChangeSessionUserPassword(context.Background(), httptest.NewRecorder(), userID, &ChangeSessionUserPasswordRequest{OldPassword: "old", NewPassword: "new"}); err != nil {
			t.Errorf("ChangeSessionUserPassword() error = %v", err)
		}
	})

	t.Run("a wrong old password changes nothing", func(t *testing.T) {
		t.Parallel()
		ctrl := gomock.NewController(t)
		f := newAuthFixture(t, ctrl, PasswordSignIn())
		f.store.EXPECT().User(gomock.Any(), userID).Return(&sessionstorage.SessionUser{ID: userID, Username: "pat", PasswordHash: hashed(t, "old")}, nil)

		err := f.auth.API().ChangeSessionUserPassword(context.Background(), httptest.NewRecorder(), userID, &ChangeSessionUserPasswordRequest{OldPassword: "nope", NewPassword: "new"})
		if !httpio.HasBadRequest(err) {
			t.Errorf("ChangeSessionUserPassword() error = %v, want BadRequest", err)
		}
	})

	t.Run("deleting an account destroys its sessions before the account and its identities go", func(t *testing.T) {
		t.Parallel()
		ctrl := gomock.NewController(t)
		f := newAuthFixture(t, ctrl, PasswordSignIn())
		gomock.InOrder(
			f.store.EXPECT().User(gomock.Any(), userID).Return(&sessionstorage.SessionUser{ID: userID}, nil),
			f.store.EXPECT().DestroyUserSessions(gomock.Any(), userID).Return(nil),
			f.store.EXPECT().DeleteUser(gomock.Any(), userID).Return(nil),
		)
		if err := f.auth.API().DeleteSessionUser(context.Background(), userID); err != nil {
			t.Errorf("DeleteSessionUser() error = %v", err)
		}
	})

	t.Run("deactivating an account destroys its sessions", func(t *testing.T) {
		t.Parallel()
		ctrl := gomock.NewController(t)
		f := newAuthFixture(t, ctrl, PasswordSignIn())
		gomock.InOrder(
			f.store.EXPECT().DeactivateUser(gomock.Any(), userID).Return(nil),
			f.store.EXPECT().DestroyUserSessions(gomock.Any(), userID).Return(nil),
		)
		if err := f.auth.API().DeactivateSessionUser(context.Background(), userID); err != nil {
			t.Errorf("DeactivateSessionUser() error = %v", err)
		}
	})

	t.Run("an account's last means of sign-in is not unlinked", func(t *testing.T) {
		t.Parallel()
		ctrl := gomock.NewController(t)
		f := newAuthFixture(t, ctrl, PasswordSignIn())
		identityID := ccc.Must(ccc.NewUUID())
		f.store.EXPECT().UnlinkIdentity(gomock.Any(), identityID).Return(httpio.NewConflictMessageWithError(sessionstorage.ErrLastSignInMethod, "last"))

		if err := f.auth.API().UnlinkIdentity(context.Background(), identityID); !errors.Is(err, sessionstorage.ErrLastSignInMethod) || !httpio.HasConflict(err) {
			t.Errorf("UnlinkIdentity() error = %v, want ErrLastSignInMethod (Conflict)", err)
		}
	})
}

func TestPendingRedirectURL(t *testing.T) {
	t.Parallel()

	tests := []struct {
		loginURL, returnURL, want string
	}{
		{"/login", "/dashboard", "/login?pending=mfa&returnUrl=%2Fdashboard"},
		{"/login", "/", "/login?pending=mfa"},
		{"/signin?tab=sso", "", "/signin?pending=mfa&tab=sso"},
	}
	for _, tt := range tests {
		if got := pendingRedirectURL(tt.loginURL, sessioninfo.PendingMFA, tt.returnURL); got != tt.want {
			t.Errorf("pendingRedirectURL(%q, %q) = %q, want %q", tt.loginURL, tt.returnURL, got, tt.want)
		}
	}
}
