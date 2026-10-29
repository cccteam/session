package session

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"maps"
	"net/http"
	"net/http/httptest"
	"net/url"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/cccteam/ccc"
	"github.com/cccteam/ccc/accesstypes"
	"github.com/cccteam/ccc/securehash"
	"github.com/cccteam/httpio"
	"github.com/cccteam/session/azure"
	"github.com/cccteam/session/google"
	internalcookie "github.com/cccteam/session/internal/cookie"
	"github.com/cccteam/session/internal/sessioncore"
	"github.com/cccteam/session/internal/signinflow"
	"github.com/cccteam/session/internal/workos"
	"github.com/cccteam/session/mock/mock_azure"
	"github.com/cccteam/session/mock/mock_google"
	"github.com/cccteam/session/mock/mock_signin"
	"github.com/cccteam/session/sessioninfo"
	"github.com/cccteam/session/sessionstorage"
	"github.com/cccteam/session/sessionstorage/mock/mock_sessionstorage"
	"github.com/cccteam/session/signin"
	"github.com/go-playground/errors/v5"
	"github.com/google/go-cmp/cmp"
	"github.com/google/go-cmp/cmp/cmpopts"
	gomock "go.uber.org/mock/gomock"
)

// mockTx is the transaction type the mocked store is generic over. The hooks an Auth
// over it takes are typed to it, as a Postgres Auth's are to pgx.Tx.
type mockTx struct{}

// newAuthStoreMock is an AuthStore mock with the constructor's probes answered: no
// custom data and no OIDC-only features.
func newAuthStoreMock(ctrl *gomock.Controller) *mock_sessionstorage.MockAuthStore[mockTx] {
	storage := mock_sessionstorage.NewMockAuthStore[mockTx](ctrl)
	storage.EXPECT().CustomUserDataType().Return(nil).AnyTimes()
	storage.EXPECT().UserDataLoginHookConfigured().Return(false).AnyTimes()
	storage.EXPECT().OIDCUsersEnabled().Return(false).AnyTimes()
	storage.EXPECT().SetUsernameIsEmail(gomock.Any()).AnyTimes()
	// The bookkeeping after a sign-in, and the hint the session read looks for, read
	// an empty store unless a test says otherwise.
	storage.EXPECT().ClaimVerifiedEmail(gomock.Any(), gomock.Any(), gomock.Any()).Return(false, nil).AnyTimes()
	storage.EXPECT().IdentitiesByUser(gomock.Any(), gomock.Any()).Return(nil, nil).AnyTimes()

	return storage
}

// resolveAll is an account rule of a method's identity type I that provisions the user
// pat for every identity. It fills a registration's resolver slot in tests whose mocked
// store never runs it.
func resolveAll[I any]() func(context.Context, mockTx, *I) (*signin.Resolution, error) {
	return func(context.Context, mockTx, *I) (*signin.Resolution, error) {
		return signin.Provision(&signin.NewUser{Username: "pat"}, nil), nil
	}
}

// authFixture is an Auth over a mocked store, with password sign-in registered. A test
// registers an external method over a mocked authenticator through its package's
// Config.Authenticator, the registration path production takes with the real one.
type authFixture struct {
	t        *testing.T
	auth     *Auth[NoCustomData, NoCustomData, mockTx]
	password *PasswordMethod
	store    *mock_sessionstorage.MockAuthStore[mockTx]
	// linked records the IdentityLinked hook's calls.
	linked []ccc.UUID
	// policyAsked counts the calls of the sign-in policy NewAuth was given.
	policyAsked int
	// signedIn is the last sign-in the store was asked for.
	signedIn *storeSignIn
	// held are the pending sign-ins the store was asked to hold, by row ID, as the
	// pending sign-ins table would hold them.
	held map[ccc.UUID]*sessionstorage.PendingSignIn
	// touched records the users whose last sign-in the store was asked to touch, and
	// touchErr is what the store answers.
	touched  []ccc.UUID
	touchErr error
	// attempts is the sign-in attempts table as the store would hold it, keyed by the
	// normalized name, under the clock the fake store and the limiter share; the
	// counters say how often the store was asked.
	mu            sync.Mutex
	attempts      map[string]*sessionstorage.SignInAttempts
	attemptReads  int
	attemptWrites int
	attemptClears int
	clock         time.Time
	// signedInCalls records the SignedInHook's calls, and signedInErr is what it answers.
	signedInCalls []*SignedIn
	signedInErr   error
}

// storeSignIn is one call of the mocked store's SignIn: the request, the account rules
// of the identity's registration and the Auth's policy, as the store received them.
type storeSignIn struct {
	req      *sessioninfo.NewSessionRequest
	rule     signin.AccountRule[mockTx]
	standard signin.StandardAccountRule
	policy   signin.Policy[mockTx]
	accept   signinflow.InvitationAcceptor
}

func newAuthFixture(t *testing.T, ctrl *gomock.Controller, options ...AuthOption) *authFixture {
	t.Helper()

	return newAuthFixtureWith(t, ctrl, nil, options...)
}

// newAuthFixtureWith is newAuthFixture with password options for the password
// method's registration.
func newAuthFixtureWith(t *testing.T, ctrl *gomock.Controller, passwordOptions []PasswordOption, options ...AuthOption) *authFixture {
	t.Helper()

	return newAuthFixtureOf(t, ctrl, true, passwordOptions, options...)
}

// newAuthFixtureWithoutPassword is the fixture with no password method registered: the
// Auth a registration that synchronizes roles stands alone on (f.password is nil).
func newAuthFixtureWithoutPassword(t *testing.T, ctrl *gomock.Controller, options ...AuthOption) *authFixture {
	t.Helper()

	return newAuthFixtureOf(t, ctrl, false, nil, options...)
}

func newAuthFixtureOf(t *testing.T, ctrl *gomock.Controller, withPassword bool, passwordOptions []PasswordOption, options ...AuthOption) *authFixture {
	t.Helper()

	f := &authFixture{
		t: t, store: newAuthStoreMock(ctrl), held: map[ccc.UUID]*sessionstorage.PendingSignIn{},
		attempts: map[string]*sessionstorage.SignInAttempts{}, clock: time.Now(),
	}
	f.store.EXPECT().SignInAttempts(gomock.Any(), gomock.Any()).DoAndReturn(f.attemptsOf).AnyTimes()
	f.store.EXPECT().RecordSignInFailure(gomock.Any(), gomock.Any(), gomock.Any()).DoAndReturn(f.recordFailure).AnyTimes()
	f.store.EXPECT().ClearSignInAttempts(gomock.Any(), gomock.Any()).DoAndReturn(f.clearAttempts).AnyTimes()
	f.store.EXPECT().PendingSignIn(gomock.Any(), gomock.Any()).DoAndReturn(f.livePending).AnyTimes()
	f.store.EXPECT().TouchUserSignIn(gomock.Any(), gomock.Any()).DoAndReturn(func(_ context.Context, userID ccc.UUID) error {
		f.touched = append(f.touched, userID)

		return f.touchErr
	}).AnyTimes()
	hook := func(_ context.Context, userID ccc.UUID, _ *sessioninfo.Identity) error {
		f.linked = append(f.linked, userID)

		return errors.New("notification failed: logged, and the link stands")
	}
	policy := func(context.Context, mockTx, *sessioninfo.NewSessionRequest) (*signin.Decision, error) {
		f.policyAsked++

		return signin.Allow(), nil
	}
	a, err := NewAuth[NoCustomData, NoCustomData](f.store, cookieKey, append([]AuthOption{WithIdentityLinked(hook)}, options...)...)
	if err != nil {
		t.Fatalf("NewAuth() error = %v", err)
	}
	a.SetSignInPolicy(policy)
	f.auth = a
	if withPassword {
		f.password = PasswordSignIn(a, passwordOptions...)
		a.methods.attempts.SetClock(f.now)
	}

	return f
}

// now is the fixture's clock, shared by the fake store and the limiter.
func (f *authFixture) now() time.Time {
	f.mu.Lock()
	defer f.mu.Unlock()

	return f.clock
}

// advance moves the fixture's clock.
func (f *authFixture) advance(d time.Duration) {
	f.mu.Lock()
	defer f.mu.Unlock()

	f.clock = f.clock.Add(d)
}

// attemptsOf answers the store's read of a name's attempts as the table would.
func (f *authFixture) attemptsOf(_ context.Context, name string) (*sessionstorage.SignInAttempts, error) {
	f.mu.Lock()
	defer f.mu.Unlock()

	f.attemptReads++
	r, found := f.attempts[name]
	if !found {
		return nil, httpio.NewNotFoundMessage("no sign-in attempts recorded")
	}
	copied := *r

	return &copied, nil
}

// recordFailure answers the store's record of a failure as the table would, under
// the fixture's clock.
func (f *authFixture) recordFailure(_ context.Context, name string, limit sessionstorage.SignInAttemptLimit) (*sessionstorage.SignInAttempts, error) {
	f.mu.Lock()
	defer f.mu.Unlock()

	f.attemptWrites++
	next := f.attempts[name].Failed(name, f.clock, limit)
	next.UpdatedAt = f.clock
	f.attempts[name] = next
	copied := *next

	return &copied, nil
}

// clearAttempts answers the store's reset of a name as the table would.
func (f *authFixture) clearAttempts(_ context.Context, name string) error {
	f.mu.Lock()
	defer f.mu.Unlock()

	f.attemptClears++
	delete(f.attempts, name)

	return nil
}

// attemptsRecord is the fixture's record of a name, nil for none.
func (f *authFixture) attemptsRecord(name string) *sessionstorage.SignInAttempts {
	f.mu.Lock()
	defer f.mu.Unlock()

	return f.attempts[name]
}

// counts are the store's attempt calls so far: reads, writes and clears.
func (f *authFixture) counts() (reads, writes, clears int) {
	f.mu.Lock()
	defer f.mu.Unlock()

	return f.attemptReads, f.attemptWrites, f.attemptClears
}

// signedInHook is the SignedInHook the fixture's tests set: it records the call and
// answers signedInErr.
func (f *authFixture) signedInHook(_ context.Context, signedIn *SignedIn) error {
	f.mu.Lock()
	defer f.mu.Unlock()

	f.signedInCalls = append(f.signedInCalls, signedIn)

	return f.signedInErr
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

// expectHold expects the store to hold one pending identity for username, keeps the row
// as the pending sign-ins table would under a fresh ID, and returns that ID.
func (f *authFixture) expectHold(username string) ccc.UUID {
	pendingID := ccc.Must(ccc.NewUUID())
	f.store.EXPECT().HoldSignIn(gomock.Any(), gomock.Any()).DoAndReturn(func(_ context.Context, p *sessionstorage.PendingSignIn) (ccc.UUID, error) {
		if p.Username != username || len(p.TokenHash) != sha256.Size || p.ID != ccc.NilUUID || !p.ExpiresAt.After(time.Now()) || p.ConsumedAt != nil {
			f.t.Errorf("HoldSignIn() = %+v, want a live row for %s with a token hash and no ID", p, username)
		}
		held := *p
		held.ID = pendingID
		f.held[pendingID] = &held

		return pendingID, nil
	})

	return pendingID
}

// hold makes a pending identity as a sign-in would and returns the cookies that carry
// it, with its row's ID.
func (f *authFixture) hold(t *testing.T, at *signInAttempt, wait *signin.PendingSignInError) ([]*http.Cookie, ccc.UUID) {
	t.Helper()

	pendingID := f.expectHold(wait.Username)
	rr := httptest.NewRecorder()
	if _, err := f.auth.holdPending(context.Background(), rr, at, wait); err != nil {
		t.Fatalf("holdPending() error = %v", err)
	}

	return rr.Result().Cookies(), pendingID
}

// heldBy returns the held row whose token hash is tokenHash, live or not.
func (f *authFixture) heldBy(tokenHash []byte) *sessionstorage.PendingSignIn {
	for _, p := range f.held {
		if bytes.Equal(p.TokenHash, tokenHash) {
			return p
		}
	}

	return nil
}

// livePending answers the store's lookup by token hash as the table would: the held row
// while it is live, NotFound once consumed, expired or unknown.
func (f *authFixture) livePending(_ context.Context, tokenHash []byte) (*sessionstorage.PendingSignIn, error) {
	p := f.heldBy(tokenHash)
	if p == nil || p.ConsumedAt != nil || !time.Now().Before(p.ExpiresAt) {
		return nil, httpio.NewNotFoundMessage("no live pending sign-in")
	}
	row := *p

	return &row, nil
}

// expectConsume expects the pending identity id to be consumed once, by its token hash,
// and marks the held row consumed as the table's conditional update would.
func (f *authFixture) expectConsume(id ccc.UUID) {
	f.store.EXPECT().ConsumePendingSignIn(gomock.Any(), gomock.Any()).DoAndReturn(func(_ context.Context, tokenHash []byte) error {
		p := f.heldBy(tokenHash)
		if p == nil || p.ID != id {
			f.t.Errorf("ConsumePendingSignIn() of token hash %x, want the pending identity %s consumed", tokenHash, id)

			return httpio.NewNotFoundMessage("no live pending sign-in")
		}
		if p.ConsumedAt != nil || !time.Now().Before(p.ExpiresAt) {
			return httpio.NewNotFoundMessage("no live pending sign-in")
		}
		now := time.Now()
		p.ConsumedAt = &now

		return nil
	})
}

// consumed marks the held row id consumed, as a completion, a cancellation or a
// replacement would have.
func (f *authFixture) consumed(id ccc.UUID) {
	now := time.Now()
	f.held[id].ConsumedAt = &now
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

// createSession expects one CreateSession call: a session the application or a user
// operation starts, with no identity to resolve. prepare asserts on the request.
func createSession(store *mock_sessionstorage.MockAuthStore[mockTx], id ccc.UUID, prepare func(req *sessioninfo.NewSessionRequest)) {
	store.EXPECT().CreateSession(gomock.Any(), gomock.Any()).DoAndReturn(func(_ context.Context, req *sessioninfo.NewSessionRequest) (ccc.UUID, error) {
		if prepare != nil {
			prepare(req)
		}

		return id, nil
	})
}

// expectSignIn expects one sign-in through the store, given the resolver of the identity's
// method (none for a password identity) and the Auth's policy, and records the call in
// signedIn. prepare sees the request first: it asserts on it or plays the driver's
// resolution by setting its user. stop then answers as the driver would, with the error
// that stops the sign-in; nil answers id.
func (f *authFixture) expectSignIn(id ccc.UUID, prepare func(req *sessioninfo.NewSessionRequest), stop func(req *sessioninfo.NewSessionRequest) error) {
	f.store.EXPECT().SignIn(gomock.Any(), gomock.Any(), gomock.Any()).DoAndReturn(
		func(_ context.Context, req *sessioninfo.NewSessionRequest, rules sessionstorage.SignInRules[mockTx]) (ccc.UUID, error) {
			rule, standard, policy, accept := rules.Account, rules.Standard, rules.Policy, rules.Accept
			f.signedIn = &storeSignIn{req: req, rule: rule, standard: standard, policy: policy, accept: accept}
			if external := !namesItsUser(req.Identity); (rule != nil || standard != "") != external {
				f.t.Errorf("SignIn() given account rules = %v, %q; want some only for an external identity, not a %s one", rule != nil, standard, req.Identity.Method)
			}
			if policy == nil {
				f.t.Error("SignIn() given no policy, want the Auth's")
			}
			if prepare != nil {
				prepare(req)
			}
			if stop != nil {
				if err := stop(req); err != nil {
					return ccc.NilUUID, err
				}
			}

			return id, nil
		})
}

var eventOpts = cmp.Options{cmpopts.IgnoreFields(sessioninfo.AuthEvent{}, "At"), cmpopts.EquateEmpty()}

func TestNewAuth(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name       string
		storage    func(ctrl *gomock.Controller) sessionstorage.AuthStore[mockTx]
		options    []AuthOption
		wantErrHas string
	}{
		{
			name:    "an Auth is built before any sign-in method is registered on it",
			storage: func(ctrl *gomock.Controller) sessionstorage.AuthStore[mockTx] { return newAuthStoreMock(ctrl) },
		},
		{
			name:    "the cookie, session and pending-identity options",
			storage: func(ctrl *gomock.Controller) sessionstorage.AuthStore[mockTx] { return newAuthStoreMock(ctrl) },
			options: []AuthOption{WithPendingTimeout(time.Minute), WithPendingCookieName("pending"), WithCookieName("app"), WithSessionTimeout(time.Hour)},
		},
		{
			name:       "no storage",
			storage:    func(*gomock.Controller) sessionstorage.AuthStore[mockTx] { return nil },
			wantErrHas: "storage is required",
		},
		{
			name:       "a pending cookie named like the session cookie",
			storage:    func(ctrl *gomock.Controller) sessionstorage.AuthStore[mockTx] { return newAuthStoreMock(ctrl) },
			options:    []AuthOption{WithCookieName("same"), WithPendingCookieName("same")},
			wantErrHas: "differ from the session cookie name",
		},
		{
			name:       "a pending timeout that is not positive",
			storage:    func(ctrl *gomock.Controller) sessionstorage.AuthStore[mockTx] { return newAuthStoreMock(ctrl) },
			options:    []AuthOption{WithPendingTimeout(0)},
			wantErrHas: "pending timeout",
		},
		{
			name: "the group's identities and pending sign-ins tables are named on the store",
			storage: func(ctrl *gomock.Controller) sessionstorage.AuthStore[mockTx] {
				s := newAuthStoreMock(ctrl)
				s.EXPECT().SetIdentitiesTableName("StaffIdentities").Return(nil)
				s.EXPECT().SetPendingSignInsTableName("StaffPendingSignIns").Return(nil)

				return s
			},
			options: []AuthOption{WithIdentitiesTableName("StaffIdentities"), WithPendingSignInsTableName("StaffPendingSignIns")},
		},
		{
			name: "a table name the store refuses is reported under its option's name",
			storage: func(ctrl *gomock.Controller) sessionstorage.AuthStore[mockTx] {
				s := newAuthStoreMock(ctrl)
				s.EXPECT().SetIdentitiesTableName(`Staff"; DROP TABLE`).Return(errors.New("not an identifier"))

				return s
			},
			options:    []AuthOption{WithIdentitiesTableName(`Staff"; DROP TABLE`)},
			wantErrHas: "WithIdentitiesTableName",
		},
		{
			name: "the session and user tables are named on the store through the base options, and a refused name is reported under its option",
			storage: func(ctrl *gomock.Controller) sessionstorage.AuthStore[mockTx] {
				s := newAuthStoreMock(ctrl)
				s.EXPECT().SetSessionTableName("StaffSessions").Return(nil)
				s.EXPECT().SetUserTableName("Staff Users").Return(errors.New("not an identifier"))

				return s
			},
			options:    []AuthOption{WithSessionTableName("StaffSessions"), WithUserTableName("Staff Users")},
			wantErrHas: "WithUserTableName",
		},
		{
			name: "storage with the OIDC user anchor",
			storage: func(ctrl *gomock.Controller) sessionstorage.AuthStore[mockTx] {
				s := mock_sessionstorage.NewMockAuthStore[mockTx](ctrl)
				s.EXPECT().UserDataLoginHookConfigured().Return(false).AnyTimes()
				s.EXPECT().OIDCUsersEnabled().Return(true).AnyTimes()

				return s
			},
			wantErrHas: "OIDC-only",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			ctrl := gomock.NewController(t)

			a, err := NewAuth[NoCustomData, NoCustomData](tt.storage(ctrl), cookieKey, tt.options...)
			switch {
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

// newBareAuth is an Auth with no sign-in method registered, allowing every sign-in.
func newBareAuth(t *testing.T, ctrl *gomock.Controller) *Auth[NoCustomData, NoCustomData, mockTx] {
	t.Helper()

	a, err := NewAuth[NoCustomData, NoCustomData](newAuthStoreMock(ctrl), cookieKey)
	if err != nil {
		t.Fatalf("NewAuth() error = %v", err)
	}

	return a
}

// registrationPanic runs register and returns what it panicked with, or nil.
func registrationPanic(register func()) (recovered any) {
	defer func() { recovered = recover() }()
	register()

	return nil
}

func TestAuth_RegisterSignInMethods(t *testing.T) {
	t.Parallel()

	t.Run("each method's registration returns its own handlers, every method on one Auth", func(t *testing.T) {
		t.Parallel()
		ctrl := gomock.NewController(t)
		a := newBareAuth(t, ctrl)

		password := PasswordSignIn(a, AutoUpgradeHashes(false))
		sso := workos.SignIn(a, "workos", resolveAll[workos.Identity](), &workos.Config{APIKey: "sk", ClientID: "client", RedirectURL: "https://app/sso/callback", BaseURL: "https://workos.test", LoginURL: "/signin"})
		entra := azure.SignIn(a, "azure", resolveAll[azure.Identity](), &azure.Config{RoleSync: signin.DisableRoleSync(), Authority: testAuthority, Tenants: azure.Tenant(tenantLake), ClientID: "client", ClientSecret: "secret", RedirectURL: "https://app/azure/callback", LoginURL: "/signin"})
		workspace := google.SignIn(a, "google", resolveAll[google.Identity](), &google.Config{RoleSync: google.DisableRoleSync(), ClientID: "client", ClientSecret: "secret", RedirectURL: "https://app/google/callback", Workspaces: google.Workspace("lakeside", "example.com")})

		for name, h := range map[string]http.HandlerFunc{
			"PasswordMethod.Login":              password.Login(),
			"PasswordMethod.ChangeUserPassword": password.ChangeUserPassword(),
			"workos.Method.Login":               sso.Login(),
			"workos.Method.Callback":            sso.Callback(),
			"azure.Method.Login":                entra.Login(),
			"azure.Method.Callback":             entra.Callback(),
			"azure.Method.FrontChannelLogout":   entra.FrontChannelLogout(),
			"google.Method.Login":               workspace.Login(),
			"google.Method.Callback":            workspace.Callback(),
		} {
			if h == nil {
				t.Errorf("%s() = nil", name)
			}
		}
		if a.methods.autoUpgrade {
			t.Error("the password method's options were not applied: autoUpgrade = true")
		}
	})

	t.Run("a registration serving several issuers scopes a front-channel logout by the issuer the request names, and one naming none, as Entra sends it, by the declared issuers live sessions carry the sid under", func(t *testing.T) {
		t.Parallel()
		f := newAuthFixture(t, gomock.NewController(t))
		h := f.auth.RegisterExternal(&signin.Registration[mockTx]{
			Name: "any-entra", Method: sessioninfo.MethodAzure, FrontChannelLogout: true,
			Issuers: signin.IssuersMatching(func(iss string) bool { return strings.HasPrefix(iss, "https://login/") }),
			AccountRule: func(context.Context, mockTx, *sessioninfo.NewSessionRequest) (*signin.Resolution, error) {
				return signin.Reject(""), nil
			},
			Build: func(signin.StateCookies) (*signin.Method, error) {
				return &signin.Method{Name: sessioninfo.MethodAzure}, nil
			},
		})

		// Entra sends the sid alone: the sessions under the declared issuers the sid is
		// recorded under end, a session under an undeclared issuer stays.
		f.store.EXPECT().ProviderSessionIssuers(gomock.Any(), "sid-9").Return([]string{"https://evil/hilltop", "https://login/hilltop", "https://login/valley"}, nil)
		f.store.EXPECT().DestroySessionsByProviderSessionID(gomock.Any(), "https://login/hilltop", "sid-9").Return(nil)
		f.store.EXPECT().DestroySessionsByProviderSessionID(gomock.Any(), "https://login/valley", "sid-9").Return(nil)
		if rr := f.serve(h.FrontChannelLogout, http.MethodGet, "/any/logout?sid=sid-9", nil, nil); rr.Code != http.StatusOK {
			t.Errorf("FrontChannelLogout() naming no issuer status = %d, want 200: %s", rr.Code, rr.Body.String())
		}
		// A sid no live session carries ends nothing and is still 200.
		f.store.EXPECT().ProviderSessionIssuers(gomock.Any(), "sid-unknown").Return(nil, nil)
		if rr := f.serve(h.FrontChannelLogout, http.MethodGet, "/any/logout?sid=sid-unknown", nil, nil); rr.Code != http.StatusOK {
			t.Errorf("FrontChannelLogout() for an unknown sid status = %d, want 200: %s", rr.Code, rr.Body.String())
		}
		if rr := f.serve(h.FrontChannelLogout, http.MethodGet, "/any/logout?sid=sid-9&iss="+url.QueryEscape("https://evil/hilltop"), nil, nil); rr.Code != http.StatusBadRequest {
			t.Errorf("FrontChannelLogout() naming an issuer outside the set status = %d, want 400", rr.Code)
		}
		f.store.EXPECT().DestroySessionsByProviderSessionID(gomock.Any(), "https://login/hilltop", "sid-9").Return(nil)
		if rr := f.serve(h.FrontChannelLogout, http.MethodGet, "/any/logout?sid=sid-9&iss="+url.QueryEscape("https://login/hilltop"), nil, nil); rr.Code != http.StatusOK {
			t.Errorf("FrontChannelLogout() naming an issuer in the set status = %d, want 200: %s", rr.Code, rr.Body.String())
		}
	})

	t.Run("two Entra tenants are two registrations of the Azure method, each with its own handlers and resolver", func(t *testing.T) {
		t.Parallel()
		a := newBareAuth(t, gomock.NewController(t))
		cfg := func(tenant string) *azure.Config {
			return &azure.Config{RoleSync: signin.DisableRoleSync(), Authority: testAuthority, Tenants: azure.Tenant(tenant), ClientID: "client", ClientSecret: "secret", RedirectURL: "https://app/" + tenant + "/callback"}
		}

		lakeside := azure.SignIn(a, "lakeside", resolveAll[azure.Identity](), cfg(tenantLake))
		riverside := azure.SignIn(a, "riverside", resolveAll[azure.Identity](), cfg(tenantRiver))

		if lakeside.Callback() == nil || riverside.Callback() == nil {
			t.Fatal("a registration returned no callback handler")
		}
		external := a.registered().external
		if len(external) != 2 || external["lakeside"] == nil || external["riverside"] == nil || external["lakeside"].rule == nil || external["riverside"].rule == nil ||
			external["lakeside"].standard != signin.MembersOfDirectory || external["riverside"].standard != signin.MembersOfDirectory {
			t.Errorf("registered external methods = %v, want lakeside and riverside, each with its rule and the standard rule", slices.Sorted(maps.Keys(external)))
		}
	})

	t.Run("a front-channel logout is scoped by its registration's issuer: a sid alone ends that issuer's sessions, and another issuer's name is refused", func(t *testing.T) {
		t.Parallel()
		f := newAuthFixture(t, gomock.NewController(t))
		cfg := func(tenant string) *azure.Config {
			return &azure.Config{RoleSync: signin.DisableRoleSync(), Authority: testAuthority, Tenants: azure.Tenant(tenant), ClientID: "client", ClientSecret: "secret", RedirectURL: "https://app/" + tenant + "/callback"}
		}
		azure.SignIn(f.auth, "lakeside", resolveAll[azure.Identity](), cfg(tenantLake))
		riverside := azure.SignIn(f.auth, "riverside", resolveAll[azure.Identity](), cfg(tenantRiver))

		// Entra may send the sid alone: the route's registration supplies the issuer.
		f.store.EXPECT().DestroySessionsByProviderSessionID(gomock.Any(), entraIssuer(tenantRiver), "sid-1").Return(nil)
		if rr := f.serve(riverside.FrontChannelLogout(), http.MethodGet, "/riverside/logout?sid=sid-1", nil, nil); rr.Code != http.StatusOK {
			t.Errorf("FrontChannelLogout() with a sid alone status = %d, want 200: %s", rr.Code, rr.Body.String())
		}
		// Lakeside's issuer at riverside's route is refused before the store is asked.
		if rr := f.serve(riverside.FrontChannelLogout(), http.MethodGet, "/riverside/logout?sid=sid-1&iss="+url.QueryEscape(entraIssuer(tenantLake)), nil, nil); rr.Code != http.StatusBadRequest {
			t.Errorf("FrontChannelLogout() naming the other registration's issuer status = %d, want 400", rr.Code)
		}
	})

	t.Run("the Azure front-channel logout ends the sessions under the sid it names, without a session of its own", func(t *testing.T) {
		t.Parallel()
		f := newAuthFixture(t, gomock.NewController(t))
		entra := azure.SignIn(f.auth, "azure", resolveAll[azure.Identity](), &azure.Config{RoleSync: signin.DisableRoleSync(), Authority: testAuthority, Tenants: azure.Tenant(tenantLake), ClientID: "client", ClientSecret: "secret", RedirectURL: "https://app/azure/callback"})

		f.store.EXPECT().DestroySessionsByProviderSessionID(gomock.Any(), entraIssuer(tenantLake), "sid-1").Return(nil)
		if rr := f.serve(entra.FrontChannelLogout(), http.MethodGet, "/azure/logout?sid=sid-1&iss="+url.QueryEscape(entraIssuer(tenantLake)), nil, nil); rr.Code != http.StatusOK {
			t.Errorf("FrontChannelLogout() status = %d, want 200: %s", rr.Code, rr.Body.String())
		}
		if rr := f.serve(entra.FrontChannelLogout(), http.MethodGet, "/azure/logout", nil, nil); rr.Code != http.StatusBadRequest {
			t.Errorf("FrontChannelLogout() without a sid status = %d, want 400", rr.Code)
		}
		// The store is not asked: a request naming another issuer is refused first.
		if rr := f.serve(entra.FrontChannelLogout(), http.MethodGet, "/azure/logout?sid=sid-1&iss="+url.QueryEscape(entraIssuer(tenantRiver)), nil, nil); rr.Code != http.StatusBadRequest {
			t.Errorf("FrontChannelLogout() naming another issuer status = %d, want 400", rr.Code)
		}
	})
}

func TestAuth_RegistrationRefused(t *testing.T) {
	t.Parallel()

	sso := func(a *Auth[NoCustomData, NoCustomData, mockTx]) {
		workos.SignIn(a, "workos", resolveAll[workos.Identity](), &workos.Config{APIKey: "sk", ClientID: "client", RedirectURL: "https://app/sso/callback"})
	}
	entra := func(a *Auth[NoCustomData, NoCustomData, mockTx]) {
		azure.SignIn(a, "azure", resolveAll[azure.Identity](), &azure.Config{RoleSync: signin.DisableRoleSync(), Authority: testAuthority, Tenants: azure.Tenant(tenantLake), ClientID: "client", ClientSecret: "secret", RedirectURL: "https://app/azure/callback"})
	}
	workspace := func(a *Auth[NoCustomData, NoCustomData, mockTx]) {
		google.SignIn(a, "google", resolveAll[google.Identity](), &google.Config{RoleSync: google.DisableRoleSync(), ClientID: "client", ClientSecret: "secret", RedirectURL: "https://app/google/callback", Workspaces: google.Workspace("lakeside", "example.com")})
	}
	password := func(a *Auth[NoCustomData, NoCustomData, mockTx]) { PasswordSignIn(a) }

	// served serves one request through the Auth's middleware, as a mounted router would.
	served := func(a *Auth[NoCustomData, NoCustomData, mockTx]) {
		r := httptest.NewRequestWithContext(context.Background(), http.MethodGet, "/", http.NoBody)
		a.StartSession(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {})).ServeHTTP(httptest.NewRecorder(), r)
	}

	allow := func(context.Context, mockTx, *sessioninfo.NewSessionRequest) (*signin.Decision, error) {
		return signin.Allow(), nil
	}
	setPolicy := func(a *Auth[NoCustomData, NoCustomData, mockTx]) { a.SetSignInPolicy(allow) }

	tests := []struct {
		name string
		// before runs on the Auth first, and must not panic.
		before   func(a *Auth[NoCustomData, NoCustomData, mockTx])
		register func(a *Auth[NoCustomData, NoCustomData, mockTx])
		// wantHas is the text the panic must say.
		wantHas string
	}{
		{
			name:   "the password method registered twice",
			before: password, register: password, wantHas: "password sign-in method is registered twice",
		},
		{
			name:   "the WorkOS method registered twice",
			before: sso, register: sso, wantHas: "workos sign-in method is registered twice",
		},
		{
			name: "a registration whose name cannot name its state cookie",
			register: func(a *Auth[NoCustomData, NoCustomData, mockTx]) {
				azure.SignIn(a, "lake side", resolveAll[azure.Identity](), &azure.Config{RoleSync: signin.DisableRoleSync(), Authority: testAuthority, Tenants: azure.Tenant(tenantLake), ClientID: "client", ClientSecret: "secret", RedirectURL: "https://app/azure/callback"})
			},
			wantHas: `registered under the name "lake side", which cannot name its state cookie`,
		},
		{
			name:   "the Azure method registered twice",
			before: entra, register: entra, wantHas: "azure sign-in method is registered twice",
		},
		{
			name:   "the Google method registered twice",
			before: workspace, register: workspace, wantHas: "google sign-in method is registered twice",
		},
		{
			name:     "a method registered after the Auth served its first request",
			before:   func(a *Auth[NoCustomData, NoCustomData, mockTx]) { password(a); served(a) },
			register: sso, wantHas: "after the Auth is in use",
		},
		{
			name:   "a first method registered after the Auth served a request",
			before: served, register: password, wantHas: "after the Auth is in use",
		},
		{
			name: "a method registered after the Auth hashed a password through its API",
			before: func(a *Auth[NoCustomData, NoCustomData, mockTx]) {
				pw := "pw"
				store, ok := a.storage.(*mock_sessionstorage.MockAuthStore[mockTx])
				if !ok {
					panic("the Auth's storage is not the mock")
				}
				store.EXPECT().CreateUser(gomock.Any(), gomock.Any(), nil).Return(&sessionstorage.SessionUser{}, nil)
				if _, err := a.API().CreateSessionUser(context.Background(), &CreateUserRequest{Username: "pat", Password: &pw}); err != nil {
					panic(err)
				}
			},
			register: password, wantHas: "after the Auth is in use",
		},
		{
			name:   "the sign-in policy set twice",
			before: setPolicy, register: setPolicy, wantHas: "set twice",
		},
		{
			name:   "the sign-in policy set after the Auth is in use",
			before: served, register: setPolicy, wantHas: "after the Auth served a request",
		},
		{
			name:     "a nil sign-in policy",
			register: func(a *Auth[NoCustomData, NoCustomData, mockTx]) { a.SetSignInPolicy(nil) },
			wantHas:  "given nil",
		},
		{
			name: "a method asking for the front-channel logout handler without declaring its issuers",
			register: func(a *Auth[NoCustomData, NoCustomData, mockTx]) {
				a.RegisterExternal(&signin.Registration[mockTx]{
					Name: "bare", Method: sessioninfo.AuthMethod("bare"), FrontChannelLogout: true,
					AccountRule: func(context.Context, mockTx, *sessioninfo.NewSessionRequest) (*signin.Resolution, error) {
						return signin.Reject(""), nil
					},
					Build: func(signin.StateCookies) (*signin.Method, error) { return &signin.Method{Name: "bare"}, nil },
				})
			},
			wantHas: "declaring its issuers",
		},
		{
			name: "the WorkOS method without an account rule, since it has no standard rule",
			register: func(a *Auth[NoCustomData, NoCustomData, mockTx]) {
				workos.SignIn(a, "workos", nil, &workos.Config{APIKey: "sk", ClientID: "client", RedirectURL: "https://app/sso/callback"})
			},
			wantHas: "rule is required",
		},
		{
			name: "a registration with neither a standard account rule nor a custom one",
			register: func(a *Auth[NoCustomData, NoCustomData, mockTx]) {
				a.RegisterExternal(&signin.Registration[mockTx]{
					Name: "bare", Method: sessioninfo.AuthMethod("bare"),
					Build: func(signin.StateCookies) (*signin.Method, error) { return &signin.Method{Name: "bare"}, nil },
				})
			},
			wantHas: "needs an account rule: it has no standard rule",
		},
		{
			name: "a registration naming a standard account rule that does not exist",
			register: func(a *Auth[NoCustomData, NoCustomData, mockTx]) {
				a.RegisterExternal(&signin.Registration[mockTx]{
					Name: "bare", Method: sessioninfo.AuthMethod("bare"), StandardRule: "everyone-welcome",
					Build: func(signin.StateCookies) (*signin.Method, error) { return &signin.Method{Name: "bare"}, nil },
				})
			},
			wantHas: `"everyone-welcome" is not a standard account rule: use signin.MembersOfDirectory`,
		},
		{
			name: "the Azure method with open sign-up, which one tenant cannot take",
			register: func(a *Auth[NoCustomData, NoCustomData, mockTx]) {
				azure.SignIn(a, "azure", nil, &azure.Config{RoleSync: signin.DisableRoleSync(), Authority: testAuthority, Tenants: azure.Tenant(tenantLake), ClientID: "client", ClientSecret: "secret", RedirectURL: "https://app/azure/callback", Accounts: signin.OpenSignUp})
			},
			wantHas: "Accounts: open sign-up is for any tenant or personal accounts",
		},
		{
			name: "the Google method with open sign-up, which one Workspace cannot take",
			register: func(a *Auth[NoCustomData, NoCustomData, mockTx]) {
				google.SignIn(a, "google", nil, &google.Config{RoleSync: google.DisableRoleSync(), ClientID: "client", ClientSecret: "secret", RedirectURL: "https://app/google/callback", Workspaces: google.Workspace("lakeside", "example.com"), Accounts: signin.OpenSignUp})
			},
			wantHas: "Accounts: open sign-up is for any Workspace or any Google account; a registration naming its Workspaces",
		},
		{
			name:   "a registration name used twice, by the same method",
			before: entra,
			register: func(a *Auth[NoCustomData, NoCustomData, mockTx]) {
				azure.SignIn(a, "azure", resolveAll[azure.Identity](), &azure.Config{RoleSync: signin.DisableRoleSync(), Authority: testAuthority, Tenants: azure.Tenant(tenantRiver), ClientID: "client", ClientSecret: "secret", RedirectURL: "https://app/other/callback"})
			},
			wantHas: `registered twice on one Auth under the name "azure"`,
		},
		{
			name:   "a registration name used twice, by another method",
			before: entra,
			register: func(a *Auth[NoCustomData, NoCustomData, mockTx]) {
				workos.SignIn(a, "azure", resolveAll[workos.Identity](), &workos.Config{APIKey: "sk", ClientID: "client", RedirectURL: "https://app/sso/callback"})
			},
			wantHas: `the workos sign-in method is registered twice on one Auth under the name "azure"`,
		},
		{
			name:   "an external registration named like the password method",
			before: password,
			register: func(a *Auth[NoCustomData, NoCustomData, mockTx]) {
				workos.SignIn(a, "password", resolveAll[workos.Identity](), &workos.Config{APIKey: "sk", ClientID: "client", RedirectURL: "https://app/sso/callback"})
			},
			wantHas: `registered twice on one Auth under the name "password"`,
		},
		{
			name: "a registration without a name",
			register: func(a *Auth[NoCustomData, NoCustomData, mockTx]) {
				google.SignIn(a, "", resolveAll[google.Identity](), &google.Config{RoleSync: google.DisableRoleSync(), ClientID: "client", ClientSecret: "secret", RedirectURL: "https://app/google/callback", Workspaces: google.Workspace("lakeside", "example.com")})
			},
			wantHas: "the google sign-in method is registered without a name",
		},
		{
			name:     "a cookie option given to the password method instead of NewAuth",
			register: func(a *Auth[NoCustomData, NoCustomData, mockTx]) { PasswordSignIn(a, WithCookieName("x")) },
			wantHas:  "pass cookie and session options to NewAuth",
		},
		{
			name: "an Azure method without its role sync slot",
			register: func(a *Auth[NoCustomData, NoCustomData, mockTx]) {
				azure.SignIn(a, "azure", resolveAll[azure.Identity](), &azure.Config{Authority: testAuthority, Tenants: azure.Tenant(tenantLake), ClientID: "client", ClientSecret: "secret", RedirectURL: "https://app/azure/callback"})
			},
			wantHas: "roleSync is required",
		},
		{
			name: "an Azure method without its Tenants",
			register: func(a *Auth[NoCustomData, NoCustomData, mockTx]) {
				azure.SignIn(a, "azure", resolveAll[azure.Identity](), &azure.Config{RoleSync: signin.DisableRoleSync(), Authority: testAuthority, ClientID: "client", ClientSecret: "secret", RedirectURL: "https://app/azure/callback"})
			},
			wantHas: "Tenants is required",
		},
		{
			name: "an Azure tenant id that is not a GUID",
			register: func(a *Auth[NoCustomData, NoCustomData, mockTx]) {
				azure.SignIn(a, "azure", resolveAll[azure.Identity](), &azure.Config{RoleSync: signin.DisableRoleSync(), Authority: testAuthority, Tenants: azure.Tenant("lakeside"), ClientID: "client", ClientSecret: "secret", RedirectURL: "https://app/azure/callback"})
			},
			wantHas: `Tenants: "lakeside" is not a tenant id`,
		},
		{
			name: "the consumer tenant listed as an Azure tenant",
			register: func(a *Auth[NoCustomData, NoCustomData, mockTx]) {
				azure.SignIn(a, "azure", resolveAll[azure.Identity](), &azure.Config{RoleSync: signin.DisableRoleSync(), Authority: testAuthority, Tenants: azure.Tenant(azure.ConsumerTenantID), ClientID: "client", ClientSecret: "secret", RedirectURL: "https://app/azure/callback"})
			},
			wantHas: "is Microsoft's consumer tenant, the personal accounts: use azure.PersonalAccounts()",
		},
		{
			name: "an Azure Authority that is not a base URL",
			register: func(a *Auth[NoCustomData, NoCustomData, mockTx]) {
				azure.SignIn(a, "azure", resolveAll[azure.Identity](), &azure.Config{RoleSync: signin.DisableRoleSync(), Authority: "https://login.microsoftonline.com/common", Tenants: azure.Tenant(tenantLake), ClientID: "client", ClientSecret: "secret", RedirectURL: "https://app/azure/callback"})
			},
			wantHas: `Authority: "https://login.microsoftonline.com/common" is not the base URL of a Microsoft identity platform`,
		},
		{
			name: "an Azure method synchronizing roles across any tenant",
			register: func(a *Auth[NoCustomData, NoCustomData, mockTx]) {
				azure.SignIn(a, "azure", resolveAll[azure.Identity](), &azure.Config{RoleSync: signin.RoleSync(mock_signin.NewMockUserRoleManager(gomock.NewController(t))), Authority: testAuthority, Tenants: azure.AnyTenant(), ClientID: "client", ClientSecret: "secret", RedirectURL: "https://app/azure/callback", Accounts: signin.InvitedUsersOnly})
			},
			wantHas: "RoleSync: role synchronization follows one tenant's application roles",
		},
		{
			name: "an Azure method admitting any tenant as members of the directory with no rule of its own",
			register: func(a *Auth[NoCustomData, NoCustomData, mockTx]) {
				azure.SignIn(a, "azure", nil, &azure.Config{RoleSync: signin.DisableRoleSync(), Authority: testAuthority, Tenants: azure.AnyTenant(), ClientID: "client", ClientSecret: "secret", RedirectURL: "https://app/azure/callback"})
			},
			wantHas: "Accounts: members of the directory with any tenant or personal accounts would sign up the world",
		},
		{
			name: "an Azure tenant list with no tenant",
			register: func(a *Auth[NoCustomData, NoCustomData, mockTx]) {
				azure.SignIn(a, "azure", resolveAll[azure.Identity](), &azure.Config{RoleSync: signin.DisableRoleSync(), Authority: testAuthority, Tenants: azure.Tenants(), ClientID: "client", ClientSecret: "secret", RedirectURL: "https://app/azure/callback"})
			},
			wantHas: "Tenants is required",
		},
		{
			name: "an Azure tenant listed twice",
			register: func(a *Auth[NoCustomData, NoCustomData, mockTx]) {
				azure.SignIn(a, "azure", resolveAll[azure.Identity](), &azure.Config{RoleSync: signin.DisableRoleSync(), Authority: testAuthority, Tenants: azure.Tenants(azure.Tenant(tenantLake), azure.Tenant(tenantLake)), ClientID: "client", ClientSecret: "secret", RedirectURL: "https://app/azure/callback"})
			},
			wantHas: "Tenants: the tenant \"" + tenantLake + "\" is listed twice",
		},
		{
			name: "an Azure tenant name used twice",
			register: func(a *Auth[NoCustomData, NoCustomData, mockTx]) {
				azure.SignIn(a, "azure", resolveAll[azure.Identity](), &azure.Config{RoleSync: signin.DisableRoleSync(), Authority: testAuthority, Tenants: azure.Tenants(azure.NamedTenant(tenantLake, "lakeside"), azure.NamedTenant(tenantRiver, "lakeside")), ClientID: "client", ClientSecret: "secret", RedirectURL: "https://app/azure/callback"})
			},
			wantHas: `Tenants: the name "lakeside" is used twice`,
		},
		{
			name: "an Azure method synchronizing roles across listed tenants",
			register: func(a *Auth[NoCustomData, NoCustomData, mockTx]) {
				azure.SignIn(a, "azure", resolveAll[azure.Identity](), &azure.Config{RoleSync: signin.RoleSync(mock_signin.NewMockUserRoleManager(gomock.NewController(t))), Authority: testAuthority, Tenants: azure.Tenants(azure.Tenant(tenantLake), azure.Tenant(tenantRiver)), ClientID: "client", ClientSecret: "secret", RedirectURL: "https://app/azure/callback", Accounts: signin.InvitedUsersOnly})
			},
			wantHas: "RoleSync: role synchronization follows one tenant's application roles",
		},
		{
			name: "an Azure method synchronizing roles for personal accounts",
			register: func(a *Auth[NoCustomData, NoCustomData, mockTx]) {
				azure.SignIn(a, "azure", resolveAll[azure.Identity](), &azure.Config{RoleSync: signin.RoleSync(mock_signin.NewMockUserRoleManager(gomock.NewController(t))), Authority: testAuthority, Tenants: azure.PersonalAccounts(), ClientID: "client", ClientSecret: "secret", RedirectURL: "https://app/azure/callback", Accounts: signin.InvitedUsersOnly})
			},
			wantHas: "RoleSync: role synchronization follows one tenant's application roles",
		},
		{
			name: "the Azure method with open sign-up on listed tenants",
			register: func(a *Auth[NoCustomData, NoCustomData, mockTx]) {
				azure.SignIn(a, "azure", nil, &azure.Config{RoleSync: signin.DisableRoleSync(), Authority: testAuthority, Tenants: azure.Tenants(azure.Tenant(tenantLake), azure.Tenant(tenantRiver)), ClientID: "client", ClientSecret: "secret", RedirectURL: "https://app/azure/callback", Accounts: signin.OpenSignUp})
			},
			wantHas: "Accounts: open sign-up is for any tenant or personal accounts",
		},
		{
			name: "an Azure method admitting personal accounts as members of the directory with no rule of its own",
			register: func(a *Auth[NoCustomData, NoCustomData, mockTx]) {
				azure.SignIn(a, "azure", nil, &azure.Config{RoleSync: signin.DisableRoleSync(), Authority: testAuthority, Tenants: azure.PersonalAccounts(), ClientID: "client", ClientSecret: "secret", RedirectURL: "https://app/azure/callback"})
			},
			wantHas: "Accounts: members of the directory with any tenant or personal accounts would sign up the world",
		},
		{
			name: "an Azure role sync slot without a manager",
			register: func(a *Auth[NoCustomData, NoCustomData, mockTx]) {
				azure.SignIn(a, "azure", resolveAll[azure.Identity](), &azure.Config{RoleSync: signin.RoleSync(nil), Authority: testAuthority, Tenants: azure.Tenant(tenantLake), ClientID: "client", ClientSecret: "secret", RedirectURL: "https://app/azure/callback"})
			},
			wantHas: "signin.RoleSync() requires a non-nil UserRoleManager",
		},
		{
			name: "a Google method without its Workspaces",
			register: func(a *Auth[NoCustomData, NoCustomData, mockTx]) {
				google.SignIn(a, "google", resolveAll[google.Identity](), &google.Config{RoleSync: google.DisableRoleSync(), ClientID: "client", ClientSecret: "secret", RedirectURL: "https://app/google/callback"})
			},
			wantHas: "Workspaces is required",
		},
		{
			name: "a Google Workspace without a domain",
			register: func(a *Auth[NoCustomData, NoCustomData, mockTx]) {
				google.SignIn(a, "google", resolveAll[google.Identity](), &google.Config{RoleSync: google.DisableRoleSync(), ClientID: "client", ClientSecret: "secret", RedirectURL: "https://app/google/callback", Workspaces: google.Workspace("lakeside")})
			},
			wantHas: `Workspaces: Workspace "lakeside" needs at least one domain`,
		},
		{
			name: "a Google Workspace without a name",
			register: func(a *Auth[NoCustomData, NoCustomData, mockTx]) {
				google.SignIn(a, "google", resolveAll[google.Identity](), &google.Config{RoleSync: google.DisableRoleSync(), ClientID: "client", ClientSecret: "secret", RedirectURL: "https://app/google/callback", Workspaces: google.Workspace("", "example.com")})
			},
			wantHas: "Workspaces: a Workspace needs a name",
		},
		{
			name: "a domain in two Google Workspaces",
			register: func(a *Auth[NoCustomData, NoCustomData, mockTx]) {
				google.SignIn(a, "google", resolveAll[google.Identity](), &google.Config{RoleSync: google.DisableRoleSync(), ClientID: "client", ClientSecret: "secret", RedirectURL: "https://app/google/callback", Workspaces: google.Workspaces(google.Workspace("lakeside", "example.com"), google.Workspace("riverside", "example.com"))})
			},
			wantHas: `Workspaces: the domain "example.com" belongs to two Workspaces`,
		},
		{
			name: "a Google method synchronizing roles across any Workspace",
			register: func(a *Auth[NoCustomData, NoCustomData, mockTx]) {
				google.SignIn(a, "google", resolveAll[google.Identity](), &google.Config{RoleSync: google.RoleSync(mock_signin.NewMockUserRoleManager(gomock.NewController(t)), "app-", google.DirectGroups()), ClientID: "client", ClientSecret: "secret", RedirectURL: "https://app/google/callback", Workspaces: google.AnyWorkspace(), Accounts: signin.InvitedUsersOnly})
			},
			wantHas: "RoleSync: role synchronization reads the groups of one Workspace",
		},
		{
			name: "a Google method admitting any Google account as members of the directory, with no rule of the application's own",
			register: func(a *Auth[NoCustomData, NoCustomData, mockTx]) {
				google.SignIn(a, "google", nil, &google.Config{RoleSync: google.DisableRoleSync(), ClientID: "client", ClientSecret: "secret", RedirectURL: "https://app/google/callback", Workspaces: google.AnyGoogleAccount()})
			},
			wantHas: "would sign up the world",
		},
		{
			name: "a Google Workspace list with no Workspace",
			register: func(a *Auth[NoCustomData, NoCustomData, mockTx]) {
				google.SignIn(a, "google", resolveAll[google.Identity](), &google.Config{RoleSync: google.DisableRoleSync(), ClientID: "client", ClientSecret: "secret", RedirectURL: "https://app/google/callback", Workspaces: google.Workspaces()})
			},
			wantHas: "Workspaces is required",
		},
		{
			name: "a Google Workspace name used twice",
			register: func(a *Auth[NoCustomData, NoCustomData, mockTx]) {
				google.SignIn(a, "google", resolveAll[google.Identity](), &google.Config{RoleSync: google.DisableRoleSync(), ClientID: "client", ClientSecret: "secret", RedirectURL: "https://app/google/callback", Workspaces: google.Workspaces(google.Workspace("lakeside", "example.com"), google.Workspace("lakeside", "example.org"))})
			},
			wantHas: `Workspaces: the name "lakeside" is used twice`,
		},
		{
			name: "a value that is not a Google domain name",
			register: func(a *Auth[NoCustomData, NoCustomData, mockTx]) {
				google.SignIn(a, "google", resolveAll[google.Identity](), &google.Config{RoleSync: google.DisableRoleSync(), ClientID: "client", ClientSecret: "secret", RedirectURL: "https://app/google/callback", Workspaces: google.Workspace("lakeside", "not a domain")})
			},
			wantHas: `Workspaces: "not a domain" is not a domain name`,
		},
		{
			name: "a Google method synchronizing roles across listed Workspaces",
			register: func(a *Auth[NoCustomData, NoCustomData, mockTx]) {
				google.SignIn(a, "google", resolveAll[google.Identity](), &google.Config{RoleSync: google.RoleSync(mock_signin.NewMockUserRoleManager(gomock.NewController(t)), "app-", google.DirectGroups()), ClientID: "client", ClientSecret: "secret", RedirectURL: "https://app/google/callback", Workspaces: google.Workspaces(google.Workspace("lakeside", "example.com"), google.Workspace("riverside", "example.org")), Accounts: signin.InvitedUsersOnly})
			},
			wantHas: "RoleSync: role synchronization reads the groups of one Workspace",
		},
		{
			name: "a Google method synchronizing roles for any Google account",
			register: func(a *Auth[NoCustomData, NoCustomData, mockTx]) {
				google.SignIn(a, "google", resolveAll[google.Identity](), &google.Config{RoleSync: google.RoleSync(mock_signin.NewMockUserRoleManager(gomock.NewController(t)), "app-", google.DirectGroups()), ClientID: "client", ClientSecret: "secret", RedirectURL: "https://app/google/callback", Workspaces: google.AnyGoogleAccount(), Accounts: signin.InvitedUsersOnly})
			},
			wantHas: "RoleSync: role synchronization reads the groups of one Workspace",
		},
		{
			name: "the Google method with open sign-up on listed Workspaces",
			register: func(a *Auth[NoCustomData, NoCustomData, mockTx]) {
				google.SignIn(a, "google", nil, &google.Config{RoleSync: google.DisableRoleSync(), ClientID: "client", ClientSecret: "secret", RedirectURL: "https://app/google/callback", Workspaces: google.Workspaces(google.Workspace("lakeside", "example.com"), google.Workspace("riverside", "example.org")), Accounts: signin.OpenSignUp})
			},
			wantHas: "Accounts: open sign-up is for any Workspace or any Google account",
		},
		{
			name: "a Google method admitting any Workspace as members of the directory with no rule of its own",
			register: func(a *Auth[NoCustomData, NoCustomData, mockTx]) {
				google.SignIn(a, "google", nil, &google.Config{RoleSync: google.DisableRoleSync(), ClientID: "client", ClientSecret: "secret", RedirectURL: "https://app/google/callback", Workspaces: google.AnyWorkspace()})
			},
			wantHas: "Accounts: members of the directory with any Workspace or any Google account would sign up the world",
		},
		{
			name: "a Google method without its role sync slot",
			register: func(a *Auth[NoCustomData, NoCustomData, mockTx]) {
				google.SignIn(a, "google", resolveAll[google.Identity](), &google.Config{ClientID: "client", ClientSecret: "secret", RedirectURL: "https://app/google/callback", Workspaces: google.Workspace("lakeside", "example.com")})
			},
			wantHas: "roleSync is required: pass google.RoleSync(manager, groupPrefix, lookup) or google.DisableRoleSync()",
		},
		{
			name: "a Google role sync slot without a manager",
			register: func(a *Auth[NoCustomData, NoCustomData, mockTx]) {
				google.SignIn(a, "google", resolveAll[google.Identity](), &google.Config{RoleSync: google.RoleSync(nil, "app-", google.DirectGroups()), ClientID: "client", ClientSecret: "secret", RedirectURL: "https://app/google/callback", Workspaces: google.Workspace("lakeside", "example.com")})
			},
			wantHas: "google.RoleSync() requires a non-nil UserRoleManager",
		},
		{
			name: "a Google role sync slot without a group prefix",
			register: func(a *Auth[NoCustomData, NoCustomData, mockTx]) {
				google.SignIn(a, "google", resolveAll[google.Identity](), &google.Config{RoleSync: google.RoleSync(mock_signin.NewMockUserRoleManager(gomock.NewController(t)), "", google.DirectGroups()), ClientID: "client", ClientSecret: "secret", RedirectURL: "https://app/google/callback", Workspaces: google.Workspace("lakeside", "example.com")})
			},
			wantHas: "google.RoleSync() requires a non-empty groupPrefix",
		},
		{
			name:     "a method registered on a nil Auth",
			register: func(*Auth[NoCustomData, NoCustomData, mockTx]) { PasswordSignIn(nil) },
			wantHas:  "registered on a nil Auth",
		},
		{
			name: "a method registered on a nil *Auth",
			register: func(*Auth[NoCustomData, NoCustomData, mockTx]) {
				workos.SignIn((*Auth[NoCustomData, NoCustomData, mockTx])(nil), "workos", resolveAll[workos.Identity](), &workos.Config{APIKey: "sk", ClientID: "client", RedirectURL: "https://app/sso/callback"})
			},
			wantHas: "registered on a nil *Auth",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			a := newBareAuth(t, gomock.NewController(t))
			if tt.before != nil {
				if got := registrationPanic(func() { tt.before(a) }); got != nil {
					t.Fatalf("the setup panicked: %v", got)
				}
			}

			got := registrationPanic(func() { tt.register(a) })
			if got == nil {
				t.Fatal("the registration did not panic")
			}
			msg := fmt.Sprint(got)
			if !strings.HasPrefix(msg, "session: ") || !strings.Contains(msg, tt.wantHas) {
				t.Errorf("panic = %q, want a session: message saying %q", msg, tt.wantHas)
			}
		})
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
			name:     "the right password starts a session for the user, recording the password method",
			password: "pw",
			prepare: func(f *authFixture) {
				f.expectSignIn(sessionID, func(req *sessioninfo.NewSessionRequest) {
					want := &sessioninfo.Identity{Method: sessioninfo.MethodPassword, Subject: userID.String()}
					if req.Reason != sessioninfo.ReasonLogin || req.UserID != userID || req.Username != "pat" || !cmp.Equal(req.Identity, want) || req.AuthEvents != nil {
						t.Errorf("SignIn() request = %+v", req)
					}
				}, nil)
			},
			wantStatus:  http.StatusOK,
			wantSession: true,
		},
		{
			name:     "a failed touch of the user's last sign-in is logged, and the sign-in goes on",
			password: "pw",
			prepare: func(f *authFixture) {
				f.touchErr = errors.New("users table unreachable")
				f.expectSignIn(sessionID, nil, nil)
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
			name:       "a password-less user fails every password",
			password:   "",
			user:       &sessionstorage.SessionUser{ID: userID, Username: "pat"},
			wantStatus: http.StatusUnauthorized,
		},
		{
			name:       "a disabled user is refused with its code",
			password:   "pw",
			user:       &sessionstorage.SessionUser{ID: userID, Username: "pat", PasswordHash: hashed(t, "pw"), Disabled: true},
			wantStatus: http.StatusUnauthorized,
			wantCode:   sessioninfo.RefusedUserDisabled,
		},
		{
			name:     "a policy denial is refused with the policy's code and writes no session cookie",
			password: "pw",
			prepare: func(f *authFixture) {
				f.expectSignIn(sessionID, nil, func(*sessioninfo.NewSessionRequest) error {
					return signinflow.Refusal("sso_required", sessioninfo.RefusedByPolicy, signin.ErrSignInDenied, "sign-in denied")
				})
			},
			wantStatus: http.StatusUnauthorized,
			wantCode:   "sso_required",
		},
		{
			name:     "a policy that requires MFA holds the sign-in as a pending identity and starts no session",
			password: "pw",
			prepare: func(f *authFixture) {
				f.expectSignIn(sessionID, nil, func(*sessioninfo.NewSessionRequest) error {
					return &signin.PendingSignInError{Reason: sessioninfo.PendingMFA, UserID: ccc.NullUUIDFromUUID(userID), Username: "pat"}
				})
				f.expectHold("pat")
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
			f := newAuthFixture(t, ctrl)

			user := tt.user
			if user == nil {
				user = &sessionstorage.SessionUser{ID: userID, Username: "pat", PasswordHash: hashed(t, "pw")}
			}
			f.store.EXPECT().UserByUserName(gomock.Any(), "pat").Return(user, nil)
			if tt.prepare != nil {
				tt.prepare(f)
			}

			rr := f.serve(f.password.Login(), http.MethodPost, "/login", map[string]string{"username": "pat", "password": tt.password}, nil)

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
			if tt.wantSession {
				// The store was given the policy NewAuth took: running it reaches the fixture's.
				if _, err := f.signedIn.policy(context.Background(), mockTx{}, f.signedIn.req); err != nil || f.policyAsked != 1 {
					t.Errorf("the policy the store was given ran the Auth's %d times, %v; want once", f.policyAsked, err)
				}
			}
			// The user's last sign-in is touched once the session stands, and only then.
			wantTouched := []ccc.UUID{}
			if tt.wantSession {
				wantTouched = []ccc.UUID{userID}
			}
			if !cmp.Equal(f.touched, wantTouched, cmpopts.EquateEmpty()) {
				t.Errorf("last sign-in touched for %v, want %v", f.touched, wantTouched)
			}
		})
	}
}

func TestAuth_ExternalLogin(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name         string
		target       string
		prepare      func(authn *mock_azure.MockAuthenticator)
		wantStatus   int
		wantLocation string
	}{
		{
			name:   "a local return path rides to the provider",
			target: "/azure/login?returnUrl=" + url.QueryEscape("/reports?id=1"),
			prepare: func(authn *mock_azure.MockAuthenticator) {
				authn.EXPECT().AuthCodeURL(gomock.Any(), gomock.Any(), "/reports?id=1", signin.LoginOptions{}).Return("https://idp/authorize?state=s", nil)
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
			name:       "a backslash scheme-relative return URL is refused",
			target:     "/azure/login?returnUrl=" + url.QueryEscape(`/\evil.example/`),
			wantStatus: http.StatusBadRequest,
		},
		{
			name:       "a return URL that a redirect would clean into a backslash scheme-relative one is refused",
			target:     "/azure/login?returnUrl=" + url.QueryEscape(`/./\evil.example/`),
			wantStatus: http.StatusBadRequest,
		},
		{
			name:   "a request for the account chooser rides to the provider",
			target: "/azure/login?returnUrl=%2Fhome&prompt=select_account",
			prepare: func(authn *mock_azure.MockAuthenticator) {
				authn.EXPECT().AuthCodeURL(gomock.Any(), gomock.Any(), "/home", signin.LoginOptions{SelectAccount: true}).Return("https://idp/authorize?state=s", nil)
			},
			wantStatus:   http.StatusFound,
			wantLocation: "https://idp/authorize?state=s",
		},
		{
			name:       "another prompt value is refused",
			target:     "/azure/login?prompt=none",
			wantStatus: http.StatusBadRequest,
		},
		{
			name:   "a provider that cannot start the login sends the browser back with a code",
			target: "/azure/login",
			prepare: func(authn *mock_azure.MockAuthenticator) {
				authn.EXPECT().AuthCodeURL(gomock.Any(), gomock.Any(), "", signin.LoginOptions{}).Return("", errors.New("discovery failed"))
			},
			wantStatus:   http.StatusFound,
			wantLocation: "/login?code=internal_error",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			ctrl := gomock.NewController(t)
			f := newAuthFixture(t, ctrl)
			authn := mock_azure.NewMockAuthenticator(ctrl)
			authn.EXPECT().LoginURL().Return("/login").AnyTimes()
			entra := azure.SignIn(f.auth, "azure", resolveAll[azure.Identity](), &azure.Config{RoleSync: signin.DisableRoleSync(), Tenants: azure.Tenant(tenantLake), Authenticator: authn})
			if tt.prepare != nil {
				tt.prepare(authn)
			}

			rr := f.serve(entra.Login(), http.MethodGet, tt.target, nil, nil)

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
	claims := `{"iss":"` + entraIssuer(tenantLake) + `","tid":"` + tenantLake + `","oid":"oid-1","preferred_username":"p.lee@lakeside.edu","email":"pat@lakeside.edu","roles":["Editor"],"amr":["pwd","mfa"],"sid":"sid-1"}`

	// resolved plays the driver: the identity resolves to the user pat.
	resolved := func(req *sessioninfo.NewSessionRequest) {
		req.UserID, req.Username = userID, "pat"
	}
	// recognizeEditor makes Editor a role the application knows, in every tenant
	// domain: the sign-in passes the role check that runs before the store is asked.
	recognizeEditor := func(roles *mock_signin.MockUserRoleManager) {
		roles.EXPECT().ResolveRole(gomock.Any(), global, "Editor").Return(accesstypes.Role(""), false, nil).AnyTimes()
		roles.EXPECT().ResolveRole(gomock.Any(), every, "Editor").Return(accesstypes.Role("Editor"), true, nil).AnyTimes()
	}

	tests := []struct {
		name    string
		claims  string
		prepare func(f *authFixture, roles *mock_signin.MockUserRoleManager)
		// wantIdentity is the identity the method's resolver decodes from the claims,
		// when the sign-in reached the store.
		wantIdentity *azure.Identity
		wantLocation string
		wantSession  bool
		wantPending  bool
	}{
		{
			name:   "a linked identity signs in by (tid, oid), and roles are reconciled for the user it resolved to",
			claims: claims,
			wantIdentity: &azure.Identity{
				TenantID: tenantLake, Organization: tenantLake, ObjectID: "oid-1", Email: "pat@lakeside.edu", PreferredUsername: "p.lee@lakeside.edu", Roles: []string{"Editor"}, AMR: []string{"pwd", "mfa"}, SessionID: "sid-1",
			},
			prepare: func(f *authFixture, roles *mock_signin.MockUserRoleManager) {
				f.expectSignIn(sessionID, func(req *sessioninfo.NewSessionRequest) {
					want := &sessioninfo.Identity{
						Method: sessioninfo.MethodAzure, Connection: tenantLake, Subject: "oid-1", Email: "pat@lakeside.edu", IDPAMR: []string{"pwd", "mfa"},
						SignInName: "p.lee@lakeside.edu", Organization: tenantLake, Attestation: sessioninfo.AttestedByEvidence,
					}
					if diff := cmp.Diff(want, req.Identity, cmpopts.IgnoreFields(sessioninfo.Identity{}, "Claims")); diff != "" || req.Reason != sessioninfo.ReasonLogin || string(req.Claims) != claims || req.ProviderSessionID != "sid-1" || req.ProviderSessionIssuer != entraIssuer(tenantLake) {
						t.Errorf("SignIn() request = %+v, mismatch (-want +got):\n%s", req, diff)
					}
					if diff := cmp.Diff([]string{"Editor"}, req.RoleNames); diff != "" {
						t.Errorf("SignIn() request RoleNames mismatch (-want +got):\n%s", diff)
					}
					resolved(req)
				}, nil)
				roles.EXPECT().UserRoles(gomock.Any(), accesstypes.User("pat")).Return(accesstypes.RoleCollection{}, nil)
				// Once before the store is asked, once at the reconciliation.
				roles.EXPECT().ResolveRole(gomock.Any(), global, "Editor").Return(accesstypes.Role(""), false, nil).Times(2)
				roles.EXPECT().ResolveRole(gomock.Any(), every, "Editor").Return(accesstypes.Role("Editor"), true, nil).Times(2)
				roles.EXPECT().AddUserRoles(gomock.Any(), every, accesstypes.User("pat"), []accesstypes.Role{"Editor"}).Return(nil)
			},
			wantLocation: "/next",
			wantSession:  true,
		},
		{
			name:   "a directory asserting no role the application knows is refused before any user is resolved or anything written",
			claims: claims,
			prepare: func(_ *authFixture, roles *mock_signin.MockUserRoleManager) {
				roles.EXPECT().ResolveRole(gomock.Any(), gomock.Any(), "Editor").Return(accesstypes.Role(""), false, nil).Times(2)
			},
			wantLocation: "/login?code=no_roles",
		},
		{
			name:   "a role store that fails once the session stands ends the sign-in and expires the session it had inserted",
			claims: claims,
			prepare: func(f *authFixture, roles *mock_signin.MockUserRoleManager) {
				f.expectSignIn(sessionID, resolved, nil)
				roles.EXPECT().ResolveRole(gomock.Any(), global, "Editor").Return(accesstypes.Role(""), false, nil).AnyTimes()
				roles.EXPECT().ResolveRole(gomock.Any(), every, "Editor").Return(accesstypes.Role("Editor"), true, nil).AnyTimes()
				roles.EXPECT().UserRoles(gomock.Any(), accesstypes.User("pat")).Return(nil, errors.New("role store down"))
				f.store.EXPECT().DestroySession(gomock.Any(), sessionID).Return(nil)
			},
			wantLocation: "/login?code=internal_error",
		},
		{
			name:   "a guest of the tenant is marked on the identity, and a refusal by the standard rule sends its code to the login page",
			claims: `{"iss":"` + entraIssuer(tenantLake) + `","idp":"` + entraIssuer(tenantOther) + `","tid":"` + tenantLake + `","oid":"oid-9","preferred_username":"visitor_gmail.com#EXT#@lakeside.onmicrosoft.com","roles":["Editor"]}`,
			wantIdentity: &azure.Identity{
				TenantID: tenantLake, Organization: tenantLake, ObjectID: "oid-9", PreferredUsername: "visitor_gmail.com#EXT#@lakeside.onmicrosoft.com", Guest: true, Roles: []string{"Editor"},
			},
			prepare: func(f *authFixture, roles *mock_signin.MockUserRoleManager) {
				recognizeEditor(roles)
				f.expectSignIn(sessionID, func(req *sessioninfo.NewSessionRequest) {
					if !req.Identity.Guest || req.Identity.SignInName != "visitor_gmail.com#EXT#@lakeside.onmicrosoft.com" {
						t.Errorf("SignIn() identity = %+v, want a guest under its preferred username", req.Identity)
					}
				}, func(*sessioninfo.NewSessionRequest) error {
					return signinflow.Refusal("", sessioninfo.RefusedGuestAccount, signin.ErrGuestAccount, "guest accounts are not members of the directory")
				})
			},
			wantLocation: "/login?code=guest_account",
		},
		{
			name:         "an ID token without tid and oid is refused before any user is resolved",
			claims:       `{"preferred_username":"pat"}`,
			wantLocation: "/login?code=parse_claims_failed",
		},
		{
			name:         "a token whose issuer is not its tenant's is refused before any user is resolved, whatever the authenticator verified",
			claims:       `{"iss":"https://other/` + tenantLake + `/v2.0","tid":"` + tenantLake + `","oid":"oid-1","preferred_username":"p.lee@lakeside.edu"}`,
			wantLocation: "/login?code=verify_id_token_failed",
		},
		{
			name:         "a token from a tenant the registration does not admit is refused before any user is resolved, whatever the authenticator verified",
			claims:       `{"iss":"` + entraIssuer(tenantRiver) + `","tid":"` + tenantRiver + `","oid":"oid-1","preferred_username":"p.lee@riverside.edu"}`,
			wantLocation: "/login?code=unlisted_tenant",
		},
		{
			name:         "a personal account under a registration for one tenant is refused before any user is resolved",
			claims:       `{"iss":"` + entraIssuer(azure.ConsumerTenantID) + `","tid":"` + azure.ConsumerTenantID + `","oid":"oid-1","preferred_username":"pat@outlook.com"}`,
			wantLocation: "/login?code=personal_account",
		},
		{
			name:   "an identity waiting for its user's password becomes a pending identity, and no roles are touched",
			claims: claims,
			prepare: func(f *authFixture, roles *mock_signin.MockUserRoleManager) {
				recognizeEditor(roles)
				f.expectSignIn(sessionID, nil, func(*sessioninfo.NewSessionRequest) error {
					return errors.Wrap(&signin.PendingSignInError{Reason: sessioninfo.PendingConfirmation, UserID: ccc.NullUUIDFromUUID(userID), Username: "pat"}, "db.InsertSession()")
				})
				f.expectHold("pat")
			},
			wantLocation: "/login?pending=confirmation&returnUrl=%2Fnext",
			wantPending:  true,
		},
		{
			name:   "a resolver's refusal sends its code to the login page",
			claims: claims,
			prepare: func(f *authFixture, roles *mock_signin.MockUserRoleManager) {
				recognizeEditor(roles)
				f.expectSignIn(sessionID, nil, func(*sessioninfo.NewSessionRequest) error {
					return signinflow.Refusal("", sessioninfo.RefusedIdentityRejected, signin.ErrIdentityRejected, "identity rejected")
				})
			},
			wantLocation: "/login?code=identity_rejected",
		},
		{
			name:   "a link the store refuses across connections sends identity_rejected to the login page",
			claims: claims,
			prepare: func(f *authFixture, roles *mock_signin.MockUserRoleManager) {
				recognizeEditor(roles)
				f.expectSignIn(sessionID, nil, func(*sessioninfo.NewSessionRequest) error {
					return signinflow.Refusal("", sessioninfo.RefusedIdentityRejected, signin.ErrLinkCrossConnection, "identity from another connection needs a trusted link")
				})
			},
			wantLocation: "/login?code=identity_rejected",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			ctrl := gomock.NewController(t)
			f := newAuthFixtureWithoutPassword(t, ctrl)
			roles := mock_signin.NewMockUserRoleManager(ctrl)
			authn := mock_azure.NewMockAuthenticator(ctrl)
			authn.EXPECT().LoginURL().Return("/login").AnyTimes()
			authn.EXPECT().Verify(gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any()).DoAndReturn(
				func(_ context.Context, _ http.ResponseWriter, _ *http.Request, claims any) (string, string, error) {
					if err := json.Unmarshal([]byte(tt.claims), claims); err != nil {
						t.Fatal(err)
					}

					return "/next", "sid", nil
				})
			var decoded *azure.Identity
			resolve := func(_ context.Context, _ mockTx, identity *azure.Identity) (*signin.Resolution, error) {
				decoded = identity

				return signin.Link(userID, false), nil
			}
			entra := azure.SignIn(f.auth, "azure", resolve, &azure.Config{RoleSync: signin.RoleSync(roles), Authority: testAuthority, Tenants: azure.Tenant(tenantLake), Authenticator: authn})
			if tt.prepare != nil {
				tt.prepare(f, roles)
			}

			rr := f.serve(entra.Callback(), http.MethodGet, "/azure/callback?code=c&state=s", nil, nil)

			if rr.Code != http.StatusFound || rr.Header().Get("Location") != tt.wantLocation {
				t.Errorf("response = %d %q, want 302 %q", rr.Code, rr.Header().Get("Location"), tt.wantLocation)
			}
			if tt.wantIdentity != nil {
				// The store was given the method's resolver: running it decodes the claims
				// the callback verified into the identity the application's rule sees.
				if _, err := f.signedIn.rule(context.Background(), mockTx{}, f.signedIn.req); err != nil {
					t.Fatalf("the resolver the store was given error = %v", err)
				}
				if diff := cmp.Diff(tt.wantIdentity, decoded, cmpopts.IgnoreFields(azure.Identity{}, "Claims")); diff != "" {
					t.Errorf("the resolver's identity mismatch (-want +got):\n%s", diff)
				}
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

// TestAuth_GoogleLogin proves the Google login route's login hint: forwarded to the
// authenticator as given, absent when none was given, and refused when it cannot be an
// email address or account id.
// TestAuth_AzureCallbackResolverOfItsOwn registers two Entra tenants on one Auth, neither
// synchronizing roles: the callback under test hands the store its own registration's
// resolver, never the other tenant's.
func TestAuth_AzureCallbackResolverOfItsOwn(t *testing.T) {
	t.Parallel()
	ctrl := gomock.NewController(t)
	f := newAuthFixture(t, ctrl)
	userID := ccc.Must(ccc.NewUUID())
	sessionID := ccc.Must(ccc.NewUUID())
	claims := `{"iss":"` + entraIssuer(tenantLake) + `","tid":"` + tenantLake + `","oid":"oid-1","preferred_username":"p.lee@lakeside.edu","email":"pat@lakeside.edu","amr":["pwd"]}`
	authn := mock_azure.NewMockAuthenticator(ctrl)
	authn.EXPECT().LoginURL().Return("/login").AnyTimes()
	authn.EXPECT().Verify(gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any()).DoAndReturn(
		func(_ context.Context, _ http.ResponseWriter, _ *http.Request, into any) (string, string, error) {
			if err := json.Unmarshal([]byte(claims), into); err != nil {
				t.Fatal(err)
			}

			return "/next", "sid", nil
		})
	var decoded *azure.Identity
	resolve := func(_ context.Context, _ mockTx, identity *azure.Identity) (*signin.Resolution, error) {
		decoded = identity

		return signin.Link(userID, false), nil
	}
	entra := azure.SignIn(f.auth, "azure", resolve, &azure.Config{RoleSync: signin.DisableRoleSync(), Authority: testAuthority, Tenants: azure.Tenant(tenantLake), Authenticator: authn})
	otherTenant := false
	azure.SignIn(f.auth, "other-tenant", func(context.Context, mockTx, *azure.Identity) (*signin.Resolution, error) {
		otherTenant = true

		return signin.Reject(""), nil
	}, &azure.Config{RoleSync: signin.DisableRoleSync(), Authority: testAuthority, Tenants: azure.Tenant(tenantRiver), ClientID: "client", ClientSecret: "secret", RedirectURL: "https://app/other/callback"})
	f.expectSignIn(sessionID, func(req *sessioninfo.NewSessionRequest) {
		req.UserID, req.Username = userID, "pat"
	}, nil)

	rr := f.serve(entra.Callback(), http.MethodGet, "/azure/callback?code=c&state=s", nil, nil)

	if rr.Code != http.StatusFound || rr.Header().Get("Location") != "/next" {
		t.Fatalf("response = %d %q, want 302 /next", rr.Code, rr.Header().Get("Location"))
	}
	// The store was given the method's resolver: running it decodes the claims the
	// callback verified into the identity the application's rule sees.
	if _, err := f.signedIn.rule(context.Background(), mockTx{}, f.signedIn.req); err != nil {
		t.Fatalf("the resolver the store was given error = %v", err)
	}
	if decoded == nil || decoded.ObjectID != "oid-1" || decoded.TenantID != tenantLake {
		t.Errorf("the resolver's identity = %+v, want oid-1 in %s", decoded, tenantLake)
	}
	if otherTenant {
		t.Error("the store was given the other tenant's resolver")
	}
}

func TestAuth_GoogleLogin(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name         string
		target       string
		prepare      func(authn *mock_google.MockAuthenticator)
		wantStatus   int
		wantLocation string
	}{
		{
			name:   "a login hint rides to Google as given",
			target: "/google/login?returnUrl=%2Fhome&login_hint=" + url.QueryEscape("Pat@Example.com"),
			prepare: func(authn *mock_google.MockAuthenticator) {
				authn.EXPECT().AuthCodeURL(gomock.Any(), gomock.Any(), "/home", signin.LoginOptions{LoginHint: "Pat@Example.com"}).Return("https://accounts/authorize?state=s", nil)
			},
			wantStatus:   http.StatusFound,
			wantLocation: "https://accounts/authorize?state=s",
		},
		{
			name:   "no login hint sends none",
			target: "/google/login",
			prepare: func(authn *mock_google.MockAuthenticator) {
				authn.EXPECT().AuthCodeURL(gomock.Any(), gomock.Any(), "", signin.LoginOptions{}).Return("https://accounts/authorize?state=s", nil)
			},
			wantStatus:   http.StatusFound,
			wantLocation: "https://accounts/authorize?state=s",
		},
		{
			name:       "a login hint with a space is refused",
			target:     "/google/login?login_hint=" + url.QueryEscape("pat smith"),
			wantStatus: http.StatusBadRequest,
		},
		{
			name:   "a request for the account chooser rides to Google beside the hint",
			target: "/google/login?prompt=select_account&login_hint=" + url.QueryEscape("pat@example.com"),
			prepare: func(authn *mock_google.MockAuthenticator) {
				authn.EXPECT().AuthCodeURL(gomock.Any(), gomock.Any(), "", signin.LoginOptions{LoginHint: "pat@example.com", SelectAccount: true}).Return("https://accounts/authorize?state=s", nil)
			},
			wantStatus:   http.StatusFound,
			wantLocation: "https://accounts/authorize?state=s",
		},
		{
			name:       "another prompt value is refused",
			target:     "/google/login?prompt=consent",
			wantStatus: http.StatusBadRequest,
		},
		{
			name:       "a login hint longer than an email address can be is refused",
			target:     "/google/login?login_hint=" + strings.Repeat("a", 255),
			wantStatus: http.StatusBadRequest,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			ctrl := gomock.NewController(t)
			f := newAuthFixture(t, ctrl)
			authn := mock_google.NewMockAuthenticator(ctrl)
			authn.EXPECT().LoginURL().Return("/login").AnyTimes()
			workspace := google.SignIn(f.auth, "google", resolveAll[google.Identity](), &google.Config{RoleSync: google.DisableRoleSync(), Workspaces: google.Workspace("lakeside", "example.com"), Authenticator: authn})
			if tt.prepare != nil {
				tt.prepare(authn)
			}

			rr := f.serve(workspace.Login(), http.MethodGet, tt.target, nil, nil)

			if rr.Code != tt.wantStatus || rr.Header().Get("Location") != tt.wantLocation {
				t.Errorf("response = %d %q, want %d %q", rr.Code, rr.Header().Get("Location"), tt.wantStatus, tt.wantLocation)
			}
		})
	}
}

func TestAuth_GoogleCallback(t *testing.T) {
	t.Parallel()

	sessionID := ccc.Must(ccc.NewUUID())

	// expectIdentity expects the store's SignIn with an identity under connection and
	// signs the request in.
	expectIdentity := func(connection, hd string) func(f *authFixture) {
		return func(f *authFixture) {
			f.expectSignIn(sessionID, func(req *sessioninfo.NewSessionRequest) {
				want := &sessioninfo.Identity{Method: sessioninfo.MethodGoogle, Connection: connection, Subject: "sub-1", Email: "pat@example.com", EmailVerified: true, SignInName: "pat@example.com", Organization: connection}
				if diff := cmp.Diff(want, req.Identity, cmpopts.IgnoreFields(sessioninfo.Identity{}, "Claims")); diff != "" {
					t.Errorf("SignIn() identity mismatch (-want +got):\n%s", diff)
				}
				if hd != "" && !strings.Contains(string(req.Claims), `"hd":"`+hd+`"`) {
					t.Errorf("SignIn() claims = %s, want the hd claim %q", req.Claims, hd)
				}
			}, func(req *sessioninfo.NewSessionRequest) error {
				req.UserID, req.Username = ccc.Must(ccc.NewUUID()), "pat"

				return nil
			})
		}
	}

	tests := []struct {
		name   string
		claims string
		// workspaces is the registration's slot; nil is the Workspace lakeside at example.com.
		workspaces func() google.WorkspaceSet
		prepare    func(f *authFixture)
		// wantIdentity is the identity the method's rule decodes from the claims, when
		// the sign-in reached the store.
		wantIdentity *google.Identity
		wantLocation string
	}{
		{
			name:         "a Google identity is keyed by the registration's name for its Workspace and sub",
			claims:       `{"iss":"https://accounts.google.com","sub":"sub-1","email":"pat@example.com","email_verified":true,"hd":"example.com"}`,
			wantIdentity: &google.Identity{Subject: "sub-1", Email: "pat@example.com", HostedDomain: "example.com", Workspace: "lakeside"},
			prepare:      expectIdentity("lakeside", "example.com"),
			wantLocation: "/home",
		},
		{
			name:   "listed Workspaces: the hd claim selects the Workspace whose domains contain it, and its name is the connection",
			claims: `{"iss":"https://accounts.google.com","sub":"sub-1","email":"pat@example.com","email_verified":true,"hd":"Example.ORG"}`,
			workspaces: func() google.WorkspaceSet {
				return google.Workspaces(google.Workspace("lakeside", "example.com"), google.Workspace("riverside", "example.org"))
			},
			wantIdentity: &google.Identity{Subject: "sub-1", Email: "pat@example.com", HostedDomain: "Example.ORG", Workspace: "riverside"},
			prepare:      expectIdentity("riverside", "Example.ORG"),
			wantLocation: "/home",
		},
		{
			name:         "a Workspace the slot does not admit is refused before any user is resolved",
			claims:       `{"iss":"https://accounts.google.com","sub":"sub-1","email":"pat@example.com","email_verified":true,"hd":"elsewhere.example"}`,
			wantLocation: "/login?code=not_workspace_member",
		},
		{
			name:         "any Workspace: the account's domain is the connection, lowercased",
			claims:       `{"iss":"https://accounts.google.com","sub":"sub-1","email":"pat@example.com","email_verified":true,"hd":"Elsewhere.Example"}`,
			workspaces:   google.AnyWorkspace,
			wantIdentity: &google.Identity{Subject: "sub-1", Email: "pat@example.com", HostedDomain: "Elsewhere.Example", Workspace: "elsewhere.example"},
			prepare:      expectIdentity("elsewhere.example", "Elsewhere.Example"),
			wantLocation: "/home",
		},
		{
			name:         "any Google account: an account outside every Workspace carries the fixed connection",
			claims:       `{"iss":"https://accounts.google.com","sub":"sub-1","email":"pat@example.com","email_verified":true}`,
			workspaces:   google.AnyGoogleAccount,
			wantIdentity: &google.Identity{Subject: "sub-1", Email: "pat@example.com", Workspace: google.AnyAccountConnection},
			prepare:      expectIdentity(google.AnyAccountConnection, ""),
			wantLocation: "/home",
		},
		{
			name:         "an ID token without an email is refused with its code",
			claims:       `{"iss":"https://accounts.google.com","sub":"sub-1"}`,
			wantLocation: "/login?code=no_email_claim",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			ctrl := gomock.NewController(t)
			f := newAuthFixture(t, ctrl)
			authn := mock_google.NewMockAuthenticator(ctrl)
			authn.EXPECT().LoginURL().Return("/login").AnyTimes()
			authn.EXPECT().Verify(gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any()).DoAndReturn(
				func(_ context.Context, _ http.ResponseWriter, _ *http.Request, claims any) (string, string, error) {
					if err := json.Unmarshal([]byte(tt.claims), claims); err != nil {
						t.Fatal(err)
					}

					return "/home", "access-token", nil
				})
			var decoded *google.Identity
			resolve := func(_ context.Context, _ mockTx, identity *google.Identity) (*signin.Resolution, error) {
				decoded = identity

				return signin.Provision(&signin.NewUser{Username: identity.Email}, nil), nil
			}
			workspaces := google.Workspace("lakeside", "example.com")
			if tt.workspaces != nil {
				workspaces = tt.workspaces()
			}
			workspace := google.SignIn(f.auth, "google", resolve, &google.Config{RoleSync: google.DisableRoleSync(), Workspaces: workspaces, Authenticator: authn})
			if tt.prepare != nil {
				tt.prepare(f)
			}

			rr := f.serve(workspace.Callback(), http.MethodGet, "/google/callback", nil, nil)

			if rr.Code != http.StatusFound || rr.Header().Get("Location") != tt.wantLocation {
				t.Errorf("response = %d %q, want 302 %q", rr.Code, rr.Header().Get("Location"), tt.wantLocation)
			}
			if tt.wantIdentity != nil {
				if _, err := f.signedIn.rule(context.Background(), mockTx{}, f.signedIn.req); err != nil {
					t.Fatalf("the resolver the store was given error = %v", err)
				}
				if diff := cmp.Diff(tt.wantIdentity, decoded, cmpopts.IgnoreFields(google.Identity{}, "Claims")); diff != "" {
					t.Errorf("the resolver's identity mismatch (-want +got):\n%s", diff)
				}
			}
		})
	}
}

func TestAuth_WorkOSCallback(t *testing.T) {
	t.Parallel()

	t.Run("the profile WorkOS exchanged is the identity's claims, and reaches the method's resolver decoded", func(t *testing.T) {
		t.Parallel()
		f := newReturnURLFixture(t, gomock.NewController(t))
		f.expectSignIn(ccc.Must(ccc.NewUUID()), func(req *sessioninfo.NewSessionRequest) {
			want := &sessioninfo.Identity{Method: sessioninfo.MethodWorkOS, Connection: "conn_1", Subject: "idp_1", Email: "pat@lakeside.edu"}
			if diff := cmp.Diff(want, req.Identity, cmpopts.IgnoreFields(sessioninfo.Identity{}, "Claims")); diff != "" {
				t.Errorf("SignIn() identity mismatch (-want +got):\n%s", diff)
			}
			req.UserID, req.Username = ccc.Must(ccc.NewUUID()), "pat"
		}, nil)

		if rr := f.callback(t, "/"); rr.Code != http.StatusFound {
			t.Fatalf("Callback() = %d, want 302: %s", rr.Code, rr.Body.String())
		}
		if _, err := f.signedIn.rule(context.Background(), mockTx{}, f.signedIn.req); err != nil {
			t.Fatalf("the resolver the store was given error = %v", err)
		}
		want := &workos.Identity{Profile: workos.Profile{ID: "prof_1", IDPID: "idp_1", ConnectionID: "conn_1", OrganizationID: "org_1", Email: "pat@lakeside.edu"}}
		if diff := cmp.Diff(want, f.identity, cmpopts.IgnoreFields(workos.Identity{}, "Raw")); diff != "" {
			t.Errorf("the resolver's identity mismatch (-want +got):\n%s", diff)
		}
	})
}

func TestAuth_PendingHook(t *testing.T) {
	t.Parallel()

	userID := ccc.Must(ccc.NewUUID())
	sessionID := ccc.Must(ccc.NewUUID())

	type hookResult struct {
		redirectURL string
		err         error
		// write makes the hook answer the request itself.
		write bool
	}
	tests := []struct {
		name string
		// password signs in with the password Login instead of the Google Callback.
		password     bool
		hook         hookResult
		wantStatus   int
		wantLocation string
		wantBody     string
		// wantDiscarded says the pending identity was discarded: its row consumed and,
		// unless the hook answered, its cookie deleted.
		wantDiscarded bool
	}{
		{
			name:         "the callback sends the browser where the hook says",
			hook:         hookResult{redirectURL: "/mfa?step=code"},
			wantStatus:   http.StatusFound,
			wantLocation: "/mfa?step=code",
		},
		{
			name:         "a hook that names no URL keeps the default redirect",
			wantStatus:   http.StatusFound,
			wantLocation: "/login?pending=mfa&returnUrl=%2Fhome",
		},
		{
			name:         "a hook that answers the request itself is the response",
			hook:         hookResult{write: true},
			wantStatus:   http.StatusSeeOther,
			wantLocation: "/own-page",
		},
		{
			name:          "a hook error discards the pending identity and refuses the sign-in",
			hook:          hookResult{err: errors.New("the MFA code could not be sent")},
			wantStatus:    http.StatusFound,
			wantLocation:  "/login?code=internal_error",
			wantDiscarded: true,
		},
		{
			name:       "the password login answers the hook's URL as redirectUrl",
			password:   true,
			hook:       hookResult{redirectURL: "/mfa"},
			wantStatus: http.StatusOK,
			wantBody:   `{"mfaIsRequired":true,"redirectUrl":"/mfa"}`,
		},
		{
			name:          "a hook error fails the password login and discards the pending identity",
			password:      true,
			hook:          hookResult{err: errors.New("the MFA code could not be sent")},
			wantStatus:    http.StatusInternalServerError,
			wantDiscarded: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			ctrl := gomock.NewController(t)

			var (
				f   *authFixture
				got *sessioninfo.PendingIdentity
			)
			hook := func(_ context.Context, w http.ResponseWriter, r *http.Request, pending *sessioninfo.PendingIdentity) (string, error) {
				if len(f.held) == 0 || !slices.ContainsFunc((&http.Response{Header: w.Header()}).Cookies(), func(c *http.Cookie) bool { return c.Name == defaultPendingCookieName }) {
					t.Error("the hook ran before the pending identity was stored")
				}
				got = pending
				if tt.hook.write {
					http.Redirect(w, r, "/own-page", http.StatusSeeOther)
				}

				return tt.hook.redirectURL, tt.hook.err
			}
			f = newAuthFixture(t, ctrl, WithPendingHook(hook))
			user := &sessionstorage.SessionUser{ID: userID, Username: "pat", PasswordHash: hashed(t, "pw")}
			f.expectSignIn(sessionID, nil, func(*sessioninfo.NewSessionRequest) error {
				return &signin.PendingSignInError{Reason: sessioninfo.PendingMFA, UserID: ccc.NullUUIDFromUUID(userID), Username: "pat", Factors: []sessioninfo.AuthMethod{"email-otp"}}
			})
			pendingID := f.expectHold("pat")
			if tt.wantDiscarded {
				f.expectConsume(pendingID)
			}

			var rr *httptest.ResponseRecorder
			if tt.password {
				f.store.EXPECT().UserByUserName(gomock.Any(), "pat").Return(user, nil)
				rr = f.serve(f.password.Login(), http.MethodPost, "/login", map[string]string{"username": "pat", "password": "pw"}, nil)
			} else {
				authn := mock_google.NewMockAuthenticator(ctrl)
				authn.EXPECT().LoginURL().Return("/login").AnyTimes()
				authn.EXPECT().Verify(gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any()).DoAndReturn(
					func(_ context.Context, _ http.ResponseWriter, _ *http.Request, claims any) (string, string, error) {
						return "/home", "access-token", json.Unmarshal([]byte(`{"iss":"https://accounts.google.com","sub":"sub-1","email":"pat@example.com","email_verified":true,"hd":"example.com"}`), claims)
					})
				workspace := google.SignIn(f.auth, "google", resolveAll[google.Identity](), &google.Config{RoleSync: google.DisableRoleSync(), Workspaces: google.Workspace("lakeside", "example.com"), Authenticator: authn})
				rr = f.serve(workspace.Callback(), http.MethodGet, "/google/callback", nil, nil)
			}

			if rr.Code != tt.wantStatus || rr.Header().Get("Location") != tt.wantLocation {
				t.Errorf("response = %d %q, want %d %q: %s", rr.Code, rr.Header().Get("Location"), tt.wantStatus, tt.wantLocation, rr.Body.String())
			}
			if tt.wantBody != "" && strings.TrimSpace(rr.Body.String()) != tt.wantBody {
				t.Errorf("body = %s, want %s", rr.Body.String(), tt.wantBody)
			}
			if got == nil || got.Reason != sessioninfo.PendingMFA || got.UserID != ccc.NullUUIDFromUUID(userID) || got.Username != "pat" || !got.ExpiresAt.After(time.Now()) ||
				!slices.Equal(got.Factors, []sessioninfo.AuthMethod{"email-otp"}) {
				t.Errorf("hook received %+v, want the stored MFA pending identity of pat, accepting email-otp", got)
			}
			if !tt.password && (got == nil || got.Identity.Email != "pat@example.com" || got.ReturnURL != "/home") {
				t.Errorf("hook received %+v, want the identity's email and the return path", got)
			}
			if pendingDeleted(rr) != (tt.wantDiscarded && !tt.hook.write) {
				t.Errorf("pending cookie deleted = %v, want %v", pendingDeleted(rr), tt.wantDiscarded)
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
		name string
		// source is how the storage resolved the user.
		source sessioninfo.UserSource
		// stop is the storage's outcome other than a session.
		stop       error
		wantLinked []ccc.UUID
	}{
		{
			name:       "a sign-in that provisioned the user reports the link, and the hook's error does not undo it",
			source:     sessioninfo.UserProvisioned,
			wantLinked: []ccc.UUID{userID},
		},
		{
			name:       "a sign-in the resolver linked reports the link",
			source:     sessioninfo.UserNewLink,
			wantLinked: []ccc.UUID{userID},
		},
		{
			name:   "a sign-in through an existing link reports nothing",
			source: sessioninfo.UserExistingLink,
		},
		{
			name:       "a provisioning sign-in held for MFA reports the link it committed",
			source:     sessioninfo.UserProvisioned,
			stop:       &signin.PendingSignInError{Reason: sessioninfo.PendingMFA, UserID: ccc.NullUUIDFromUUID(userID), Username: "pat"},
			wantLinked: []ccc.UUID{userID},
		},
		{
			name:       "a provisioning sign-in the policy denied reports the link it committed",
			source:     sessioninfo.UserProvisioned,
			stop:       signinflow.Refusal("", sessioninfo.RefusedByPolicy, signin.ErrSignInDenied, "sign-in denied"),
			wantLinked: []ccc.UUID{userID},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			ctrl := gomock.NewController(t)
			f := newAuthFixture(t, ctrl)
			workos.SignIn(f.auth, "workos", resolveAll[workos.Identity](), &workos.Config{APIKey: "sk", ClientID: "client", RedirectURL: "https://app/sso/callback"})
			f.expectSignIn(sessionID, nil, func(req *sessioninfo.NewSessionRequest) error {
				req.UserID, req.Username = userID, "pat"
				req.User = &sessioninfo.SignInUser{ID: userID, Username: "pat", Source: tt.source}

				return tt.stop
			})
			var wait *signin.PendingSignInError
			if errors.As(tt.stop, &wait) {
				f.expectHold("pat")
			}

			_, err := f.auth.signIn(context.Background(), httptest.NewRecorder(), &signInAttempt{identity: identity, reason: sessioninfo.ReasonLogin, registration: "workos", sameSite: sessioncore.SameSiteNone})
			var refusal *sessioninfo.LoginRefusal
			if (err != nil) != errors.As(tt.stop, &refusal) {
				t.Fatalf("signIn() error = %v", err)
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
	confirmation := &signin.PendingSignInError{Reason: sessioninfo.PendingConfirmation, UserID: ccc.NullUUIDFromUUID(userID), Username: "pat", Tenant: "lakeside"}

	tests := []struct {
		name string
		wait *signin.PendingSignInError
		// stale says the row is no longer live when the confirmation arrives.
		stale         bool
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
				f.expectSignIn(sessionID, func(req *sessioninfo.NewSessionRequest) {
					want := []sessioninfo.AuthEvent{{Method: sessioninfo.MethodWorkOS, Connection: "conn"}, {Method: sessioninfo.MethodLinkConfirmation}}
					if diff := cmp.Diff(want, req.AuthEvents, eventOpts); diff != "" || req.Reason != sessioninfo.ReasonIdentityLinked || !cmp.Equal(req.Identity, identity) {
						t.Errorf("SignIn() request = %+v, events mismatch (-want +got):\n%s", req, diff)
					}
				}, func(req *sessioninfo.NewSessionRequest) error {
					req.UserID, req.Username = userID, "pat"

					return nil
				})
				f.expectConsume(pendingID)
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
				f.expectSignIn(sessionID, nil, func(*sessioninfo.NewSessionRequest) error {
					return &signin.PendingSignInError{Reason: sessioninfo.PendingMFA, UserID: ccc.NullUUIDFromUUID(userID), Username: "pat"}
				})
				f.expectHold("pat")
				f.expectConsume(pendingID)
			},
			wantStatus:   http.StatusOK,
			wantMFA:      true,
			wantLinked:   1,
			wantReplaced: true,
		},
		{
			name:       "a wrong password is invalid credentials, links nothing and leaves the pending identity unconsumed",
			wait:       confirmation,
			password:   "wrong",
			wantStatus: http.StatusUnauthorized,
		},
		{
			name:     "an identity linked meanwhile to another user is refused, and the pending identity is spent",
			wait:     confirmation,
			password: "pw",
			prepare: func(f *authFixture, pendingID ccc.UUID) {
				f.expectConsume(pendingID)
				f.store.EXPECT().LinkIdentity(gomock.Any(), userID, identity, "lakeside").Return(nil, httpio.NewConflictMessage("already linked"))
				f.store.EXPECT().Identity(gomock.Any(), identity.Method, identity.Connection, identity.Subject).Return(&sessionstorage.SessionIdentity{UserID: otherID}, nil)
			},
			wantStatus: http.StatusUnauthorized,
			wantCode:   sessioninfo.RefusedIdentityRejected,
		},
		{
			name:       "an identity waiting for MFA has nothing to confirm",
			wait:       &signin.PendingSignInError{Reason: sessioninfo.PendingMFA, UserID: ccc.NullUUIDFromUUID(userID), Username: "pat"},
			password:   "pw",
			wantStatus: http.StatusConflict,
		},
		{
			name:       "a pending identity whose row is no longer live has expired",
			wait:       confirmation,
			stale:      true,
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
			f := newAuthFixture(t, ctrl)
			workos.SignIn(f.auth, "workos", resolveAll[workos.Identity](), &workos.Config{APIKey: "sk", ClientID: "client", RedirectURL: "https://app/sso/callback"})
			f.store.EXPECT().User(gomock.Any(), userID).Return(&sessionstorage.SessionUser{ID: userID, Username: "pat", PasswordHash: hashed(t, "pw")}, nil).AnyTimes()

			var cookies []*http.Cookie
			var pendingID ccc.UUID
			if !tt.noPendingSent {
				cookies, pendingID = f.hold(t, &signInAttempt{identity: identity, reason: sessioninfo.ReasonLogin, registration: "workos"}, tt.wait)
				if tt.stale {
					f.consumed(pendingID)
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
	mfa := &signin.PendingSignInError{Reason: sessioninfo.PendingMFA, UserID: ccc.NullUUIDFromUUID(userID), Username: "pat"}
	mfaBy := func(factors ...sessioninfo.AuthMethod) *signin.PendingSignInError {
		return &signin.PendingSignInError{Reason: sessioninfo.PendingMFA, UserID: ccc.NullUUIDFromUUID(userID), Username: "pat", Factors: factors}
	}

	tests := []struct {
		name        string
		wait        *signin.PendingSignInError
		prepare     func(f *authFixture, pendingID ccc.UUID)
		wantSession bool
		wantErr     func(err error) bool
	}{
		{
			name: "the MFA step completes the sign-in under a new session ID that records both steps, and is not decided again",
			wait: mfa,
			prepare: func(f *authFixture, pendingID ccc.UUID) {
				f.expectSignIn(sessionID, func(req *sessioninfo.NewSessionRequest) {
					want := []sessioninfo.AuthEvent{{Method: sessioninfo.MethodPassword}, {Method: "email-otp", IDPAMR: []string{"otp"}}}
					if diff := cmp.Diff(want, req.AuthEvents, eventOpts); diff != "" || req.Reason != sessioninfo.ReasonStepUp || req.UserID != userID || !cmp.Equal(req.Identity, password) || req.ProviderSessionID != "sid-1" || req.ProviderSessionIssuer != "https://issuer" {
						t.Errorf("SignIn() request = %+v, events mismatch (-want +got):\n%s", req, diff)
					}
				}, nil)
				f.expectConsume(pendingID)
			},
			wantSession: true,
		},
		{
			name: "an identity resolving to another user than it waited on is refused and its session expired",
			wait: mfa,
			prepare: func(f *authFixture, pendingID ccc.UUID) {
				f.expectConsume(pendingID)
				f.expectSignIn(sessionID, nil, func(req *sessioninfo.NewSessionRequest) error {
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
			name: "a step-up by a method the policy accepts completes the sign-in",
			wait: mfaBy("totp", "email-otp"),
			prepare: func(f *authFixture, pendingID ccc.UUID) {
				f.expectSignIn(sessionID, nil, nil)
				f.expectConsume(pendingID)
			},
			wantSession: true,
		},
		{
			name:    "a step-up by a method the policy did not accept is refused, and the pending sign-in stays unconsumed",
			wait:    mfaBy("totp"),
			wantErr: httpio.HasBadRequest,
		},
		{
			name:    "an identity waiting for a password confirmation can't be completed by MFA",
			wait:    &signin.PendingSignInError{Reason: sessioninfo.PendingConfirmation, UserID: ccc.NullUUIDFromUUID(userID), Username: "pat"},
			wantErr: httpio.HasConflict,
		},
		{
			name: "a user the store finds disabled at completion is refused, and the pending identity is spent",
			wait: mfa,
			prepare: func(f *authFixture, pendingID ccc.UUID) {
				f.expectConsume(pendingID)
				f.expectSignIn(sessionID, nil, func(*sessioninfo.NewSessionRequest) error {
					return signinflow.Refusal("", sessioninfo.RefusedUserDisabled, signin.ErrUserDisabled, "User disabled")
				})
			},
			wantErr: func(err error) bool { return errors.Is(err, signin.ErrUserDisabled) },
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			ctrl := gomock.NewController(t)
			f := newAuthFixture(t, ctrl)
			cookies, pendingID := f.hold(t, &signInAttempt{identity: password, reason: sessioninfo.ReasonLogin, userID: userID, providerSessionID: "sid-1", providerSessionIssuer: "https://issuer"}, tt.wait)
			if tt.prepare != nil {
				tt.prepare(f, pendingID)
			}
			f.store.EXPECT().User(gomock.Any(), userID).Return(&sessionstorage.SessionUser{ID: userID, Username: "pat"}, nil).AnyTimes()

			var (
				got ccc.UUID
				err error
			)
			rr := f.serve(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				got, err = f.auth.API().CompletePending(r.Context(), w, sessioninfo.AuthEvent{Method: "email-otp", IDPAMR: []string{"otp"}})
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
	f := newAuthFixture(t, ctrl)
	identity := &sessioninfo.Identity{Method: sessioninfo.MethodWorkOS, Connection: "conn", Subject: "idp", Email: "pat@lakeside.edu"}
	cookies, pendingID := f.hold(t, &signInAttempt{identity: identity, reason: sessioninfo.ReasonLogin, returnURL: "/next"},
		&signin.PendingSignInError{Reason: sessioninfo.PendingConfirmation, UserID: ccc.NullUUIDFromUUID(ccc.Must(ccc.NewUUID())), Username: "pat"})

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
		t.Errorf("Status() = %s, want no user username", rr.Body.String())
	}

	f.expectConsume(pendingID)
	rr = f.serve(f.auth.Pending().Cancel(), http.MethodPost, "/pending/cancel", nil, cookies)
	if rr.Code != http.StatusOK || !pendingDeleted(rr) {
		t.Errorf("Cancel() = %d, pending cookie deleted %v; want 200 and deleted", rr.Code, pendingDeleted(rr))
	}

	// A cookie that is not the pending identity's is ignored, and the store is not asked.
	rr = f.serve(f.auth.Pending().Status(), http.MethodGet, "/pending", nil, []*http.Cookie{{Name: defaultPendingCookieName, Value: "forged", Secure: true, HttpOnly: true, SameSite: http.SameSiteLaxMode}})
	if rr.Code != http.StatusNotFound {
		t.Errorf("Status() with a forged cookie = %d, want 404", rr.Code)
	}

	// A consumed pending identity's cookie is a spent token: pending_expired, and nothing to cancel.
	rr = f.serve(f.auth.Pending().Status(), http.MethodGet, "/pending", nil, cookies)
	if rr.Code != http.StatusUnauthorized || refusalCode(t, rr) != sessioninfo.RefusedPendingExpired {
		t.Errorf("Status() with a consumed token = %d %s, want 401 pending_expired", rr.Code, rr.Body.String())
	}

	// An MFA wait reports the factors the policy accepts, so the page offers those steps.
	userID := ccc.Must(ccc.NewUUID())
	cookies, _ = f.hold(t, &signInAttempt{identity: &sessioninfo.Identity{Method: sessioninfo.MethodPassword, Subject: userID.String()}, reason: sessioninfo.ReasonLogin, userID: userID},
		&signin.PendingSignInError{Reason: sessioninfo.PendingMFA, UserID: ccc.NullUUIDFromUUID(userID), Username: "pat", Factors: []sessioninfo.AuthMethod{"email-otp", "totp"}})
	rr = f.serve(f.auth.Pending().Status(), http.MethodGet, "/pending", nil, cookies)
	var mfa struct {
		Reason  string   `json:"reason"`
		Factors []string `json:"factors"`
	}
	if err := json.Unmarshal(rr.Body.Bytes(), &mfa); err != nil || rr.Code != http.StatusOK || mfa.Reason != "mfa" || !slices.Equal(mfa.Factors, []string{"email-otp", "totp"}) {
		t.Errorf("Status() of an MFA wait = %d %s, want reason mfa with factors [email-otp totp]", rr.Code, rr.Body.String())
	}
}

func TestAuthAPI_StartAuthenticatedSession(t *testing.T) {
	t.Parallel()

	userID := ccc.Must(ccc.NewUUID())
	sessionID := ccc.Must(ccc.NewUUID())
	events := []sessioninfo.AuthEvent{{Method: "magic-link"}, {Method: "email-otp"}}
	user := &sessionstorage.SessionUser{ID: userID, Username: "pat"}

	tests := []struct {
		name        string
		events      []sessioninfo.AuthEvent
		user        *sessionstorage.SessionUser
		prepare     func(f *authFixture)
		wantErr     func(error) bool
		wantPending bool
	}{
		{
			name:   "the application's own steps are recorded, and the sign-in policy decides the start like a login",
			events: events, user: user,
			prepare: func(f *authFixture) {
				f.expectSignIn(sessionID, func(req *sessioninfo.NewSessionRequest) {
					want := &sessioninfo.Identity{Method: sessioninfo.MethodApplication, Subject: userID.String()}
					if req.Reason != sessioninfo.ReasonExternalAuth || req.UserID != userID || req.Username != "pat" || !cmp.Equal(want, req.Identity) || !cmp.Equal(events, req.AuthEvents) || req.CustomData != nil {
						f.t.Errorf("SignIn() request = %+v, want the application identity of %s with the events", req, userID)
					}
				}, nil)
			},
		},
		{
			name:   "a policy that denies refuses the start with its code, and no session is written",
			events: events, user: user,
			prepare: func(f *authFixture) {
				f.expectSignIn(sessionID, nil, func(*sessioninfo.NewSessionRequest) error {
					return signinflow.Refusal("sso_required", sessioninfo.RefusedByPolicy, signin.ErrSignInDenied, "sign-in denied")
				})
			},
			wantErr: func(err error) bool { return sessioninfo.LoginRefusalCodeOf(err) == "sso_required" },
		},
		{
			name:   "a policy that requires MFA holds the start as the browser's pending identity",
			events: events, user: user,
			prepare: func(f *authFixture) {
				f.expectSignIn(sessionID, nil, func(*sessioninfo.NewSessionRequest) error {
					return errors.Wrap(&signin.PendingSignInError{Reason: sessioninfo.PendingMFA, UserID: ccc.NullUUIDFromUUID(userID), Username: "pat", Factors: []sessioninfo.AuthMethod{"email-otp"}}, "db.InsertSession()")
				})
				f.expectHold("pat")
			},
			wantErr: func(err error) bool {
				var wait *signin.PendingSignInError

				return errors.As(err, &wait) && wait.Reason == sessioninfo.PendingMFA
			},
			wantPending: true,
		},
		{
			name:   "a disabled user is refused by the library before any policy",
			events: events, user: &sessionstorage.SessionUser{ID: userID, Username: "pat", Disabled: true},
			prepare: func(f *authFixture) {
				f.expectSignIn(sessionID, nil, func(*sessioninfo.NewSessionRequest) error {
					return signinflow.Refusal("", sessioninfo.RefusedUserDisabled, signin.ErrUserDisabled, "User disabled")
				})
			},
			wantErr: httpio.HasUnauthorized,
		},
		{name: "no events is refused: the application says how the user authenticated", wantErr: httpio.HasBadRequest},
		{name: "an event without a method is refused", events: []sessioninfo.AuthEvent{{}}, wantErr: httpio.HasBadRequest},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			f := newAuthFixture(t, gomock.NewController(t))
			if tt.user != nil {
				f.store.EXPECT().User(gomock.Any(), userID).Return(tt.user, nil)
			}
			if tt.prepare != nil {
				tt.prepare(f)
			}

			rr := httptest.NewRecorder()
			got, err := f.auth.API().StartAuthenticatedSession(context.Background(), rr, userID, tt.events)
			if gotPending := cookieNamed(rr, defaultPendingCookieName) != nil; gotPending != tt.wantPending {
				t.Errorf("pending cookie written = %v, want %v", gotPending, tt.wantPending)
			}
			if tt.wantErr != nil {
				if !tt.wantErr(err) {
					t.Errorf("StartAuthenticatedSession() error = %v", err)
				}
				if cookieNamed(rr, internalcookie.AuthCookieName) != nil {
					t.Error("a session cookie was written for a refused or held start")
				}

				return
			}
			if err != nil || got != sessionID || cookieNamed(rr, internalcookie.AuthCookieName) == nil {
				t.Errorf("StartAuthenticatedSession() = %s, %v; want %s with its cookies", got, err, sessionID)
			}
		})
	}
}

// TestAuth_AccountRulesGivenToTheStore proves a registration hands the store the account
// rules it was configured with: the standard rule, members of the directory unless
// Accounts says otherwise, and the application's own rule only when one was given.
func TestAuth_AccountRulesGivenToTheStore(t *testing.T) {
	t.Parallel()

	sessionID := ccc.Must(ccc.NewUUID())
	custom := func(context.Context, mockTx, *azure.Identity) (*signin.Resolution, error) {
		return signin.Standard(), nil
	}

	tests := []struct {
		name         string
		rule         azure.AccountRule[mockTx]
		accounts     signin.StandardAccountRule
		wantStandard signin.StandardAccountRule
		wantRule     bool
	}{
		{name: "no rule and no Accounts: members of the directory, by the library", wantStandard: signin.MembersOfDirectory},
		{name: "no rule, invited users only", accounts: signin.InvitedUsersOnly, wantStandard: signin.InvitedUsersOnly},
		{name: "a custom rule beside the standard one", rule: custom, accounts: signin.InvitedUsersOnly, wantStandard: signin.InvitedUsersOnly, wantRule: true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			ctrl := gomock.NewController(t)
			f := newAuthFixture(t, ctrl)
			authn := mock_azure.NewMockAuthenticator(ctrl)
			authn.EXPECT().LoginURL().Return("/login").AnyTimes()
			authn.EXPECT().Verify(gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any()).DoAndReturn(
				func(_ context.Context, _ http.ResponseWriter, _ *http.Request, claims any) (string, string, error) {
					if err := json.Unmarshal([]byte(`{"iss":"`+entraIssuer(tenantLake)+`","tid":"`+tenantLake+`","oid":"oid-1","preferred_username":"p.lee@lakeside.edu"}`), claims); err != nil {
						t.Fatal(err)
					}

					return "/next", "", nil
				})
			entra := azure.SignIn(f.auth, "azure", tt.rule, &azure.Config{RoleSync: signin.DisableRoleSync(), Authority: testAuthority, Tenants: azure.Tenant(tenantLake), Accounts: tt.accounts, Authenticator: authn})
			f.expectSignIn(sessionID, func(req *sessioninfo.NewSessionRequest) {
				req.UserID, req.Username = ccc.Must(ccc.NewUUID()), "p.lee@lakeside.edu"
			}, nil)

			rr := f.serve(entra.Callback(), http.MethodGet, "/azure/callback?code=c&state=s", nil, nil)

			if rr.Code != http.StatusFound || rr.Header().Get("Location") != "/next" {
				t.Fatalf("response = %d %q, want 302 /next", rr.Code, rr.Header().Get("Location"))
			}
			if f.signedIn.standard != tt.wantStandard || (f.signedIn.rule != nil) != tt.wantRule {
				t.Errorf("SignIn() given standard rule %q and a custom rule = %v, want %q and %v", f.signedIn.standard, f.signedIn.rule != nil, tt.wantStandard, tt.wantRule)
			}
			if tt.wantRule {
				res, err := f.signedIn.rule(context.Background(), mockTx{}, f.signedIn.req)
				if err != nil || res.Outcome() != signin.ApplyStandardRule {
					t.Errorf("the custom rule the store was given = %v, %v; want the Standard answer", res, err)
				}
			}
		})
	}
}

// TestAuth_WithoutPolicy proves an Auth with no sign-in policy signs in on the library's
// checks alone: the store is asked with no policy, and the session is established.
func TestAuth_WithoutPolicy(t *testing.T) {
	t.Parallel()

	ctrl := gomock.NewController(t)
	store := newAuthStoreMock(ctrl)
	a, err := NewAuth[NoCustomData, NoCustomData](store, cookieKey)
	if err != nil {
		t.Fatalf("NewAuth() error = %v", err)
	}
	userID := ccc.Must(ccc.NewUUID())
	sessionID := ccc.Must(ccc.NewUUID())
	store.EXPECT().User(gomock.Any(), userID).Return(&sessionstorage.SessionUser{ID: userID, Username: "pat"}, nil)
	store.EXPECT().SignIn(gomock.Any(), gomock.Any(), gomock.Any()).DoAndReturn(
		func(_ context.Context, _ *sessioninfo.NewSessionRequest, rules sessionstorage.SignInRules[mockTx]) (ccc.UUID, error) {
			if rules.Account != nil || rules.Standard != "" || rules.Policy != nil || rules.Accept != nil || rules.Directories != nil || rules.Seat != nil {
				t.Errorf("SignIn() given rules = %+v, want none: the Auth has no policy and no hooks", rules)
			}

			return sessionID, nil
		})
	// A session the application starts is a sign-in: the user's last sign-in moves.
	store.EXPECT().TouchUserSignIn(gomock.Any(), userID).Return(nil)

	rr := httptest.NewRecorder()
	got, err := a.API().StartAuthenticatedSession(context.Background(), rr, userID, []sessioninfo.AuthEvent{{Method: "api-key"}})
	if err != nil || got != sessionID || cookieNamed(rr, internalcookie.AuthCookieName) == nil {
		t.Errorf("StartAuthenticatedSession() = %s, %v; want %s with its cookies", got, err, sessionID)
	}
}

func TestAuthAPI_StartImpersonatedSession(t *testing.T) {
	t.Parallel()

	bobID := ccc.Must(ccc.NewUUID())
	sourceID := ccc.Must(ccc.NewUUID())
	source := func() *sessioninfo.SessionData {
		return &sessioninfo.SessionData{SessionInfo: &sessioninfo.SessionInfo{ID: sourceID, Username: "alice", UpdatedAt: time.Now()}, ProviderSessionID: "sid-1", ProviderSessionIssuer: "https://issuer"}
	}
	tests := []struct {
		name            string
		ctx             func() context.Context
		request         *ImpersonationRequest
		prepare         func(store *mock_sessionstorage.MockAuthStore[mockTx])
		wantUserID      ccc.UUID
		wantProviderSID string
	}{
		{
			name:    "a user principal's session belongs to the impersonated user",
			ctx:     context.Background,
			request: &ImpersonationRequest{Actor: "alice", ActorRealm: "admin-portal", Principal: accesstypes.UserPrincipal("bob")},
			prepare: func(store *mock_sessionstorage.MockAuthStore[mockTx]) {
				store.EXPECT().UserByUserName(gomock.Any(), "bob").Return(&sessionstorage.SessionUser{ID: bobID, Username: "bob"}, nil)
			},
			wantUserID: bobID,
		},
		{
			name:    "a role principal's session belongs to no user",
			ctx:     context.Background,
			request: &ImpersonationRequest{Actor: "alice", ActorRealm: "admin-portal", Principal: accesstypes.RolePrincipal("Viewer")},
			prepare: func(store *mock_sessionstorage.MockAuthStore[mockTx]) {
				store.EXPECT().UserByUserName(gomock.Any(), "alice").Return(nil, httpio.NewNotFoundMessage("no such user"))
			},
		},
		{
			name: "an impersonation started on a validated session keeps its provider session id, so a provider-initiated logout reaches it",
			ctx: func() context.Context {
				return context.WithValue(context.Background(), sessioninfo.CtxSessionInfo, source())
			},
			request: &ImpersonationRequest{Actor: "alice", Principal: accesstypes.UserPrincipal("bob")},
			prepare: func(store *mock_sessionstorage.MockAuthStore[mockTx]) {
				store.EXPECT().Session(gomock.Any(), sourceID).Return(source(), nil)
				store.EXPECT().UserByUserName(gomock.Any(), "bob").Return(&sessionstorage.SessionUser{ID: bobID, Username: "bob"}, nil)
			},
			wantUserID:      bobID,
			wantProviderSID: "sid-1",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			ctrl := gomock.NewController(t)
			f := newAuthFixture(t, ctrl)
			f.store.EXPECT().ImpersonationEnabled().Return(true)
			tt.prepare(f.store)
			f.store.EXPECT().CreateImpersonatedSession(gomock.Any(), gomock.Any(), gomock.Any()).DoAndReturn(
				func(_ context.Context, req *sessioninfo.NewSessionRequest, _ *sessioninfo.Impersonation) (ccc.UUID, error) {
					wantIssuer := ""
					if tt.wantProviderSID != "" {
						wantIssuer = "https://issuer"
					}
					if req.UserID != tt.wantUserID || req.Reason != sessioninfo.ReasonImpersonation || req.ProviderSessionID != tt.wantProviderSID || req.ProviderSessionIssuer != wantIssuer {
						t.Errorf("CreateImpersonatedSession() request = %+v, want UserID %s and provider session (%q, %q)", req, tt.wantUserID, tt.wantProviderSID, wantIssuer)
					}

					return ccc.Must(ccc.NewUUID()), nil
				})

			if _, err := f.auth.API().StartImpersonatedSession(tt.ctx(), httptest.NewRecorder(), tt.request); err != nil {
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
		name       string
		userID     ccc.NullUUID
		imp        *sessioninfo.Impersonation
		user       *sessionstorage.SessionUser
		userErr    error
		wantNext   bool
		wantUser   ccc.UUID
		wantStatus int
		wantCode   sessioninfo.LoginRefusalCode
	}{
		{name: "a session is admitted with the user it belongs to, loaded by UserId", userID: ccc.NullUUIDFromUUID(userID), imp: nil, user: &sessionstorage.SessionUser{ID: userID, Username: "pat"}, wantNext: true, wantUser: userID},
		{name: "a session whose user is disabled is refused", userID: ccc.NullUUIDFromUUID(userID), imp: nil, user: &sessionstorage.SessionUser{ID: userID, Username: "pat", Disabled: true}, wantStatus: http.StatusUnauthorized},
		{name: "a session whose user is gone is refused", userID: ccc.NullUUIDFromUUID(userID), imp: nil, userErr: httpio.NewNotFoundMessage("gone"), wantStatus: http.StatusUnauthorized},
		{name: "a session that belongs to no user (a pending identity's row) is refused", userID: ccc.NullUUID{}, imp: nil, wantStatus: http.StatusUnauthorized},
		{
			name:   "a foreign actor's role-principal impersonation has no user to load",
			userID: ccc.NullUUID{}, imp: &sessioninfo.Impersonation{Actor: "alice", ActorRealm: "admin", Principal: accesstypes.RolePrincipal("Viewer"), ExpiresAt: time.Now().Add(time.Hour)},
			wantNext: true,
		},
		{
			name:   "a user who must change their password is refused with the code until the change",
			userID: ccc.NullUUIDFromUUID(userID), imp: nil,
			user:       &sessionstorage.SessionUser{ID: userID, Username: "pat", PasswordChangeRequired: true},
			wantStatus: http.StatusForbidden, wantCode: sessioninfo.RefusedPasswordChangeRequired,
		},
		{
			name:   "an impersonation of a user who must change their password is the actor's and is not held to the mark",
			userID: ccc.NullUUIDFromUUID(userID), imp: &sessioninfo.Impersonation{Actor: "alice", Principal: accesstypes.UserPrincipal("pat"), ExpiresAt: time.Now().Add(time.Hour)},
			user:     &sessionstorage.SessionUser{ID: userID, Username: "pat", PasswordChangeRequired: true},
			wantNext: true, wantUser: userID,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			ctrl := gomock.NewController(t)
			f := newAuthFixture(t, ctrl)
			// The row is built here, not with the table: a row older than five seconds
			// makes the handler refresh its activity, a call this test does not expect, and
			// the parallel subtests can start that long after the table was assembled.
			f.store.EXPECT().Session(gomock.Any(), sessionID).Return(session(tt.userID, tt.imp), nil)
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
			if !tt.wantNext && rr.Code != tt.wantStatus {
				t.Errorf("status = %d, want %d", rr.Code, tt.wantStatus)
			}
			if tt.wantCode != "" {
				var body refusalResponse
				if err := json.Unmarshal(rr.Body.Bytes(), &body); err != nil || body.Code != tt.wantCode {
					t.Errorf("body = %s (%v), want code %q", rr.Body.String(), err, tt.wantCode)
				}
			}
			if tt.wantNext && sessioninfo.UserFromCtx(rec.ctx).ID != tt.wantUser {
				t.Errorf("user in context = %s, want %s", sessioninfo.UserFromCtx(rec.ctx).ID, tt.wantUser)
			}
		})
	}
}

// TestAuth_ForcedPasswordChange proves what a user who must change their password
// reaches: the session read, which reports the mark, and the password change, which
// validates the session itself and clears the mark.
func TestAuth_ForcedPasswordChange(t *testing.T) {
	t.Parallel()

	userID := ccc.Must(ccc.NewUUID())
	sessionID := ccc.Must(ccc.NewUUID())
	marked := func() *sessionstorage.SessionUser {
		return &sessionstorage.SessionUser{ID: userID, Username: "pat", PasswordHash: hashed(t, "temporary"), PasswordChangeRequired: true}
	}
	request := func(method string, body any) *http.Request {
		var payload *strings.Reader
		if body != nil {
			raw, _ := json.Marshal(body)
			payload = strings.NewReader(string(raw))
		} else {
			payload = strings.NewReader("")
		}
		r := httptest.NewRequestWithContext(context.WithValue(context.Background(), sessioninfo.CTXSessionID, sessionID), method, "/api/user/password", payload)
		r.Header.Set("Content-Type", "application/json")

		return r
	}
	session := func() *sessioninfo.SessionData {
		return &sessioninfo.SessionData{SessionInfo: &sessioninfo.SessionInfo{ID: sessionID, Username: "pat", UpdatedAt: time.Now()}, UserID: ccc.NullUUIDFromUUID(userID)}
	}

	t.Run("the session read reports the mark", func(t *testing.T) {
		t.Parallel()
		ctrl := gomock.NewController(t)
		f := newAuthFixture(t, ctrl)
		f.store.EXPECT().Session(gomock.Any(), sessionID).Return(session(), nil)
		f.store.EXPECT().User(gomock.Any(), userID).Return(marked(), nil)

		rr := httptest.NewRecorder()
		f.auth.Authenticated().ServeHTTP(rr, request(http.MethodGet, nil))
		var body struct {
			Authenticated          bool   `json:"authenticated"`
			Username               string `json:"username"`
			PasswordChangeRequired bool   `json:"passwordChangeRequired"`
		}
		if err := json.Unmarshal(rr.Body.Bytes(), &body); err != nil || rr.Code != http.StatusOK || !body.Authenticated || body.Username != "pat" || !body.PasswordChangeRequired {
			t.Errorf("Authenticated() = %d %s (%v), want the authenticated user with passwordChangeRequired", rr.Code, rr.Body.String(), err)
		}
	})

	t.Run("the password change validates the session itself, clears the mark and continues in a new session", func(t *testing.T) {
		t.Parallel()
		ctrl := gomock.NewController(t)
		f := newAuthFixture(t, ctrl)
		f.store.EXPECT().Session(gomock.Any(), sessionID).Return(session(), nil)
		f.store.EXPECT().User(gomock.Any(), userID).Return(marked(), nil).Times(2)
		gomock.InOrder(
			f.store.EXPECT().DestroyUserSessions(gomock.Any(), userID).Return(nil),
			f.store.EXPECT().SetUserPassword(gomock.Any(), userID, gomock.Any(), false).Return(nil),
		)
		createSession(f.store, ccc.Must(ccc.NewUUID()), func(req *sessioninfo.NewSessionRequest) {
			if req.Reason != sessioninfo.ReasonRegeneration || req.UserID != userID {
				t.Errorf("CreateSession() request = %+v", req)
			}
		})

		rr := httptest.NewRecorder()
		f.password.ChangeUserPassword().ServeHTTP(rr, request(http.MethodPost, map[string]string{"oldPassword": "temporary", "newPassword": "chosen"}))
		if rr.Code != http.StatusOK {
			t.Errorf("ChangeUserPassword() = %d %s, want 200", rr.Code, rr.Body.String())
		}
	})

	t.Run("a wrong old password or the same password changes nothing", func(t *testing.T) {
		t.Parallel()
		for _, body := range []map[string]string{{"oldPassword": "nope", "newPassword": "chosen"}, {"oldPassword": "temporary", "newPassword": "temporary"}} {
			ctrl := gomock.NewController(t)
			f := newAuthFixture(t, ctrl)
			f.store.EXPECT().Session(gomock.Any(), sessionID).Return(session(), nil)
			f.store.EXPECT().User(gomock.Any(), userID).Return(marked(), nil).Times(2)

			rr := httptest.NewRecorder()
			f.password.ChangeUserPassword().ServeHTTP(rr, request(http.MethodPost, body))
			if rr.Code != http.StatusBadRequest {
				t.Errorf("ChangeUserPassword(%v) = %d %s, want 400", body, rr.Code, rr.Body.String())
			}
		}
	})

	t.Run("the API's validation refuses the request with the code", func(t *testing.T) {
		t.Parallel()
		ctrl := gomock.NewController(t)
		f := newAuthFixture(t, ctrl)
		f.store.EXPECT().Session(gomock.Any(), sessionID).Return(session(), nil)
		f.store.EXPECT().User(gomock.Any(), userID).Return(marked(), nil)

		_, err := f.auth.API().ValidateSession(context.WithValue(context.Background(), sessioninfo.CTXSessionID, sessionID))
		var refusal *sessioninfo.LoginRefusal
		if !errors.As(err, &refusal) || refusal.Code() != sessioninfo.RefusedPasswordChangeRequired || !httpio.HasForbidden(err) {
			t.Errorf("ValidateSession() error = %v, want a Forbidden refusal with %s", err, sessioninfo.RefusedPasswordChangeRequired)
		}
	})
}

func TestAuthAPI_UserManagement(t *testing.T) {
	t.Parallel()

	userID := ccc.Must(ccc.NewUUID())

	t.Run("changing the password destroys the user's sessions by UserId, clears the mark and continues in a new session that records the password", func(t *testing.T) {
		t.Parallel()
		ctrl := gomock.NewController(t)
		f := newAuthFixture(t, ctrl)
		f.store.EXPECT().User(gomock.Any(), userID).Return(&sessionstorage.SessionUser{ID: userID, Username: "pat", PasswordHash: hashed(t, "old"), PasswordChangeRequired: true}, nil)
		gomock.InOrder(
			f.store.EXPECT().DestroyUserSessions(gomock.Any(), userID).Return(nil),
			f.store.EXPECT().SetUserPassword(gomock.Any(), userID, gomock.Any(), false).Return(nil),
		)
		createSession(f.store, ccc.Must(ccc.NewUUID()), func(req *sessioninfo.NewSessionRequest) {
			if req.Reason != sessioninfo.ReasonRegeneration || req.UserID != userID || !cmp.Equal(req.AuthEvents, []sessioninfo.AuthEvent{{Method: sessioninfo.MethodPassword}}) {
				t.Errorf("CreateSession() request = %+v", req)
			}
		})

		if err := f.auth.API().ChangeSessionUserPassword(context.Background(), httptest.NewRecorder(), userID, &ChangeSessionUserPasswordRequest{OldPassword: "old", NewPassword: "new"}); err != nil {
			t.Errorf("ChangeSessionUserPassword() error = %v", err)
		}
	})

	t.Run("a wrong old password changes nothing", func(t *testing.T) {
		t.Parallel()
		ctrl := gomock.NewController(t)
		f := newAuthFixture(t, ctrl)
		f.store.EXPECT().User(gomock.Any(), userID).Return(&sessionstorage.SessionUser{ID: userID, Username: "pat", PasswordHash: hashed(t, "old")}, nil)

		err := f.auth.API().ChangeSessionUserPassword(context.Background(), httptest.NewRecorder(), userID, &ChangeSessionUserPasswordRequest{OldPassword: "nope", NewPassword: "new"})
		if !httpio.HasBadRequest(err) {
			t.Errorf("ChangeSessionUserPassword() error = %v, want BadRequest", err)
		}
	})

	t.Run("a new password equal to the old one changes nothing", func(t *testing.T) {
		t.Parallel()
		ctrl := gomock.NewController(t)
		f := newAuthFixture(t, ctrl)
		f.store.EXPECT().User(gomock.Any(), userID).Return(&sessionstorage.SessionUser{ID: userID, Username: "pat", PasswordHash: hashed(t, "old")}, nil)

		err := f.auth.API().ChangeSessionUserPassword(context.Background(), httptest.NewRecorder(), userID, &ChangeSessionUserPasswordRequest{OldPassword: "old", NewPassword: "old"})
		if !httpio.HasBadRequest(err) {
			t.Errorf("ChangeSessionUserPassword() error = %v, want BadRequest", err)
		}
	})

	t.Run("resetting the password marks the user and destroys its sessions; setting one the user chose clears the mark", func(t *testing.T) {
		t.Parallel()
		ctrl := gomock.NewController(t)
		f := newAuthFixture(t, ctrl)
		f.store.EXPECT().User(gomock.Any(), userID).Return(&sessionstorage.SessionUser{ID: userID, Username: "pat"}, nil).Times(2)
		gomock.InOrder(
			f.store.EXPECT().SetUserPassword(gomock.Any(), userID, gomock.Any(), true).Return(nil),
			f.store.EXPECT().DestroyUserSessions(gomock.Any(), userID).Return(nil),
			f.store.EXPECT().SetUserPassword(gomock.Any(), userID, gomock.Any(), false).Return(nil),
			f.store.EXPECT().DestroyUserSessions(gomock.Any(), userID).Return(nil),
		)
		if err := f.auth.API().ResetSessionUserPassword(context.Background(), userID, "temporary"); err != nil {
			t.Errorf("ResetSessionUserPassword() error = %v", err)
		}
		if err := f.auth.API().SetSessionUserPassword(context.Background(), userID, "chosen"); err != nil {
			t.Errorf("SetSessionUserPassword() error = %v", err)
		}
	})

	t.Run("a user created with a password an operator set carries the mark; the mark without a password is refused", func(t *testing.T) {
		t.Parallel()
		ctrl := gomock.NewController(t)
		f := newAuthFixture(t, ctrl)
		f.store.EXPECT().CreateUser(gomock.Any(), gomock.Any(), nil).DoAndReturn(func(_ context.Context, user *sessionstorage.InsertSessionUser, _ any) (*sessionstorage.SessionUser, error) {
			if user.Username != "pat" || user.PasswordHash == nil || !user.PasswordChangeRequired {
				t.Errorf("CreateUser() = %+v, want pat with a password and the mark", user)
			}

			return &sessionstorage.SessionUser{ID: userID, Username: user.Username, PasswordHash: user.PasswordHash, PasswordChangeRequired: user.PasswordChangeRequired}, nil
		})
		temporary := "temporary"
		if id, err := f.auth.API().CreateSessionUser(context.Background(), &CreateUserRequest{Username: "pat", Password: &temporary, PasswordChangeRequired: true}); err != nil || id != userID {
			t.Errorf("CreateSessionUser() = %s, %v; want %s", id, err, userID)
		}
		if _, err := f.auth.API().CreateSessionUser(context.Background(), &CreateUserRequest{Username: "sam", PasswordChangeRequired: true}); !httpio.HasBadRequest(err) {
			t.Errorf("CreateSessionUser() of a password-less user with the mark error = %v, want BadRequest", err)
		}
	})

	t.Run("the users are listed and read through the API", func(t *testing.T) {
		t.Parallel()
		ctrl := gomock.NewController(t)
		f := newAuthFixture(t, ctrl)
		users := []*sessionstorage.SessionUser{{ID: userID, Username: "pat"}, {ID: ccc.Must(ccc.NewUUID()), Username: "sam"}}
		f.store.EXPECT().Users(gomock.Any()).Return(users, nil)
		f.store.EXPECT().User(gomock.Any(), userID).Return(users[0], nil)
		f.store.EXPECT().UserByUserName(gomock.Any(), "Pat").Return(users[0], nil)

		if got, err := f.auth.API().Users(context.Background()); err != nil || !cmp.Equal(got, users) {
			t.Errorf("Users() = %v, %v; want %v", got, err, users)
		}
		if got, err := f.auth.API().User(context.Background(), userID); err != nil || got != users[0] {
			t.Errorf("User() = %v, %v; want pat", got, err)
		}
		if got, err := f.auth.API().UserByUsername(context.Background(), "Pat"); err != nil || got != users[0] {
			t.Errorf("UserByUsername() = %v, %v; want pat", got, err)
		}
	})

	t.Run("deleting a user destroys its sessions before the user and its identities go", func(t *testing.T) {
		t.Parallel()
		ctrl := gomock.NewController(t)
		f := newAuthFixture(t, ctrl)
		gomock.InOrder(
			f.store.EXPECT().User(gomock.Any(), userID).Return(&sessionstorage.SessionUser{ID: userID}, nil),
			f.store.EXPECT().DestroyUserSessions(gomock.Any(), userID).Return(nil),
			f.store.EXPECT().DeleteUser(gomock.Any(), userID).Return(nil),
		)
		if err := f.auth.API().DeleteSessionUser(context.Background(), userID); err != nil {
			t.Errorf("DeleteSessionUser() error = %v", err)
		}
	})

	t.Run("deactivating a user destroys its sessions", func(t *testing.T) {
		t.Parallel()
		ctrl := gomock.NewController(t)
		f := newAuthFixture(t, ctrl)
		gomock.InOrder(
			f.store.EXPECT().DeactivateUser(gomock.Any(), userID).Return(nil),
			f.store.EXPECT().DestroyUserSessions(gomock.Any(), userID).Return(nil),
		)
		if err := f.auth.API().DeactivateSessionUser(context.Background(), userID); err != nil {
			t.Errorf("DeactivateSessionUser() error = %v", err)
		}
	})

	t.Run("a user's last means of sign-in is not unlinked", func(t *testing.T) {
		t.Parallel()
		ctrl := gomock.NewController(t)
		f := newAuthFixture(t, ctrl)
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

func TestAuth_RegistrationRacingTheFirstRequest(t *testing.T) {
	t.Parallel()

	// Under -race: a registration racing the Auth's first request either lands before it
	// or is refused; the request never reads a half-registered method.
	for range 20 {
		a := newBareAuth(t, gomock.NewController(t))
		done := make(chan any)
		go func() {
			done <- registrationPanic(func() {
				workos.SignIn(a, "workos", resolveAll[workos.Identity](), &workos.Config{APIKey: "sk", ClientID: "client", RedirectURL: "https://app/sso/callback"})
			})
		}()
		r := httptest.NewRequestWithContext(context.Background(), http.MethodGet, "/", http.NoBody)
		a.StartSession(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
			_ = len(a.registered().external)
		})).ServeHTTP(httptest.NewRecorder(), r)

		if got := <-done; got != nil && !strings.Contains(fmt.Sprint(got), "after the Auth is in use") {
			t.Fatalf("the racing registration panicked with %v", got)
		}
	}
}

const (
	// tenantLake, tenantRiver and tenantOther are three Entra tenants' ids: the two
	// the tests register, and one no registration admits.
	tenantLake  = "11111111-1111-1111-1111-111111111111"
	tenantRiver = "22222222-2222-2222-2222-222222222222"
	tenantOther = "33333333-3333-3333-3333-333333333333"
	// testAuthority is the Microsoft identity platform the tests' tenants live on.
	testAuthority = "https://login"
)

// entraIssuer is the issuer of tenant tid's tokens under testAuthority.
func entraIssuer(tid string) string {
	return testAuthority + "/" + tid + "/v2.0"
}

// TestAuth_CallbackFromUndeclaredIssuer proves the core refuses a round trip whose token
// came from an issuer the registration does not declare, whatever the method verified,
// before any user is resolved. (The Entra method refuses such a token itself first;
// this is the core's own check, which every method is behind.)
func TestAuth_CallbackFromUndeclaredIssuer(t *testing.T) {
	t.Parallel()
	f := newAuthFixture(t, gomock.NewController(t))
	h := f.auth.RegisterExternal(&signin.Registration[mockTx]{
		Name: "bare", Method: sessioninfo.AuthMethod("bare"), StandardRule: signin.MembersOfDirectory,
		Issuers: signin.IssuerList("https://issuer"),
		Build: func(signin.StateCookies) (*signin.Method, error) {
			return &signin.Method{
				Name:     "bare",
				LoginURL: func() string { return "/login" },
				Complete: func(context.Context, http.ResponseWriter, *http.Request) (*signin.Verified, error) {
					return &signin.Verified{
						Identity:  &sessioninfo.Identity{Method: "bare", Connection: "c", Subject: "s", SignInName: "pat"},
						ReturnURL: "/next", Issuer: "https://other",
					}, nil
				},
			}, nil
		},
	})

	rr := f.serve(h.Callback, http.MethodGet, "/bare/callback?code=c&state=s", nil, nil)

	if rr.Code != http.StatusFound || rr.Header().Get("Location") != "/login?code=internal_error" {
		t.Errorf("response = %d %q, want 302 /login?code=internal_error", rr.Code, rr.Header().Get("Location"))
	}
}
