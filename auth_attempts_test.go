package session

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/cccteam/ccc"
	"github.com/cccteam/ccc/securehash"
	"github.com/cccteam/httpio"
	"github.com/cccteam/session/azure"
	internalcookie "github.com/cccteam/session/internal/cookie"
	"github.com/cccteam/session/internal/workos"
	"github.com/cccteam/session/mock/mock_azure"
	"github.com/cccteam/session/sessioninfo"
	"github.com/cccteam/session/sessionstorage"
	"github.com/cccteam/session/signin"
	"github.com/go-playground/errors/v5"
	"github.com/google/go-cmp/cmp"
	gomock "go.uber.org/mock/gomock"
)

// The attempt limiter's tests run the login handler, the API's credential check, the
// MFA completion, the password change and the pending confirmation against the
// fixture's fake attempts table under a short limit, and count the store's reads and
// the hasher's comparisons to prove what each attempt touched.

// testLimit is the limit these tests register: three failures within fifteen minutes
// lock the name for testLock, ten minutes.
var testLimit = []PasswordOption{AttemptLimit(3, 15*time.Minute, testLock)}

const testLock = 10 * time.Minute

// countCompares wraps the fixture's password comparison to count the hashes made.
func countCompares(f *authFixture) *int {
	compares := 0
	compare := f.auth.methods.compare
	f.auth.methods.compare = func(hash *securehash.Hash, password string) (bool, error) {
		compares++

		return compare(hash, password)
	}

	return &compares
}

// login posts a password login for username from client's address and cookie.
func (f *authFixture) login(username, password, address, cookie string) *httptest.ResponseRecorder {
	r := httptest.NewRequestWithContext(context.Background(), http.MethodPost, "/login", strings.NewReader(`{"username":"`+username+`","password":"`+password+`"}`))
	r.Header.Set("Content-Type", "application/json")
	r.RemoteAddr = address + ":4242"
	if cookie != "" {
		r.AddCookie(&http.Cookie{Name: internalcookie.XSRFCookieName, Value: cookie, Secure: true, HttpOnly: true, SameSite: http.SameSiteStrictMode})
	}
	rr := httptest.NewRecorder()
	f.auth.StartSession(f.password.Login()).ServeHTTP(rr, r)

	return rr
}

// refusal decodes a refused login's answer.
func refusal(t *testing.T, rr *httptest.ResponseRecorder) refusalResponse {
	t.Helper()

	var body refusalResponse
	if err := json.Unmarshal(rr.Body.Bytes(), &body); err != nil {
		t.Fatalf("json.Unmarshal(%s) error = %v", rr.Body.String(), err)
	}

	return body
}

// assertLocked checks a 429 answer: the code, the lock period as the wait in the body
// and the header, and nothing about the name.
func assertLocked(t *testing.T, rr *httptest.ResponseRecorder) {
	t.Helper()

	if rr.Code != http.StatusTooManyRequests {
		t.Fatalf("status = %d, want 429: %s", rr.Code, rr.Body.String())
	}
	body := refusal(t, rr)
	seconds := int(testLock.Seconds())
	if body.Code != sessioninfo.RefusedTooManyAttempts || body.RetryAfter != seconds || body.Message != "Too many sign-in attempts" {
		t.Errorf("body = %+v, want code %s with retryAfter %d", body, sessioninfo.RefusedTooManyAttempts, seconds)
	}
	if got := rr.Header().Get("Retry-After"); got != strconv.Itoa(seconds) {
		t.Errorf("Retry-After = %q, want %d", got, seconds)
	}
	if strings.Contains(rr.Body.String(), "pat") {
		t.Errorf("body = %s, want nothing about the name", rr.Body.String())
	}
}

func TestAuth_PasswordLogin_AttemptLimit(t *testing.T) {
	t.Parallel()

	userID := ccc.Must(ccc.NewUUID())
	pat := func() *sessionstorage.SessionUser {
		return &sessionstorage.SessionUser{ID: userID, Username: "pat", PasswordHash: hashed(t, "pw")}
	}

	tests := []struct {
		name string
		run  func(t *testing.T, f *authFixture)
	}{
		{
			name: "the failure that reaches the limit locks the name, and the next attempt is refused with 429, the code and the wait before the user is read or the password hashed",
			run: func(t *testing.T, f *authFixture) {
				f.store.EXPECT().UserByUserName(gomock.Any(), "pat").Return(pat(), nil).Times(3)
				compares := countCompares(f)
				for i := range 3 {
					if rr := f.login("pat", "wrong", "10.0.0.1", "tok"); rr.Code != http.StatusUnauthorized || refusal(t, rr).Code != "" {
						t.Fatalf("attempt %d = %d %s, want 401 invalid credentials", i+1, rr.Code, rr.Body.String())
					}
				}
				reads, writes, _ := f.counts()
				if writes != 3 {
					t.Errorf("store writes = %d, want one per failure", writes)
				}
				assertLocked(t, f.login("pat", "pw", "10.0.0.1", "tok"))
				if readsAfter, _, _ := f.counts(); readsAfter != reads {
					t.Errorf("store reads during the lock = %d, want none beyond %d", readsAfter, reads)
				}
				if *compares != 3 {
					t.Errorf("password comparisons = %d, want 3: the locked attempt hashed nothing", *compares)
				}
				if r := f.attemptsRecord("pat"); r == nil || r.Failures != 3 || r.LockedUntil == nil {
					t.Errorf("record = %+v, want three failures and a lock", r)
				}
			},
		},
		{
			name: "early retries during the lock count against the client's address and cookie and not the name: the client is then held for any name while the name's record stands",
			run: func(t *testing.T, f *authFixture) {
				f.store.EXPECT().UserByUserName(gomock.Any(), "pat").Return(pat(), nil).Times(3)
				for range 3 {
					f.login("pat", "wrong", "10.0.0.1", "tok")
				}
				locked := *f.attemptsRecord("pat")
				// Thirty retries reach the client's limit (ten times the name's).
				for i := range 30 {
					if rr := f.login("pat", "pw", "10.0.0.1", "tok"); rr.Code != http.StatusTooManyRequests {
						t.Fatalf("retry %d = %d, want 429", i+1, rr.Code)
					}
				}
				if r := f.attemptsRecord("pat"); *r != locked {
					t.Errorf("the name's record moved during the retries: %+v, want %+v", r, locked)
				}
				reads, writes, _ := f.counts()
				// Another name from the same address, with a fresh cookie, is refused
				// from memory; the same name from elsewhere is refused by the name.
				assertLocked(t, f.login("sam", "pw", "10.0.0.1", "fresh"))
				assertLocked(t, f.login("pat", "pw", "10.0.0.2", "other"))
				if readsAfter, writesAfter, _ := f.counts(); readsAfter != reads || writesAfter != writes {
					t.Errorf("store calls for the held client and name = %d reads, %d writes; want none beyond %d, %d", readsAfter, writesAfter, reads, writes)
				}
				// A client with none of the held keys reaches the store for another name.
				f.store.EXPECT().UserByUserName(gomock.Any(), "sam").Return(nil, httpio.NewNotFoundMessage("no such user"))
				if rr := f.login("sam", "pw", "10.0.0.2", "other"); rr.Code != http.StatusUnauthorized {
					t.Errorf("another name from another client = %d, want 401", rr.Code)
				}
			},
		},
		{
			name: "the lock passes with time, and failures outside the window do not add up",
			run: func(t *testing.T, f *authFixture) {
				f.store.EXPECT().UserByUserName(gomock.Any(), "pat").Return(pat(), nil).Times(4)
				for range 3 {
					f.login("pat", "wrong", "10.0.0.1", "tok")
				}
				f.advance(10*time.Minute + time.Second)
				if rr := f.login("pat", "wrong", "10.0.0.1", "tok"); rr.Code != http.StatusUnauthorized {
					t.Errorf("attempt after the lock = %d, want 401: the name may try again", rr.Code)
				}
				if r := f.attemptsRecord("pat"); r == nil || r.Failures != 1 || r.LockedUntil != nil {
					t.Errorf("record after the lock = %+v, want one failure in a new window", r)
				}
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			ctrl := gomock.NewController(t)
			f := newAuthFixtureWith(t, ctrl, testLimit)

			tt.run(t, f)
		})
	}
}

// TestAuth_AttemptLimit_Resets proves what resets a name's count: a matching
// password, an MFA completion and a password change of each kind.
func TestAuth_AttemptLimit_Resets(t *testing.T) {
	t.Parallel()

	userID := ccc.Must(ccc.NewUUID())
	sessionID := ccc.Must(ccc.NewUUID())
	pat := func() *sessionstorage.SessionUser {
		return &sessionstorage.SessionUser{ID: userID, Username: "pat", PasswordHash: hashed(t, "pw")}
	}

	tests := []struct {
		name string
		run  func(t *testing.T, f *authFixture)
	}{
		{
			name: "a matching password resets the name: the record goes, and the count starts over",
			run: func(t *testing.T, f *authFixture) {
				f.store.EXPECT().UserByUserName(gomock.Any(), "pat").Return(pat(), nil).Times(5)
				f.expectSignIn(sessionID, nil, nil)
				f.login("pat", "wrong", "10.0.0.1", "tok")
				f.login("pat", "wrong", "10.0.0.1", "tok")
				if rr := f.login("pat", "pw", "10.0.0.1", "tok"); rr.Code != http.StatusOK {
					t.Fatalf("the right password = %d %s, want 200", rr.Code, rr.Body.String())
				}
				if _, _, clears := f.counts(); clears != 1 || f.attemptsRecord("pat") != nil {
					t.Errorf("clears = %d, record = %v; want the record deleted once", clears, f.attemptsRecord("pat"))
				}
				f.login("pat", "wrong", "10.0.0.1", "tok")
				if rr := f.login("pat", "wrong", "10.0.0.1", "tok"); rr.Code != http.StatusUnauthorized {
					t.Errorf("second failure after the success = %d, want 401: the count started over", rr.Code)
				}
			},
		},
		{
			name: "an MFA completion resets the name",
			run: func(t *testing.T, f *authFixture) {
				f.store.EXPECT().UserByUserName(gomock.Any(), "pat").Return(pat(), nil).Times(2)
				f.login("pat", "wrong", "10.0.0.1", "tok")
				f.login("pat", "wrong", "10.0.0.1", "tok")
				password := &sessioninfo.Identity{Method: sessioninfo.MethodPassword, Subject: userID.String()}
				cookies, pendingID := f.hold(t, &signInAttempt{identity: password, reason: sessioninfo.ReasonLogin, userID: userID, username: "pat"},
					&signin.PendingSignInError{Reason: sessioninfo.PendingMFA, UserID: ccc.NullUUIDFromUUID(userID), Username: "pat"})
				f.expectConsume(pendingID)
				f.expectSignIn(sessionID, nil, nil)
				var err error
				f.serve(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					_, err = f.auth.API().CompletePending(r.Context(), w, sessioninfo.AuthEvent{Method: "email-otp"})
				}), http.MethodPost, "/mfa", nil, cookies)
				if err != nil {
					t.Fatalf("CompletePending() error = %v", err)
				}
				if _, _, clears := f.counts(); clears != 1 || f.attemptsRecord("pat") != nil {
					t.Errorf("clears = %d, record = %v; want the record deleted by the completion", clears, f.attemptsRecord("pat"))
				}
			},
		},
		{
			name: "the user's own password change resets the name",
			run: func(t *testing.T, f *authFixture) {
				f.store.EXPECT().UserByUserName(gomock.Any(), "pat").Return(pat(), nil).Times(2)
				f.login("pat", "wrong", "10.0.0.1", "tok")
				f.login("pat", "wrong", "10.0.0.1", "tok")
				f.store.EXPECT().User(gomock.Any(), userID).Return(pat(), nil)
				f.store.EXPECT().DestroyUserSessions(gomock.Any(), userID).Return(nil)
				f.store.EXPECT().SetUserPassword(gomock.Any(), userID, gomock.Any(), false).Return(nil)
				createSession(f.store, sessionID, nil)
				if err := f.auth.API().ChangeSessionUserPassword(context.Background(), httptest.NewRecorder(), userID, &ChangeSessionUserPasswordRequest{OldPassword: "pw", NewPassword: "new"}); err != nil {
					t.Fatalf("ChangeSessionUserPassword() error = %v", err)
				}
				if _, _, clears := f.counts(); clears != 1 || f.attemptsRecord("pat") != nil {
					t.Errorf("clears = %d, record = %v; want the record deleted by the change", clears, f.attemptsRecord("pat"))
				}
			},
		},
		{
			name: "a password the user set through a flow of the application's own, and a temporary one an operator reset, reset the name",
			run: func(t *testing.T, f *authFixture) {
				f.store.EXPECT().UserByUserName(gomock.Any(), "pat").Return(pat(), nil).Times(3)
				f.login("pat", "wrong", "10.0.0.1", "tok")
				f.login("pat", "wrong", "10.0.0.1", "tok")
				f.store.EXPECT().User(gomock.Any(), userID).Return(pat(), nil).Times(2)
				f.store.EXPECT().SetUserPassword(gomock.Any(), userID, gomock.Any(), gomock.Any()).Return(nil).Times(2)
				f.store.EXPECT().DestroyUserSessions(gomock.Any(), userID).Return(nil).Times(2)
				if err := f.auth.API().SetSessionUserPassword(context.Background(), userID, "chosen"); err != nil {
					t.Fatalf("SetSessionUserPassword() error = %v", err)
				}
				if f.attemptsRecord("pat") != nil {
					t.Error("the name's attempts survived the set password, want them cleared")
				}
				f.login("pat", "wrong", "10.0.0.1", "tok")
				if err := f.auth.API().ResetSessionUserPassword(context.Background(), userID, "temporary"); err != nil {
					t.Fatalf("ResetSessionUserPassword() error = %v", err)
				}
				if _, _, clears := f.counts(); clears != 2 || f.attemptsRecord("pat") != nil {
					t.Errorf("clears = %d, record = %v; want one clear per password change and no record", clears, f.attemptsRecord("pat"))
				}
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			ctrl := gomock.NewController(t)
			f := newAuthFixtureWith(t, ctrl, testLimit)

			tt.run(t, f)
		})
	}
}

// TestAuth_AttemptLimit_EveryCheck proves the limiter holds every password check the
// same: the API's, an unknown or password-less name's, a name in another spelling and
// a pending identity's confirmation.
func TestAuth_AttemptLimit_EveryCheck(t *testing.T) {
	t.Parallel()

	userID := ccc.Must(ccc.NewUUID())
	pat := func() *sessionstorage.SessionUser {
		return &sessionstorage.SessionUser{ID: userID, Username: "pat", PasswordHash: hashed(t, "pw")}
	}

	tests := []struct {
		name string
		run  func(t *testing.T, f *authFixture)
	}{
		{
			name: "an unknown name is hashed against the dummy, refused as invalid credentials, counted and locked exactly as a known one",
			run: func(t *testing.T, f *authFixture) {
				f.store.EXPECT().UserByUserName(gomock.Any(), "nobody").Return(nil, httpio.NewNotFoundMessage("no such user")).Times(3)
				compares := countCompares(f)
				for range 3 {
					rr := f.login("nobody", "pw", "10.0.0.1", "tok")
					if rr.Code != http.StatusUnauthorized {
						t.Fatalf("unknown name = %d %s, want 401", rr.Code, rr.Body.String())
					}
					if body := refusal(t, rr); body.Message != "Invalid Credentials" || body.Code != "" {
						t.Errorf("unknown name body = %+v, want the same invalid credentials as a wrong password", body)
					}
				}
				if *compares != 3 {
					t.Errorf("password comparisons for an unknown name = %d, want one per attempt, against the dummy hash", *compares)
				}
				if r := f.attemptsRecord("nobody"); r == nil || r.Failures != 3 || r.LockedUntil == nil {
					t.Errorf("record of the unknown name = %+v, want three failures and a lock, as for a known one", r)
				}
				assertLocked(t, f.login("nobody", "pw", "10.0.0.1", "tok"))
			},
		},
		{
			name: "a password-less user is hashed against the dummy and refused as invalid credentials",
			run: func(t *testing.T, f *authFixture) {
				f.store.EXPECT().UserByUserName(gomock.Any(), "pat").Return(&sessionstorage.SessionUser{ID: userID, Username: "pat"}, nil)
				compares := countCompares(f)
				if rr := f.login("pat", "pw", "10.0.0.1", "tok"); rr.Code != http.StatusUnauthorized {
					t.Errorf("password-less user = %d, want 401", rr.Code)
				}
				if *compares != 1 {
					t.Errorf("password comparisons = %d, want 1 against the dummy hash", *compares)
				}
				if r := f.attemptsRecord("pat"); r == nil || r.Failures != 1 {
					t.Errorf("record = %+v, want the failure counted", r)
				}
			},
		},
		{
			name: "ValidateCredentials counts and refuses as the login does, with the wait on the error",
			run: func(t *testing.T, f *authFixture) {
				f.store.EXPECT().UserByUserName(gomock.Any(), "pat").Return(pat(), nil).Times(3)
				for range 3 {
					if _, err := f.auth.API().ValidateCredentials(context.Background(), "pat", "wrong"); !httpio.HasUnauthorized(err) {
						t.Fatalf("ValidateCredentials() error = %v, want unauthorized", err)
					}
				}
				_, err := f.auth.API().ValidateCredentials(context.Background(), "pat", "pw")
				wait, ok := sessioninfo.RetryAfterOf(err)
				if !ok || wait != 10*time.Minute || !httpio.HasTooManyRequests(err) || sessioninfo.LoginRefusalCodeOf(err) != sessioninfo.RefusedTooManyAttempts {
					t.Errorf("ValidateCredentials() at the limit error = %v (wait %v, %v), want too_many_attempts with a 10m wait", err, wait, ok)
				}
				// The login handler shares the limiter.
				assertLocked(t, f.login("pat", "pw", "10.0.0.1", "tok"))
			},
		},
		{
			name: "a name spelled in another case is the same name",
			run: func(t *testing.T, f *authFixture) {
				f.store.EXPECT().UserByUserName(gomock.Any(), gomock.Any()).Return(pat(), nil).Times(3)
				for _, name := range []string{"Pat", "PAT", "pat"} {
					f.login(name, "wrong", "10.0.0.1", "tok")
				}
				assertLocked(t, f.login("pAt", "pw", "10.0.0.1", "tok"))
			},
		},
		{
			name: "a pending identity's password confirmation is limited under the user's name: the fourth attempt is refused before the hash and the pending identity remains",
			run: func(t *testing.T, f *authFixture) {
				identity := &sessioninfo.Identity{Method: sessioninfo.MethodWorkOS, Connection: "conn", Subject: "idp", Email: "pat@lakeside.edu"}
				cookies, pendingID := f.hold(t, &signInAttempt{identity: identity, reason: sessioninfo.ReasonLogin},
					&signin.PendingSignInError{Reason: sessioninfo.PendingConfirmation, UserID: ccc.NullUUIDFromUUID(userID), Username: "pat", Tenant: "lakeside"})
				f.store.EXPECT().User(gomock.Any(), userID).Return(pat(), nil).Times(4)
				compares := countCompares(f)
				for i := range 3 {
					rr := f.serve(f.auth.Pending().ConfirmWithPassword(), http.MethodPost, "/pending/confirm", map[string]string{"password": "wrong"}, cookies)
					if rr.Code != http.StatusUnauthorized {
						t.Fatalf("confirmation %d = %d %s, want 401", i+1, rr.Code, rr.Body.String())
					}
				}
				rr := f.serve(f.auth.Pending().ConfirmWithPassword(), http.MethodPost, "/pending/confirm", map[string]string{"password": "pw"}, cookies)
				assertLocked(t, rr)
				if *compares != 3 {
					t.Errorf("password comparisons = %d, want 3: the locked confirmation hashed nothing", *compares)
				}
				if f.held[pendingID].ConsumedAt != nil {
					t.Error("the pending identity was consumed by the refused confirmation")
				}
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			ctrl := gomock.NewController(t)
			f := newAuthFixtureWith(t, ctrl, testLimit)

			tt.run(t, f)
		})
	}
}

func TestAuth_SignedInHook(t *testing.T) {
	t.Parallel()

	userID := ccc.Must(ccc.NewUUID())
	sessionID := ccc.Must(ccc.NewUUID())
	pat := &sessionstorage.SessionUser{ID: userID, Username: "pat", PasswordHash: hashed(t, "pw")}
	password := &sessioninfo.Identity{Method: sessioninfo.MethodPassword, Subject: userID.String()}
	// stepUp is the pending sign-in an MFA completion finishes, held at the fixture's
	// clock so its password event carries that time.
	entraClaims := `{"iss":"` + entraIssuer(tenantLake) + `","tid":"` + tenantLake + `","oid":"oid-1","preferred_username":"p.lee@lakeside.edu","email":"pat@lakeside.edu","amr":["pwd"]}`

	tests := []struct {
		name string
		// run establishes a session, or fails to, and returns what the test observed.
		run func(t *testing.T, f *authFixture)
		// want is the call the hook received, nil for none.
		want *SignedIn
		// hookErr is what the hook answers.
		hookErr error
	}{
		{
			name: "a password login calls the hook once with the user and the password event",
			run: func(t *testing.T, f *authFixture) {
				f.store.EXPECT().UserByUserName(gomock.Any(), "pat").Return(pat, nil)
				f.expectSignIn(sessionID, nil, nil)
				if rr := f.login("pat", "pw", "10.0.0.1", ""); rr.Code != http.StatusOK {
					t.Fatalf("login = %d %s", rr.Code, rr.Body.String())
				}
			},
			want: &SignedIn{SessionID: sessionID, UserID: userID, Username: "pat", Reason: sessioninfo.ReasonLogin, Events: []sessioninfo.AuthEvent{{Method: sessioninfo.MethodPassword}}},
		},
		{
			name: "a hook error is logged and the session stands",
			run: func(t *testing.T, f *authFixture) {
				f.store.EXPECT().UserByUserName(gomock.Any(), "pat").Return(pat, nil)
				f.expectSignIn(sessionID, nil, nil)
				rr := f.login("pat", "pw", "10.0.0.1", "")
				if rr.Code != http.StatusOK || cookieNamed(rr, internalcookie.XSRFCookieName) == nil {
					t.Fatalf("login = %d %s, want 200 with the session's cookies", rr.Code, rr.Body.String())
				}
			},
			want:    &SignedIn{SessionID: sessionID, UserID: userID, Username: "pat", Reason: sessioninfo.ReasonLogin, Events: []sessioninfo.AuthEvent{{Method: sessioninfo.MethodPassword}}},
			hookErr: errors.New("notification failed: logged, and the session stands"),
		},
		{
			name: "a session the application starts calls the hook with the events it was given",
			run: func(t *testing.T, f *authFixture) {
				f.store.EXPECT().User(gomock.Any(), userID).Return(pat, nil)
				f.expectSignIn(sessionID, nil, nil)
				events := []sessioninfo.AuthEvent{{Method: "magic-link", Connection: "app"}}
				if _, err := f.auth.API().StartAuthenticatedSession(context.Background(), httptest.NewRecorder(), userID, events); err != nil {
					t.Fatalf("StartAuthenticatedSession() error = %v", err)
				}
			},
			want: &SignedIn{SessionID: sessionID, UserID: userID, Username: "pat", Reason: sessioninfo.ReasonExternalAuth, Events: []sessioninfo.AuthEvent{{Method: "magic-link", Connection: "app"}}},
		},
		{
			name: "an MFA completion calls the hook with the sign-in's events followed by the step's",
			run: func(t *testing.T, f *authFixture) {
				cookies, pendingID := f.hold(t, &signInAttempt{identity: password, reason: sessioninfo.ReasonLogin, userID: userID, username: "pat"},
					&signin.PendingSignInError{Reason: sessioninfo.PendingMFA, UserID: ccc.NullUUIDFromUUID(userID), Username: "pat"})
				f.expectConsume(pendingID)
				f.expectSignIn(sessionID, nil, nil)
				var err error
				f.serve(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					_, err = f.auth.API().CompletePending(r.Context(), w, sessioninfo.AuthEvent{Method: "email-otp"})
				}), http.MethodPost, "/mfa", nil, cookies)
				if err != nil {
					t.Fatalf("CompletePending() error = %v", err)
				}
			},
			want: &SignedIn{SessionID: sessionID, UserID: userID, Username: "pat", Reason: sessioninfo.ReasonStepUp, Events: []sessioninfo.AuthEvent{{Method: sessioninfo.MethodPassword}, {Method: "email-otp"}}},
		},
		{
			name: "a password confirmation calls the hook with the sign-in's event and the confirmation",
			run: func(t *testing.T, f *authFixture) {
				workos.SignIn(f.auth, "workos", resolveAll[workos.Identity](), &workos.Config{APIKey: "sk", ClientID: "client", RedirectURL: "https://app/sso/callback"})
				identity := &sessioninfo.Identity{Method: sessioninfo.MethodWorkOS, Connection: "conn", Subject: "idp", Email: "pat@lakeside.edu"}
				cookies, pendingID := f.hold(t, &signInAttempt{identity: identity, reason: sessioninfo.ReasonLogin, registration: "workos"},
					&signin.PendingSignInError{Reason: sessioninfo.PendingConfirmation, UserID: ccc.NullUUIDFromUUID(userID), Username: "pat", Tenant: "lakeside"})
				f.store.EXPECT().User(gomock.Any(), userID).Return(pat, nil)
				f.store.EXPECT().LinkIdentity(gomock.Any(), userID, identity, "lakeside").Return(&sessionstorage.SessionIdentity{}, nil)
				f.expectConsume(pendingID)
				f.expectSignIn(sessionID, func(req *sessioninfo.NewSessionRequest) { req.UserID, req.Username = userID, "pat" }, nil)
				rr := f.serve(f.auth.Pending().ConfirmWithPassword(), http.MethodPost, "/pending/confirm", map[string]string{"password": "pw"}, cookies)
				if rr.Code != http.StatusOK {
					t.Fatalf("confirmation = %d %s", rr.Code, rr.Body.String())
				}
			},
			want: &SignedIn{
				SessionID: sessionID, UserID: userID, Username: "pat", Reason: sessioninfo.ReasonIdentityLinked,
				Events: []sessioninfo.AuthEvent{{Method: sessioninfo.MethodWorkOS, Connection: "conn"}, {Method: sessioninfo.MethodLinkConfirmation}},
			},
		},
		{
			name: "an external sign-in calls the hook with the user it resolved to and the method's event",
			run: func(t *testing.T, f *authFixture) {
				ctrl := gomock.NewController(t)
				authn := mock_azure.NewMockAuthenticator(ctrl)
				authn.EXPECT().LoginURL().Return("/login").AnyTimes()
				authn.EXPECT().Verify(gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any()).DoAndReturn(
					func(_ context.Context, _ http.ResponseWriter, _ *http.Request, claims any) (string, string, error) {
						if err := json.Unmarshal([]byte(entraClaims), claims); err != nil {
							t.Fatal(err)
						}

						return "/next", "sid", nil
					})
				resolve := func(context.Context, mockTx, *azure.Identity) (*signin.Resolution, error) {
					return signin.Link(userID, false), nil
				}
				entra := azure.SignIn(f.auth, "azure", resolve, &azure.Config{RoleSync: signin.DisableRoleSync(), Authority: testAuthority, Tenants: azure.Tenant(tenantLake), Authenticator: authn})
				f.expectSignIn(sessionID, func(req *sessioninfo.NewSessionRequest) { req.UserID, req.Username = userID, "pat" }, nil)
				if rr := f.serve(entra.Callback(), http.MethodGet, "/azure/callback?code=c&state=s", nil, nil); rr.Code != http.StatusFound || rr.Header().Get("Location") != "/next" {
					t.Fatalf("callback = %d %q", rr.Code, rr.Header().Get("Location"))
				}
			},
			want: &SignedIn{
				SessionID: sessionID, UserID: userID, Username: "pat", Reason: sessioninfo.ReasonLogin,
				Events: []sessioninfo.AuthEvent{{Method: sessioninfo.MethodAzure, Connection: tenantLake, IDPAMR: []string{"pwd"}}},
			},
		},
		{
			name: "a refused sign-in never calls the hook",
			run: func(t *testing.T, f *authFixture) {
				f.store.EXPECT().UserByUserName(gomock.Any(), "pat").Return(pat, nil)
				f.expectSignIn(sessionID, nil, func(*sessioninfo.NewSessionRequest) error {
					return signinflowRefusal()
				})
				if rr := f.login("pat", "pw", "10.0.0.1", ""); rr.Code != http.StatusUnauthorized {
					t.Fatalf("login = %d, want 401", rr.Code)
				}
			},
		},
		{
			name: "a sign-in held for MFA never calls the hook",
			run: func(t *testing.T, f *authFixture) {
				f.store.EXPECT().UserByUserName(gomock.Any(), "pat").Return(pat, nil)
				f.expectSignIn(sessionID, nil, func(*sessioninfo.NewSessionRequest) error {
					return &signin.PendingSignInError{Reason: sessioninfo.PendingMFA, UserID: ccc.NullUUIDFromUUID(userID), Username: "pat"}
				})
				f.expectHold("pat")
				if rr := f.login("pat", "pw", "10.0.0.1", ""); rr.Code != http.StatusOK {
					t.Fatalf("login = %d, want 200 with mfaIsRequired", rr.Code)
				}
			},
		},
		{
			name: "a wrong password never calls the hook",
			run: func(t *testing.T, f *authFixture) {
				f.store.EXPECT().UserByUserName(gomock.Any(), "pat").Return(pat, nil)
				if rr := f.login("pat", "wrong", "10.0.0.1", ""); rr.Code != http.StatusUnauthorized {
					t.Fatalf("login = %d, want 401", rr.Code)
				}
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			ctrl := gomock.NewController(t)
			f := newAuthFixture(t, ctrl)
			f.signedInErr = tt.hookErr
			f.auth.SetSignedInHook(f.signedInHook)

			tt.run(t, f)

			var want []*SignedIn
			if tt.want != nil {
				want = []*SignedIn{tt.want}
			}
			if diff := cmp.Diff(want, f.signedInCalls, eventOpts); diff != "" {
				t.Errorf("SignedInHook calls mismatch (-want +got):\n%s", diff)
			}
		})
	}
}

// signinflowRefusal is a policy denial as the store answers it.
func signinflowRefusal() error {
	return sessioninfo.NewLoginRefusal(sessioninfo.RefusedByPolicy, httpio.NewUnauthorizedMessage("sign-in denied"))
}

func TestAuth_SetSignedInHook_Refused(t *testing.T) {
	t.Parallel()

	hook := func(context.Context, *SignedIn) error { return nil }

	tests := []struct {
		name    string
		prepare func(f *authFixture)
		hook    SignedInHook
		want    string
	}{
		{
			name: "a nil hook",
			want: "given nil",
		},
		{
			name:    "a second hook",
			prepare: func(f *authFixture) { f.auth.SetSignedInHook(hook) },
			hook:    hook,
			want:    "set twice",
		},
		{
			name: "a hook set once the Auth is in use",
			prepare: func(f *authFixture) {
				f.serve(f.auth.Authenticated(), http.MethodGet, "/authenticated", nil, nil)
			},
			hook: hook,
			want: "after the Auth served a request",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			ctrl := gomock.NewController(t)
			f := newAuthFixture(t, ctrl)
			f.store.EXPECT().Session(gomock.Any(), gomock.Any()).Return(nil, httpio.NewNotFoundMessage("no session")).AnyTimes()
			if tt.prepare != nil {
				tt.prepare(f)
			}

			defer func() {
				msg, _ := recover().(string)
				if !strings.Contains(msg, tt.want) {
					t.Errorf("SetSignedInHook() panic = %q, want it to mention %q", msg, tt.want)
				}
			}()
			f.auth.SetSignedInHook(tt.hook)
		})
	}
}

func TestPasswordSignIn_AttemptLimitRefused(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name   string
		option PasswordOption
	}{
		{name: "no failures", option: AttemptLimit(0, time.Minute, time.Minute)},
		{name: "a zero window", option: AttemptLimit(3, 0, time.Minute)},
		{name: "a negative lock", option: AttemptLimit(3, time.Minute, -time.Second)},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			ctrl := gomock.NewController(t)
			a, err := NewAuth[NoCustomData, NoCustomData](newAuthStoreMock(ctrl), cookieKey)
			if err != nil {
				t.Fatal(err)
			}

			defer func() {
				err, _ := recover().(error)
				if err == nil || !strings.Contains(err.Error(), "AttemptLimit(") {
					t.Errorf("PasswordSignIn() panic = %v, want the limit refused under its option's name", err)
				}
			}()
			PasswordSignIn(a, tt.option)
		})
	}
}

func TestClientAddress(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name    string
		remote  string
		headers map[string]string
		want    string
	}{
		{name: "the connection's address without a proxy header", remote: "203.0.113.7:51234", want: "203.0.113.7"},
		{name: "an address with no port is kept whole", remote: "203.0.113.7", want: "203.0.113.7"},
		{name: "the first X-Forwarded-For entry", remote: "10.0.0.1:1", headers: map[string]string{"X-Forwarded-For": " 203.0.113.7 , 10.0.0.2"}, want: "203.0.113.7"},
		{name: "X-Real-IP before X-Forwarded-For", remote: "10.0.0.1:1", headers: map[string]string{"X-Real-IP": "198.51.100.9", "X-Forwarded-For": "203.0.113.7"}, want: "198.51.100.9"},
		{name: "True-Client-IP first", remote: "10.0.0.1:1", headers: map[string]string{"True-Client-IP": "192.0.2.4", "X-Real-IP": "198.51.100.9"}, want: "192.0.2.4"},
		{name: "an empty header is skipped", remote: "10.0.0.1:1", headers: map[string]string{"X-Forwarded-For": " "}, want: "10.0.0.1"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			r := httptest.NewRequestWithContext(context.Background(), http.MethodPost, "/login", http.NoBody)
			r.RemoteAddr = tt.remote
			for k, v := range tt.headers {
				r.Header.Set(k, v)
			}
			if got := clientAddress(r); got != tt.want {
				t.Errorf("clientAddress() = %q, want %q", got, tt.want)
			}
		})
	}
}

func TestRetryAfterSeconds(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		wait time.Duration
		want int
	}{
		{name: "a wait rounds up", wait: 1200 * time.Millisecond, want: 2},
		{name: "whole seconds stay", wait: time.Minute, want: 60},
		{name: "a wait under a second is one", wait: 10 * time.Millisecond, want: 1},
		{name: "no wait is one, so a client never retries at once", wait: 0, want: 1},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			if got := retryAfterSeconds(tt.wait); got != tt.want {
				t.Errorf("retryAfterSeconds(%v) = %d, want %d", tt.wait, got, tt.want)
			}
		})
	}
}
