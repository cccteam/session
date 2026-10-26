package deviceflow

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"
)

// fake is an application's machine outlet with the device flow, as the session
// library serves it: the wire shapes of the two public endpoints, the outlet's bearer
// check and challenges, the rotation of a refreshed pair and the revocation of a
// family on a reuse. Its clock is the test's: the waits the client under test asks
// for advance it, so the poll interval is enforced without sleeping.
type fake struct {
	t      *testing.T
	server *httptest.Server
	// prefix is where the public endpoints and the outlet sit, outlet the outlet's
	// name, verification the approval page's path, as the application names it.
	prefix, outlet, verification string
	// interval is the interval told to the client, in seconds, and minimumGap the
	// one enforced between polls: larger than interval, it provokes slow_down.
	interval, minimumGap int
	// codeLifetime and accessLifetime are how long a device code and an access token
	// live, in seconds.
	codeLifetime, accessLifetime int

	mu sync.Mutex
	// offset is how far the test moved the clock ahead.
	offset time.Duration
	codes  map[string]*fakeCode
	// alive is every family not revoked.
	alive map[int]bool
	// access and refresh are the tokens by their secret.
	access, refresh map[string]*fakeToken
	nextFamily      int
	// refreshes counts the refresh grants answered with a pair, outletCalls the
	// requests the outlet answered 200, and polls the device code polls.
	refreshes, outletCalls, polls int
}

// fakeCode is one device authorization.
type fakeCode struct {
	userCode, client string
	expiresAt        time.Time
	lastPoll         time.Time
	// decided is "", "approved" or "denied".
	decided  string
	redeemed bool
}

// fakeToken is one token of a pair.
type fakeToken struct {
	family    int
	expiresAt time.Time
	// pair is the other token of the pair: the access token's secret on a refresh token.
	pair    string
	rotated bool
}

// newFake serves the outlet at prefix.
func newFake(t *testing.T, prefix string) *fake {
	t.Helper()

	f := &fake{
		t: t, prefix: prefix, outlet: "machines", verification: "/device", interval: 5, minimumGap: 5, codeLifetime: 600, accessLifetime: 3600,
		codes: map[string]*fakeCode{}, alive: map[int]bool{}, access: map[string]*fakeToken{}, refresh: map[string]*fakeToken{},
	}
	mux := http.NewServeMux()
	mux.HandleFunc("POST "+prefix+"/oauth/device/authorize", f.authorize)
	mux.HandleFunc("POST "+prefix+"/oauth/token", f.token)
	mux.HandleFunc("GET "+prefix+"/whoami", f.whoami)
	mux.HandleFunc("POST "+prefix+"/echo", f.echo)
	f.server = httptest.NewServer(mux)
	t.Cleanup(f.server.Close)

	return f
}

// now is the fake's clock.
func (f *fake) now() time.Time {
	return time.Now().Add(f.offset)
}

// advance moves the clock ahead by d.
func (f *fake) advance(d time.Duration) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.offset += d
}

// secret mints a token secret.
func (f *fake) secret() string {
	raw := make([]byte, 16)
	if _, err := rand.Read(raw); err != nil {
		f.t.Fatalf("rand.Read() error = %v", err)
	}

	return hex.EncodeToString(raw)
}

// issue mints a pair in a new family, as a redeemed grant does; the caller holds
// the lock.
func (f *fake) issue() *tokenAnswer {
	f.nextFamily++
	f.alive[f.nextFamily] = true
	access, refresh := f.secret(), f.secret()
	f.access[access] = &fakeToken{family: f.nextFamily, expiresAt: f.now().Add(time.Duration(f.accessLifetime) * time.Second)}
	f.refresh[refresh] = &fakeToken{family: f.nextFamily, pair: access}

	return &tokenAnswer{AccessToken: access, TokenType: "Bearer", ExpiresIn: f.accessLifetime, RefreshToken: refresh}
}

// grant is a pair as a signed-in program holds it.
func (f *fake) grant() *tokenAnswer {
	f.mu.Lock()
	defer f.mu.Unlock()

	return f.issue()
}

// killAccess forgets an access token, as the application does once it expired or
// was rotated; its refresh token stays good.
func (f *fake) killAccess(access string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	delete(f.access, access)
}

// revokeFamily revokes the family of refresh, as a revocation by hand does.
func (f *fake) revokeFamily(refresh string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.alive[f.refresh[refresh].family] = false
}

// decide records the person's decision on the user code.
func (f *fake) decide(userCode, decision string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	for _, code := range f.codes {
		if code.userCode == userCode {
			code.decided = decision

			return
		}
	}
	f.t.Errorf("decide(%q): no such code", userCode)
}

// counts is what the fake answered so far.
func (f *fake) counts() (refreshes, outletCalls, polls int) {
	f.mu.Lock()
	defer f.mu.Unlock()

	return f.refreshes, f.outletCalls, f.polls
}

// fields decodes a request's JSON fields.
func (f *fake) fields(w http.ResponseWriter, r *http.Request) (map[string]string, bool) {
	if r.Header.Get("Content-Type") != "application/json" {
		f.refuse(w, "invalid_request", "the request is not JSON")

		return nil, false
	}
	var fields map[string]string
	if err := json.NewDecoder(r.Body).Decode(&fields); err != nil {
		f.refuse(w, "invalid_request", "the request is not JSON")

		return nil, false
	}

	return fields, true
}

// answer writes body as the endpoints do.
func (f *fake) answer(w http.ResponseWriter, status int, body any) {
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	if err := json.NewEncoder(w).Encode(body); err != nil {
		f.t.Errorf("json.Encoder.Encode() error = %v", err)
	}
}

// refuse writes the RFC's 400.
func (f *fake) refuse(w http.ResponseWriter, code, description string) {
	f.answer(w, http.StatusBadRequest, oauthError{Code: code, Description: description})
}

// authorize is the device authorization endpoint.
func (f *fake) authorize(w http.ResponseWriter, r *http.Request) {
	fields, ok := f.fields(w, r)
	if !ok {
		return
	}
	if fields["outlet"] != f.outlet {
		f.refuse(w, "invalid_request", fmt.Sprintf("%q is not a machine outlet of this application", fields["outlet"]))

		return
	}
	if fields["client_id"] == "" || len(fields["client_id"]) > 200 {
		f.refuse(w, "invalid_request", "a device authorization names its client, in at most 200 characters")

		return
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	deviceCode := f.secret()
	userCode := strings.ToUpper(f.secret()[:4] + "-" + f.secret()[:4])
	f.codes[deviceCode] = &fakeCode{userCode: userCode, client: fields["client_id"], expiresAt: f.now().Add(time.Duration(f.codeLifetime) * time.Second)}
	f.answer(w, http.StatusOK, deviceAuthorization{
		DeviceCode: deviceCode, UserCode: userCode, VerificationURI: f.verification, VerificationURIComplete: f.verification + "?userCode=" + userCode,
		ExpiresIn: f.codeLifetime, Interval: f.interval,
	})
}

// token is the token endpoint.
func (f *fake) token(w http.ResponseWriter, r *http.Request) {
	fields, ok := f.fields(w, r)
	if !ok {
		return
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	switch fields["grant_type"] {
	case grantDeviceCode:
		f.redeem(w, fields["device_code"])
	case grantRefreshToken:
		f.rotate(w, fields["refresh_token"])
	default:
		f.refuse(w, "unsupported_grant_type", "grant_type is "+grantDeviceCode+" or "+grantRefreshToken)
	}
}

// redeem answers a device_code grant; the caller holds the lock.
func (f *fake) redeem(w http.ResponseWriter, deviceCode string) {
	if deviceCode == "" {
		f.refuse(w, "invalid_request", "device_code is required")

		return
	}
	code := f.codes[deviceCode]
	if code == nil || code.redeemed {
		f.refuse(w, "invalid_grant", "the device code is unknown or was redeemed")

		return
	}
	f.polls++
	now := f.now()
	switch {
	case !now.Before(code.expiresAt):
		f.refuse(w, "expired_token", "the device code expired; start again")
	case !code.lastPoll.IsZero() && now.Sub(code.lastPoll) < time.Duration(f.minimumGap)*time.Second:
		code.lastPoll = now
		f.refuse(w, "slow_down", "poll less often")
	case code.decided == "denied":
		f.refuse(w, "access_denied", "the person denied the request")
	case code.decided == "approved":
		code.redeemed = true
		f.answer(w, http.StatusOK, f.issue())
	default:
		code.lastPoll = now
		f.refuse(w, "authorization_pending", "the person has not decided yet")
	}
}

// rotate answers a refresh_token grant; the caller holds the lock.
func (f *fake) rotate(w http.ResponseWriter, refresh string) {
	if refresh == "" {
		f.refuse(w, "invalid_request", "refresh_token is required")

		return
	}
	tok := f.refresh[refresh]
	if tok == nil {
		f.refuse(w, "invalid_grant", "the refresh token is not valid; sign in again")

		return
	}
	if tok.rotated || !f.alive[tok.family] {
		f.alive[tok.family] = false
		f.refuse(w, "invalid_grant", "the refresh token is not valid; sign in again")

		return
	}
	tok.rotated = true
	delete(f.access, tok.pair)
	next := f.issue()
	f.refresh[next.RefreshToken].family, f.access[next.AccessToken].family = tok.family, tok.family
	f.refreshes++
	f.answer(w, http.StatusOK, next)
}

// bearer checks the request's bearer token on the outlet and answers the challenge
// when it is refused.
func (f *fake) bearer(w http.ResponseWriter, r *http.Request) bool {
	f.mu.Lock()
	defer f.mu.Unlock()
	scheme, secret, ok := strings.Cut(r.Header.Get("Authorization"), " ")
	if !ok || scheme != "Bearer" {
		w.Header().Set("WWW-Authenticate", fmt.Sprintf("Bearer realm=%q", f.outlet))
		f.answer(w, http.StatusUnauthorized, map[string]string{"message": "a bearer token is required"})

		return false
	}
	tok := f.access[secret]
	if tok == nil || !f.alive[tok.family] || !f.now().Before(tok.expiresAt) {
		w.Header().Set("WWW-Authenticate", fmt.Sprintf("Bearer realm=%q, error=\"invalid_token\"", f.outlet))
		f.answer(w, http.StatusUnauthorized, map[string]string{"message": "invalid token"})

		return false
	}
	f.outletCalls++

	return true
}

// whoami is the outlet's GET: the client the token was issued to.
func (f *fake) whoami(w http.ResponseWriter, r *http.Request) {
	if !f.bearer(w, r) {
		return
	}
	f.answer(w, http.StatusOK, map[string]string{"client": "corral"})
}

// echo is the outlet's POST: the body back.
func (f *fake) echo(w http.ResponseWriter, r *http.Request) {
	if !f.bearer(w, r) {
		return
	}
	body, err := io.ReadAll(r.Body)
	if err != nil {
		f.t.Errorf("io.ReadAll() error = %v", err)
	}
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(body)
}
