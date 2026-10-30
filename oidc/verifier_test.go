//go:build !skipAuth

package oidc

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/cccteam/session/internal/oidctest"
	"github.com/cccteam/session/sessioninfo"
	"github.com/cccteam/session/signin"
	"github.com/google/go-cmp/cmp"
)

const (
	testClientID    = "lanterns"
	testRedirectURL = "https://app.example.com/callback"
)

// gatewayClaims are the claims a provider such as an identity gateway issues: a subject,
// the names, a verified address, and the roles it asserts.
func gatewayClaims() map[string]any {
	return map[string]any{
		"sub": "cadet", "email": "cadet@example.com", "email_verified": true, "preferred_username": "cadet",
		"name": "Cadet Example", "roles": []string{"Cadet"}, "amr": []string{"pwd"},
	}
}

func newVerifier(t *testing.T, idp *oidctest.FakeIDP, clientSecret string, scopes ...string) *Verifier {
	t.Helper()

	return NewVerifier(oidctest.NewCookieClient(t).ForRegistration("gateway"), idp.Server.URL, testClientID, clientSecret, testRedirectURL, scopes)
}

// startLogin runs AuthCodeURL and returns the parsed authorization URL plus a callback
// request carrying the state cookie and the authorization URL's state.
func startLogin(t *testing.T, v *Verifier, options signin.LoginOptions) (authURL *url.URL, callback *http.Request) {
	t.Helper()

	ctx := t.Context()
	rec := httptest.NewRecorder()
	rawURL, err := v.AuthCodeURL(ctx, rec, "/app", options)
	if err != nil {
		t.Fatalf("Verifier.AuthCodeURL() error = %v", err)
	}
	authURL, err = url.Parse(rawURL)
	if err != nil {
		t.Fatalf("url.Parse() error = %v", err)
	}

	callback = httptest.NewRequestWithContext(ctx, http.MethodGet, fmt.Sprintf("/callback?code=test-code&state=%s", url.QueryEscape(authURL.Query().Get("state"))), http.NoBody)
	for _, c := range rec.Result().Cookies() {
		callback.AddCookie(c)
	}

	return authURL, callback
}

// TestVerifier_AuthCodeURL proves the authorization request: the provider's endpoint,
// the client, the redirect address, a fresh state and PKCE challenge per login, the
// scopes asked for, and the login page's hints forwarded as the provider's parameters.
func TestVerifier_AuthCodeURL(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name          string
		scopes        []string
		options       signin.LoginOptions
		wantScope     string
		wantLoginHint string
		wantPrompt    string
	}{
		{name: "the default scopes, no hints", wantScope: "openid email profile"},
		{name: "the scopes given, after openid", scopes: []string{"groups", "email"}, wantScope: "openid groups email"},
		{name: "the hints ride as the provider's parameters", options: signin.LoginOptions{LoginHint: "cadet", SelectAccount: true}, wantScope: "openid email profile", wantLoginHint: "cadet", wantPrompt: "select_account"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			idp := oidctest.NewFakeIDP(t, testClientID)
			v := newVerifier(t, idp, "", tt.scopes...)

			authURL, _ := startLogin(t, v, tt.options)
			q := authURL.Query()
			if got := strings.TrimSuffix(authURL.String(), "?"+authURL.RawQuery); got != idp.Server.URL+"/auth" {
				t.Errorf("authorization endpoint = %q, want %q", got, idp.Server.URL+"/auth")
			}
			if q.Get("client_id") != testClientID || q.Get("redirect_uri") != testRedirectURL || q.Get("response_type") != "code" {
				t.Errorf("client_id, redirect_uri, response_type = %q, %q, %q", q.Get("client_id"), q.Get("redirect_uri"), q.Get("response_type"))
			}
			if q.Get("state") == "" || q.Get("code_challenge") == "" || q.Get("code_challenge_method") != "S256" {
				t.Errorf("state = %q, code_challenge = %q, code_challenge_method = %q: want a state and an S256 challenge", q.Get("state"), q.Get("code_challenge"), q.Get("code_challenge_method"))
			}
			if got := q.Get("scope"); got != tt.wantScope {
				t.Errorf("scope = %q, want %q", got, tt.wantScope)
			}
			if got := q.Get("login_hint"); got != tt.wantLoginHint {
				t.Errorf("login_hint = %q, want %q", got, tt.wantLoginHint)
			}
			if got := q.Get("prompt"); got != tt.wantPrompt {
				t.Errorf("prompt = %q, want %q", got, tt.wantPrompt)
			}

			// A second login must use fresh state and PKCE values.
			authURL2, _ := startLogin(t, v, tt.options)
			if authURL2.Query().Get("state") == q.Get("state") || authURL2.Query().Get("code_challenge") == q.Get("code_challenge") {
				t.Error("state or PKCE challenge reused across logins")
			}
		})
	}
}

// TestVerifier_Verify proves a completed round trip: the token's claims as the provider
// issued them, and the return address the login recorded.
func TestVerifier_Verify(t *testing.T) {
	t.Parallel()

	idp := oidctest.NewFakeIDP(t, testClientID)
	idp.TokenClaims = gatewayClaims
	v := newVerifier(t, idp, "")
	_, callback := startLogin(t, v, signin.LoginOptions{})

	var got claims
	returnURL, err := v.Verify(t.Context(), httptest.NewRecorder(), callback, &got)
	if err != nil {
		t.Fatalf("Verifier.Verify() error = %v", err)
	}
	if returnURL != "/app" {
		t.Errorf("returnURL = %q, want /app", returnURL)
	}
	want := claims{
		Iss: idp.Server.URL, Sub: "cadet", Email: "cadet@example.com", EmailVerified: true, PreferredUsername: "cadet",
		Name: "Cadet Example", Roles: []string{"Cadet"}, Amr: []string{"pwd"},
	}
	if diff := cmp.Diff(want, got); diff != "" {
		t.Errorf("claims mismatch (-want +got):\n%s", diff)
	}
}

// TestVerifier_Verify_clientAuthentication proves how the code exchange authenticates:
// a public client sends its client ID in the request body and nothing else, no
// authorization header with an empty password; a confidential client sends its secret.
func TestVerifier_Verify_clientAuthentication(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name         string
		clientSecret string
		wantSecret   bool
	}{
		{name: "a public client exchanges with its client ID alone", clientSecret: ""},
		{name: "a confidential client sends its secret", clientSecret: "s3cret", wantSecret: true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			idp := oidctest.NewFakeIDP(t, testClientID)
			idp.TokenClaims = gatewayClaims
			v := newVerifier(t, idp, tt.clientSecret)
			_, callback := startLogin(t, v, signin.LoginOptions{})

			var got claims
			if _, err := v.Verify(t.Context(), httptest.NewRecorder(), callback, &got); err != nil {
				t.Fatalf("Verifier.Verify() error = %v", err)
			}
			requests := idp.TokenRequests()
			if len(requests) == 0 {
				t.Fatal("the token endpoint received no request")
			}
			last := requests[len(requests)-1]
			if last.Form.Get("grant_type") != "authorization_code" || last.Form.Get("code") != "test-code" || last.Form.Get("code_verifier") == "" {
				t.Errorf("token request form = %v, want the code exchange with its PKCE verifier", last.Form)
			}
			sentSecret := last.Authorization != "" || last.Form.Has("client_secret")
			if sentSecret != tt.wantSecret {
				t.Errorf("secret sent = %v (Authorization %q, client_secret in form %v), want %v", sentSecret, last.Authorization, last.Form.Has("client_secret"), tt.wantSecret)
			}
			if !tt.wantSecret && last.Form.Get("client_id") != testClientID {
				t.Errorf("client_id in the form = %q, want %q", last.Form.Get("client_id"), testClientID)
			}
		})
	}
}

// TestVerifier_Verify_refusals proves the refusals of the shared flow reach the caller
// coded: a token for another client or from another issuer, a failed exchange, and a
// callback without the login's cookie.
func TestVerifier_Verify_refusals(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name     string
		claims   func(issuer string) map[string]any
		status   int
		noCookie bool
		wantCode sessioninfo.LoginRefusalCode
	}{
		{name: "a token for another client is refused", claims: func(string) map[string]any { c := gatewayClaims(); c["aud"] = "someone-else"; return c }, wantCode: sessioninfo.RefusedIDTokenVerification},
		{name: "a token from another issuer is refused", claims: func(string) map[string]any { c := gatewayClaims(); c["iss"] = "https://other.example.com"; return c }, wantCode: sessioninfo.RefusedIDTokenVerification},
		{name: "a failed exchange is refused", claims: func(string) map[string]any { return gatewayClaims() }, status: http.StatusInternalServerError, wantCode: sessioninfo.RefusedTokenExchange},
		{name: "a callback without the login's cookie is refused", claims: func(string) map[string]any { return gatewayClaims() }, noCookie: true, wantCode: sessioninfo.RefusedNoOIDCCookie},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			idp := oidctest.NewFakeIDP(t, testClientID)
			idp.TokenClaims = func() map[string]any { return tt.claims(idp.Server.URL) }
			idp.TokenStatus = tt.status
			v := newVerifier(t, idp, "")
			_, callback := startLogin(t, v, signin.LoginOptions{})
			if tt.noCookie {
				callback = httptest.NewRequestWithContext(t.Context(), http.MethodGet, callback.URL.String(), http.NoBody)
			}

			var got claims
			_, err := v.Verify(t.Context(), httptest.NewRecorder(), callback, &got)
			if code := sessioninfo.LoginRefusalCodeOf(err); code != tt.wantCode {
				t.Errorf("Verifier.Verify() refusal = %q (error %v), want %q", code, err, tt.wantCode)
			}
		})
	}
}
