//go:build skipAuth

package oidc

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/cccteam/session/internal/oidctest"
	"github.com/cccteam/session/sessioninfo"
	"github.com/cccteam/session/signin"
	"github.com/google/go-cmp/cmp"
)

const testIssuer = "https://id.example.com"

// simulatedRoundTrip runs the simulated login and callback for the registration and
// returns the claims and return address the callback produced.
func simulatedRoundTrip(t *testing.T, registration, returnURL string) (got claims, ret string) {
	t.Helper()

	ctx := t.Context()
	v := NewVerifier(oidctest.NewCookieClient(t).ForRegistration(registration), testIssuer, "", "", "/auth/callback", nil)
	v.simulateAs(registration)

	rec := httptest.NewRecorder()
	u, err := v.AuthCodeURL(ctx, rec, returnURL, signin.LoginOptions{LoginHint: "ignored", SelectAccount: true})
	if err != nil {
		t.Fatalf("Verifier.AuthCodeURL() error = %v", err)
	}
	if u != "/auth/callback" {
		t.Fatalf("Verifier.AuthCodeURL() = %q, want the callback itself: no provider is asked", u)
	}
	callback := httptest.NewRequestWithContext(ctx, http.MethodGet, "/auth/callback", http.NoBody)
	for _, c := range rec.Result().Cookies() {
		callback.AddCookie(c)
	}

	ret, err = v.Verify(ctx, httptest.NewRecorder(), callback, &got)
	if err != nil {
		t.Fatalf("Verifier.Verify() error = %v", err)
	}

	return got, ret
}

// The simulated login is what every developer runs against; the claims it fabricates
// must be the ones the method reads from a real token: the issuer, a durable sub, the
// username as the preferred username, the verified address and the name, and the roles.
func TestVerifier_Verify_simulatedClaims(t *testing.T) {
	t.Setenv("APP_USERNAME", "dev@example.com")
	t.Setenv("APP_ROLES", "Cadet, Crew")

	got, ret := simulatedRoundTrip(t, "gateway", "/app")
	want := claims{
		Iss: testIssuer, Sub: "skipauth-dev@example.com", Email: "dev@example.com", EmailVerified: true,
		PreferredUsername: "dev@example.com", Name: "dev@example.com", Roles: []string{"Cadet", "Crew"},
	}
	if diff := cmp.Diff(want, got); diff != "" {
		t.Errorf("claims mismatch (-want +got):\n%s", diff)
	}
	if ret != "/app" {
		t.Errorf("returnURL = %q, want /app", ret)
	}
}

// A registration reads its own person first: APP_<NAME>_USERNAME over APP_USERNAME.
func TestVerifier_Verify_simulatedRegistrationVariables(t *testing.T) {
	t.Setenv("APP_USERNAME", "client")
	t.Setenv("APP_GATEWAY_USERNAME", "navigator")
	t.Setenv("APP_GATEWAY_ROLES", "Navigator")

	got, _ := simulatedRoundTrip(t, "gateway", "/app")
	if got.PreferredUsername != "navigator" || got.Sub != "skipauth-navigator" || len(got.Roles) != 1 || got.Roles[0] != "Navigator" {
		t.Errorf("claims = %+v, want the gateway registration's own person and roles", got)
	}
}

// The return URL is sanitized, so the simulator cannot send the browser off-site.
func TestVerifier_Verify_simulatedReturnURL(t *testing.T) {
	t.Setenv("APP_USERNAME", "dev@example.com")

	_, ret := simulatedRoundTrip(t, "gateway", "https://evil.example.com/steal")
	if !strings.HasPrefix(ret, "/") || strings.HasPrefix(ret, "//") {
		t.Errorf("returnURL = %q, want a path in the application", ret)
	}
}

// A callback without the login's cookie is refused, as the production verifier refuses it.
func TestVerifier_Verify_simulatedNoCookie(t *testing.T) {
	t.Setenv("APP_USERNAME", "dev@example.com")

	v := NewVerifier(oidctest.NewCookieClient(t).ForRegistration("gateway"), testIssuer, "", "", "/auth/callback", nil)
	var got claims
	_, err := v.Verify(t.Context(), httptest.NewRecorder(), httptest.NewRequestWithContext(t.Context(), http.MethodGet, "/auth/callback", http.NoBody), &got)
	if code := sessioninfo.LoginRefusalCodeOf(err); code != sessioninfo.RefusedNoOIDCCookie {
		t.Errorf("Verifier.Verify() refusal = %q (error %v), want %q", code, err, sessioninfo.RefusedNoOIDCCookie)
	}
}
