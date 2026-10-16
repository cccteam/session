//go:build !skipAuth

package google

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"

	"github.com/cccteam/session/azure"
	internalcookie "github.com/cccteam/session/internal/cookie"
	"github.com/cccteam/session/internal/oidctest"
	"github.com/cccteam/session/sessioninfo"
)

// jar is a browser's cookie store: a cookie written later replaces one of the same name.
type jar map[string]*http.Cookie

func (j jar) store(rec *httptest.ResponseRecorder) {
	for _, c := range rec.Result().Cookies() {
		j[c.Name] = c
	}
}

func (j jar) request(t *testing.T, target string) *http.Request {
	t.Helper()

	r := httptest.NewRequestWithContext(t.Context(), http.MethodGet, target, http.NoBody)
	for _, c := range j {
		r.AddCookie(c)
	}

	return r
}

// TestOIDC_StateCookie_ProvidersCoexist proves an Azure and a Google login started in the
// same browser keep separate state: each callback completes, whichever started last. With
// one shared state cookie the later login overwrote the earlier one's state and PKCE
// verifier, and the earlier callback was refused.
func TestOIDC_StateCookie_ProvidersCoexist(t *testing.T) {
	t.Parallel()
	ctx := t.Context()

	cookies := oidctest.NewCookieClient(t)

	azureIDP := oidctest.NewFakeIDP(t, testClientID)
	azureIDP.TokenClaims = func() map[string]any {
		return map[string]any{"preferred_username": "user@example.com", "tid": "tenant-1", "oid": "object-1"}
	}
	googleIDP := newFakeIDP(t)
	googleIDP.TokenClaims = workspaceClaims

	entra := azure.NewOIDC(cookies.ForRegistration("azure"), azureIDP.Server.URL, testClientID, "test-secret", "https://app.example.com/azure/callback")
	google := newWithIssuer(cookies.ForRegistration("google"), googleIDP.Server.URL, testClientID, "test-secret", "https://app.example.com/google/callback", []string{testHostedDomain})

	browser := jar{}
	start := func(authCodeURL func(rec *httptest.ResponseRecorder) (string, error)) string {
		rec := httptest.NewRecorder()
		raw, err := authCodeURL(rec)
		if err != nil {
			t.Fatalf("AuthCodeURL() error = %v", err)
		}
		browser.store(rec)
		u, err := url.Parse(raw)
		if err != nil {
			t.Fatalf("url.Parse() error = %v", err)
		}

		return u.Query().Get("state")
	}

	// Azure first, then Google: the Google login's state cookie is written last.
	azureState := start(func(rec *httptest.ResponseRecorder) (string, error) { return entra.AuthCodeURL(ctx, rec, "/azure") })
	googleState := start(func(rec *httptest.ResponseRecorder) (string, error) {
		return google.AuthCodeURL(ctx, rec, "/google", "")
	})

	if _, ok := browser[internalcookie.StateCookieName("azure")]; !ok {
		t.Fatalf("browser cookies = %v, want the Azure state cookie %q", browser, internalcookie.StateCookieName("azure"))
	}
	if _, ok := browser[internalcookie.StateCookieName("google")]; !ok {
		t.Fatalf("browser cookies = %v, want the Google state cookie %q", browser, internalcookie.StateCookieName("google"))
	}

	var azureClaims json.RawMessage
	returnURL, _, err := entra.Verify(ctx, httptest.NewRecorder(), browser.request(t, fmt.Sprintf("/azure/callback?code=c&state=%s", url.QueryEscape(azureState))), &azureClaims)
	if err != nil {
		t.Fatalf("Azure Verify() after a later Google login error = %v, want the Azure login to complete", err)
	}
	if returnURL != "/azure" {
		t.Errorf("Azure Verify() returnURL = %q, want %q", returnURL, "/azure")
	}

	var googleClaims json.RawMessage
	returnURL, _, err = google.Verify(ctx, httptest.NewRecorder(), browser.request(t, fmt.Sprintf("/google/callback?code=c&state=%s", url.QueryEscape(googleState))), &googleClaims)
	if err != nil {
		t.Fatalf("Google Verify() error = %v, want the Google login to complete", err)
	}
	if returnURL != "/google" {
		t.Errorf("Google Verify() returnURL = %q, want %q", returnURL, "/google")
	}
}

// TestOIDC_Verify_RefusesLegacyStateCookie proves a registration's callback never
// completes a login from the shared "OIDC" state cookie of v0.12: the registration's
// cookie is the only one it reads, so the callback is refused (no_oidc_cookie) and the
// shared cookie is left alone. (The legacy Azure session, which has v0.12 logins to
// complete, reads it through its own cookies; see azure.)
func TestOIDC_Verify_RefusesLegacyStateCookie(t *testing.T) {
	t.Parallel()
	ctx := t.Context()

	idp := newFakeIDP(t)
	idp.TokenClaims = func() map[string]any {
		t.Error("the token endpoint was called for a login the callback should have refused")

		return workspaceClaims()
	}
	cookies := oidctest.NewCookieClient(t)
	o := newWithIssuer(cookies.ForRegistration("google"), idp.Server.URL, testClientID, "test-secret", "https://app.example.com/callback", []string{testHostedDomain})

	_, callback := startLogin(t, o)
	legacy := legacyStateCallback(t, cookies, callback, internalcookie.StateCookieName("google"))

	rec := httptest.NewRecorder()
	var claims json.RawMessage
	_, _, err := o.Verify(ctx, rec, legacy, &claims)
	var refusal *sessioninfo.LoginRefusal
	if !errors.As(err, &refusal) || refusal.Code() != sessioninfo.RefusedNoOIDCCookie {
		t.Fatalf("OIDC.Verify() with the legacy state cookie error = %v, want the login refused with %s", err, sessioninfo.RefusedNoOIDCCookie)
	}
	for _, c := range rec.Result().Cookies() {
		if c.Name == internalcookie.OIDCCookieName {
			t.Errorf("the callback touched the shared %s cookie: %v", internalcookie.OIDCCookieName, c)
		}
	}
}

func legacyStateCallback(t *testing.T, cookies *internalcookie.Client, callback *http.Request, name string) *http.Request {
	t.Helper()

	values, readName, err := cookies.ReadStateCookie(callback, name)
	if err != nil || readName != name {
		t.Fatalf("ReadStateCookie() = %q, %v, want the %q cookie", readName, err, name)
	}
	rec := httptest.NewRecorder()
	cookies.Cookie().WritePersistentCookie(rec, internalcookie.OIDCCookieName, "", false, http.SameSiteDefaultMode, internalcookie.OIDCCookieExpiration, values)

	legacy := httptest.NewRequestWithContext(callback.Context(), http.MethodGet, callback.URL.String(), http.NoBody)
	for _, c := range rec.Result().Cookies() {
		legacy.AddCookie(c)
	}

	return legacy
}
