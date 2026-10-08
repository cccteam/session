//go:build !skipAuth

package googleoidc

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"
	"time"

	"github.com/cccteam/session/internal/azureoidc"
	internalcookie "github.com/cccteam/session/internal/cookie"
	"github.com/cccteam/session/internal/oidctest"
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

	azure := azureoidc.New(cookies, azureIDP.Server.URL, testClientID, "test-secret", "https://app.example.com/azure/callback")
	google := newWithIssuer(cookies, googleIDP.Server.URL, testClientID, "test-secret", "https://app.example.com/google/callback", testHostedDomain)

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
	azureState := start(func(rec *httptest.ResponseRecorder) (string, error) { return azure.AuthCodeURL(ctx, rec, "/azure") })
	googleState := start(func(rec *httptest.ResponseRecorder) (string, error) { return google.AuthCodeURL(ctx, rec, "/google") })

	if _, ok := browser[internalcookie.AzureStateCookieName]; !ok {
		t.Fatalf("browser cookies = %v, want the Azure state cookie %q", browser, internalcookie.AzureStateCookieName)
	}
	if _, ok := browser[internalcookie.GoogleStateCookieName]; !ok {
		t.Fatalf("browser cookies = %v, want the Google state cookie %q", browser, internalcookie.GoogleStateCookieName)
	}

	var azureClaims json.RawMessage
	returnURL, _, err := azure.Verify(ctx, httptest.NewRecorder(), browser.request(t, fmt.Sprintf("/azure/callback?code=c&state=%s", url.QueryEscape(azureState))), &azureClaims)
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

// TestOIDC_Verify_LegacyStateCookie proves a login started before the upgrade, whose
// browser carries the shared "OIDC" state cookie, completes after it, and that the
// legacy cookie is cleared.
func TestOIDC_Verify_LegacyStateCookie(t *testing.T) {
	t.Parallel()
	ctx := t.Context()

	idp := newFakeIDP(t)
	idp.TokenClaims = workspaceClaims
	o := newWithIssuer(oidctest.NewCookieClient(t), idp.Server.URL, testClientID, "test-secret", "https://app.example.com/callback", testHostedDomain)

	_, callback := startLogin(t, o)
	legacy := legacyStateCallback(t, o.cookieClient, callback, internalcookie.GoogleStateCookieName)

	rec := httptest.NewRecorder()
	var claims json.RawMessage
	if _, _, err := o.Verify(ctx, rec, legacy, &claims); err != nil {
		t.Fatalf("OIDC.Verify() with the legacy state cookie error = %v, want the login to complete", err)
	}

	cleared := false
	for _, c := range rec.Result().Cookies() {
		if c.Name == internalcookie.OIDCCookieName && c.Value == "" && !c.Expires.IsZero() && c.Expires.Before(time.Now()) {
			cleared = true
		}
	}
	if !cleared {
		t.Error("the legacy state cookie was not deleted by the callback")
	}
}

// legacyStateCallback rewrites callback as a pre-upgrade browser would send it: the
// login's state values under the shared legacy cookie name instead of name.
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
