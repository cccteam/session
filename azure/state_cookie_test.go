//go:build !skipAuth

package azure

import (
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"
	"time"

	internalcookie "github.com/cccteam/session/internal/cookie"
	"github.com/cccteam/session/internal/oidctest"
	"github.com/cccteam/session/sessioninfo"
	"github.com/cccteam/session/signin"
)

// TestOIDC_Verify_LegacyStateCookie proves a login started before the upgrade, whose
// browser carries the shared "OIDC" state cookie, completes after it, and that the
// legacy cookie is cleared. (The coexistence of providers is proven in google.)
func TestOIDC_Verify_LegacyStateCookie(t *testing.T) {
	t.Parallel()
	ctx := t.Context()

	idp := oidctest.NewFakeEntra(t, testClientID)
	idp.TokenClaims = func() map[string]any {
		return map[string]any{"preferred_username": "user@example.com", "tid": tenantLake, "oid": "object-1"}
	}
	cookies := oidctest.NewCookieClient(t)
	o := NewOIDC(cookies.ForLegacy("azure"), idp.Server.URL, Tenant(tenantLake), testClientID, "test-secret", "https://app.example.com/callback")

	_, callback := startLogin(t, o)
	values, readName, err := cookies.ReadStateCookie(callback, internalcookie.LegacyStateCookieName("azure"))
	if err != nil || readName != internalcookie.LegacyStateCookieName("azure") {
		t.Fatalf("ReadStateCookie() = %q, %v, want the Azure state cookie", readName, err)
	}
	written := httptest.NewRecorder()
	cookies.Cookie().WritePersistentCookie(written, internalcookie.OIDCCookieName, "", false, http.SameSiteDefaultMode, internalcookie.OIDCCookieExpiration, values)
	legacy := httptest.NewRequestWithContext(ctx, http.MethodGet, callback.URL.String(), http.NoBody)
	for _, c := range written.Result().Cookies() {
		legacy.AddCookie(c)
	}

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

// browserJar is a browser's cookie store: a cookie written later replaces one of the
// same name.
type browserJar map[string]*http.Cookie

func (j browserJar) store(rec *httptest.ResponseRecorder) {
	for _, c := range rec.Result().Cookies() {
		j[c.Name] = c
	}
}

func (j browserJar) request(t *testing.T, target string) *http.Request {
	t.Helper()

	r := httptest.NewRequestWithContext(t.Context(), http.MethodGet, target, http.NoBody)
	for _, c := range j {
		r.AddCookie(c)
	}

	return r
}

// beginLogin starts a login of o in the browser and returns its state.
func beginLogin(t *testing.T, browser browserJar, o *OIDC, returnURL string) string {
	t.Helper()

	rec := httptest.NewRecorder()
	raw, err := o.AuthCodeURL(t.Context(), rec, returnURL, signin.LoginOptions{})
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

// TestOIDC_StateCookie_RegistrationsCoexist proves two registrations of the Azure method,
// two Entra tenants on one Auth, keep separate state: each login writes the cookie of its
// own registration (OIDC-<session cookie name>-<registration>), logins begun in turn both complete, and a
// callback carrying the other registration's state is refused before its provider is
// asked, so one tenant's state never completes a login at the other (RFC 9700 §4.4.2).
func TestOIDC_StateCookie_RegistrationsCoexist(t *testing.T) {
	t.Parallel()
	ctx := t.Context()

	cookies := oidctest.NewCookieClient(t)
	claimsOf := func(tenant, oid string) func() map[string]any {
		return func() map[string]any {
			return map[string]any{"preferred_username": oid + "@example.com", "tid": tenant, "oid": oid}
		}
	}
	lakeIDP := oidctest.NewFakeEntra(t, testClientID)
	lakeIDP.TokenClaims = claimsOf(tenantLake, "lake-1")
	riverIDP := oidctest.NewFakeEntra(t, testClientID)
	riverIDP.TokenClaims = claimsOf(tenantRiver, "river-1")
	lakeside := NewOIDC(cookies.ForRegistration("lakeside"), lakeIDP.Server.URL, Tenant(tenantLake), testClientID, "test-secret", "https://app.example.com/lakeside/callback")
	riverside := NewOIDC(cookies.ForRegistration("riverside"), riverIDP.Server.URL, Tenant(tenantRiver), testClientID, "test-secret", "https://app.example.com/riverside/callback")

	browser := browserJar{}
	lakeState := beginLogin(t, browser, lakeside, "/lake")
	riverState := beginLogin(t, browser, riverside, "/river")
	for _, name := range []string{internalcookie.StateCookieName(cookies.CookieName, "lakeside"), internalcookie.StateCookieName(cookies.CookieName, "riverside")} {
		if _, ok := browser[name]; !ok {
			t.Fatalf("browser cookies = %v, want the state cookie %q", browser, name)
		}
	}

	var claims json.RawMessage
	returnURL, _, err := lakeside.Verify(ctx, httptest.NewRecorder(), browser.request(t, "/lakeside/callback?code=c&state="+url.QueryEscape(lakeState)), &claims)
	if err != nil || returnURL != "/lake" {
		t.Fatalf("lakeside Verify() after riverside's login began = %q, %v; want the lakeside login to complete to /lake", returnURL, err)
	}
	returnURL, _, err = riverside.Verify(ctx, httptest.NewRecorder(), browser.request(t, "/riverside/callback?code=c&state="+url.QueryEscape(riverState)), &claims)
	if err != nil || returnURL != "/river" {
		t.Fatalf("riverside Verify() after lakeside's login completed = %q, %v; want the riverside login to complete to /river", returnURL, err)
	}

	// Lakeside's state at riverside's callback: refused, and riverside's token endpoint
	// is never asked, so the code is never exchanged with lakeside's verifier.
	riverIDP.TokenClaims = func() map[string]any {
		t.Error("riverside's token endpoint was called for a callback carrying lakeside's state")

		return nil
	}
	other := browserJar{}
	lakeState = beginLogin(t, other, lakeside, "/lake")
	_, _, err = riverside.Verify(ctx, httptest.NewRecorder(), other.request(t, "/riverside/callback?code=c&state="+url.QueryEscape(lakeState)), &claims)
	var refusal *sessioninfo.LoginRefusal
	if !errors.As(err, &refusal) || refusal.Code() != sessioninfo.RefusedNoOIDCCookie {
		t.Fatalf("riverside Verify() with lakeside's state error = %v, want the login refused with %s", err, sessioninfo.RefusedNoOIDCCookie)
	}
}

// TestOIDC_Verify_RegistrationRefusesLegacyStateCookie proves a registration's callback
// never completes a login from the shared "OIDC" state cookie of v0.12: only the legacy
// Azure session reads it (TestOIDC_Verify_LegacyStateCookie), through its own cookies.
func TestOIDC_Verify_RegistrationRefusesLegacyStateCookie(t *testing.T) {
	t.Parallel()
	ctx := t.Context()

	idp := oidctest.NewFakeEntra(t, testClientID)
	idp.TokenClaims = func() map[string]any {
		t.Error("the token endpoint was called for a login the callback should have refused")

		return nil
	}
	cookies := oidctest.NewCookieClient(t)
	o := NewOIDC(cookies.ForRegistration("azure"), idp.Server.URL, Tenant(tenantLake), testClientID, "test-secret", "https://app.example.com/callback")

	_, callback := startLogin(t, o)
	values, readName, err := cookies.ReadStateCookie(callback, internalcookie.StateCookieName(cookies.CookieName, "azure"))
	if err != nil || readName != internalcookie.StateCookieName(cookies.CookieName, "azure") {
		t.Fatalf("ReadStateCookie() = %q, %v, want the registration's state cookie", readName, err)
	}
	written := httptest.NewRecorder()
	cookies.Cookie().WritePersistentCookie(written, internalcookie.OIDCCookieName, "", false, http.SameSiteDefaultMode, internalcookie.OIDCCookieExpiration, values)
	legacy := httptest.NewRequestWithContext(ctx, http.MethodGet, callback.URL.String(), http.NoBody)
	for _, c := range written.Result().Cookies() {
		legacy.AddCookie(c)
	}

	var claims json.RawMessage
	_, _, err = o.Verify(ctx, httptest.NewRecorder(), legacy, &claims)
	var refusal *sessioninfo.LoginRefusal
	if !errors.As(err, &refusal) || refusal.Code() != sessioninfo.RefusedNoOIDCCookie {
		t.Fatalf("OIDC.Verify() with the legacy state cookie error = %v, want the login refused with %s", err, sessioninfo.RefusedNoOIDCCookie)
	}
}
