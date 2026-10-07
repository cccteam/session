//go:build !skipAuth

package azureoidc

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	internalcookie "github.com/cccteam/session/internal/cookie"
	"github.com/cccteam/session/internal/oidctest"
)

// TestOIDC_Verify_LegacyStateCookie proves a login started before the upgrade, whose
// browser carries the shared "OIDC" state cookie, completes after it, and that the
// legacy cookie is cleared. (The coexistence of providers is proven in googleoidc.)
func TestOIDC_Verify_LegacyStateCookie(t *testing.T) {
	t.Parallel()
	ctx := t.Context()

	idp := oidctest.NewFakeIDP(t, testClientID)
	idp.TokenClaims = func() map[string]any {
		return map[string]any{"preferred_username": "user@example.com", "tid": "tenant-1", "oid": "object-1"}
	}
	o := New(oidctest.NewCookieClient(t), idp.Server.URL, testClientID, "test-secret", "https://app.example.com/callback")

	_, callback := startLogin(t, o)
	values, readName, err := o.cookieClient.ReadStateCookie(callback, internalcookie.AzureStateCookieName)
	if err != nil || readName != internalcookie.AzureStateCookieName {
		t.Fatalf("ReadStateCookie() = %q, %v, want the Azure state cookie", readName, err)
	}
	written := httptest.NewRecorder()
	o.cookieClient.Cookie().WritePersistentCookie(written, internalcookie.OIDCCookieName, "", false, http.SameSiteDefaultMode, internalcookie.OIDCCookieExpiration, values)
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
