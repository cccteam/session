//go:build !skipAuth

package azure

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/cccteam/httpio"
	internalcookie "github.com/cccteam/session/internal/cookie"
	"github.com/cccteam/session/internal/oidctest"
	"github.com/cccteam/session/sessioninfo"
)

const testClientID = "test-client-id"

// newVerifier is an OIDC for tenants over idp, a fake Microsoft identity platform,
// under the registration named.
func newVerifier(t *testing.T, idp *oidctest.FakeIDP, tenants TenantSet, registration string) *OIDC {
	t.Helper()

	return NewOIDC(oidctest.NewCookieClient(t).ForRegistration(registration), idp.Server.URL, tenants, testClientID, "test-secret", "https://app.example.com/callback")
}

// serverHost is the host idp serves on.
func serverHost(t *testing.T, idp *oidctest.FakeIDP) string {
	t.Helper()

	u, err := url.Parse(idp.Server.URL)
	if err != nil {
		t.Fatalf("url.Parse() error = %v", err)
	}

	return u.Host
}

// startLogin runs AuthCodeURL and returns the parsed redirect URL plus a callback
// request pre-loaded with the OIDC cookie, the redirect's state value, and the
// provider's session_state.
func startLogin(t *testing.T, o *OIDC) (authURL *url.URL, callback *http.Request) {
	t.Helper()

	ctx := t.Context()
	rec := httptest.NewRecorder()
	rawURL, err := o.AuthCodeURL(ctx, rec, "/app")
	if err != nil {
		t.Fatalf("OIDC.AuthCodeURL() error = %v", err)
	}
	authURL, err = url.Parse(rawURL)
	if err != nil {
		t.Fatalf("url.Parse() error = %v", err)
	}

	target := fmt.Sprintf("/callback?code=test-code&state=%s&session_state=idp-session-1", url.QueryEscape(authURL.Query().Get("state")))
	callback = httptest.NewRequestWithContext(ctx, http.MethodGet, target, http.NoBody)
	for _, c := range rec.Result().Cookies() {
		callback.AddCookie(c)
	}

	return authURL, callback
}

func TestOIDC_AuthCodeURL(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name     string
		tenants  TenantSet
		wantPath string
	}{
		{name: "one tenant authorizes at the tenant's own endpoint", tenants: Tenant(tenantLake), wantPath: "/" + tenantLake + "/oauth2/v2.0/authorize"},
		{name: "several tenants authorize at organizations", tenants: Tenants(Tenant(tenantLake), Tenant(tenantRiver)), wantPath: "/organizations/oauth2/v2.0/authorize"},
		{name: "any tenant authorizes at organizations", tenants: AnyTenant(), wantPath: "/organizations/oauth2/v2.0/authorize"},
		{name: "personal accounts authorize at consumers", tenants: PersonalAccounts(), wantPath: "/consumers/oauth2/v2.0/authorize"},
		{name: "any tenant and personal accounts authorize at common", tenants: Tenants(AnyTenant(), PersonalAccounts()), wantPath: "/common/oauth2/v2.0/authorize"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			idp := oidctest.NewFakeEntra(t, testClientID)
			o := newVerifier(t, idp, tt.tenants, "azure")

			authURL, _ := startLogin(t, o)

			if authURL.Host != serverHost(t, idp) || authURL.Path != tt.wantPath {
				t.Errorf("authorization URL = %s, want %s at the provider", authURL, tt.wantPath)
			}
			q := authURL.Query()
			if q.Get("state") == "" {
				t.Error("state parameter is empty")
			}
			if q.Get("code_challenge") == "" || q.Get("code_challenge_method") != "S256" {
				t.Errorf("PKCE challenge missing or not S256: method = %q", q.Get("code_challenge_method"))
			}
			if !strings.Contains(q.Get("scope"), "openid") {
				t.Errorf("scope = %q, want it to include openid", q.Get("scope"))
			}

			// A second login must use fresh state and PKCE values.
			authURL2, _ := startLogin(t, o)
			if authURL2.Query().Get("state") == q.Get("state") {
				t.Error("state parameter reused across logins")
			}
			if authURL2.Query().Get("code_challenge") == q.Get("code_challenge") {
				t.Error("PKCE challenge reused across logins")
			}
		})
	}
}

func TestOIDC_Verify(t *testing.T) {
	t.Parallel()

	// claimsOf is a token of tenant tid, issued by idp for that tenant unless mutate
	// says otherwise.
	claimsOf := func(tid string, mutate func(idp *oidctest.FakeIDP, c map[string]any)) func(idp *oidctest.FakeIDP) map[string]any {
		return func(idp *oidctest.FakeIDP) map[string]any {
			c := map[string]any{
				"preferred_username": "user@example.com",
				"roles":              []string{"Admin"},
				"tid":                tid,
				"oid":                "object-1",
			}
			if mutate != nil {
				mutate(idp, c)
			}

			return c
		}
	}
	goodClaims := claimsOf(tenantLake, nil)

	tests := []struct {
		name string
		// tenants is the registration's slot; the zero value stands for one tenant,
		// tenantLake.
		tenants     TenantSet
		tokenClaims func(idp *oidctest.FakeIDP) map[string]any
		tokenStatus int
		// mint, when set, serializes the token in place of the provider's signing.
		mint          func(claims map[string]any) string
		mutateReq     func(r *http.Request)
		dropCookie    bool
		wantErr       bool
		wantForbidden bool
		wantErrPart   string
		wantCode      sessioninfo.LoginRefusalCode
	}{
		{
			name:        "happy path: claims, return URL and the provider's session ID come back",
			tokenClaims: goodClaims,
		},
		{
			name:          "missing OIDC cookie is refused",
			tokenClaims:   goodClaims,
			dropCookie:    true,
			wantErr:       true,
			wantForbidden: true,
			wantErrPart:   "No OIDC cookie",
			wantCode:      sessioninfo.RefusedNoOIDCCookie,
		},
		{
			name:        "state mismatch is refused: the callback is not the login this browser started",
			tokenClaims: goodClaims,
			mutateReq: func(r *http.Request) {
				q := r.URL.Query()
				q.Set("state", "tampered-state")
				r.URL.RawQuery = q.Encode()
			},
			wantErr:       true,
			wantForbidden: true,
			wantErrPart:   "Invalid 'state' parameter value",
			wantCode:      sessioninfo.RefusedInvalidState,
		},
		{
			name:        "token exchange failure",
			tokenClaims: goodClaims,
			tokenStatus: http.StatusInternalServerError,
			wantErr:     true,
			wantErrPart: "Failed to exchange token",
			wantCode:    sessioninfo.RefusedTokenExchange,
		},
		{
			name:        "a token for another client fails verification",
			tokenClaims: claimsOf(tenantLake, func(_ *oidctest.FakeIDP, c map[string]any) { c["aud"] = "other-client" }),
			wantErr:     true,
			wantErrPart: "Failed to verify ID token",
			wantCode:    sessioninfo.RefusedIDTokenVerification,
		},
		{
			name:        "a token from another issuer fails verification",
			tokenClaims: claimsOf(tenantLake, func(_ *oidctest.FakeIDP, c map[string]any) { c["iss"] = "https://login.attacker.example" }),
			wantErr:     true,
			wantErrPart: "Failed to verify ID token",
			wantCode:    sessioninfo.RefusedIDTokenVerification,
		},
		{
			name:        "an expired token fails verification",
			tokenClaims: claimsOf(tenantLake, func(_ *oidctest.FakeIDP, c map[string]any) { c["exp"] = time.Now().Add(-time.Minute).Unix() }),
			wantErr:     true,
			wantErrPart: "Failed to verify ID token",
			wantCode:    sessioninfo.RefusedIDTokenVerification,
		},
		{
			name:        "a token signed with a key the provider never published fails verification",
			tokenClaims: goodClaims,
			mint:        func(c map[string]any) string { return oidctest.SignedBy(oidctest.NewKey(t), "rogue-key", c) },
			wantErr:     true,
			wantErrPart: "Failed to verify ID token",
			wantCode:    sessioninfo.RefusedIDTokenVerification,
		},
		{
			name:        "an unsigned token fails verification",
			tokenClaims: goodClaims,
			mint:        oidctest.Unsigned,
			wantErr:     true,
			wantErrPart: "Failed to verify ID token",
			wantCode:    sessioninfo.RefusedIDTokenVerification,
		},
		{
			name:        "a token under another algorithm than the provider's fails verification",
			tokenClaims: goodClaims,
			mint: func(c map[string]any) string {
				return oidctest.SignedHS256([]byte("a shared secret the provider never had"), c)
			},
			wantErr:     true,
			wantErrPart: "Failed to verify ID token",
			wantCode:    sessioninfo.RefusedIDTokenVerification,
		},
		{
			name:        "one tenant: a token of another tenant fails verification at the tenant's own endpoint, whose document names one issuer",
			tokenClaims: claimsOf(tenantRiver, nil),
			wantErr:     true,
			wantErrPart: "Failed to verify ID token",
			wantCode:    sessioninfo.RefusedIDTokenVerification,
		},
		{
			name:        "any tenant admits the work or school account of a tenant it never heard of",
			tenants:     AnyTenant(),
			tokenClaims: claimsOf(tenantOther, nil),
		},
		{
			name:          "any tenant refuses a personal account",
			tenants:       AnyTenant(),
			tokenClaims:   claimsOf(ConsumerTenantID, nil),
			wantErr:       true,
			wantForbidden: true,
			wantErrPart:   "Personal Microsoft accounts cannot sign in here",
			wantCode:      sessioninfo.RefusedPersonalAccount,
		},
		{
			name:        "personal accounts admit the consumer tenant",
			tenants:     PersonalAccounts(),
			tokenClaims: claimsOf(ConsumerTenantID, nil),
		},
		{
			name:          "personal accounts refuse a work or school account",
			tenants:       PersonalAccounts(),
			tokenClaims:   claimsOf(tenantLake, nil),
			wantErr:       true,
			wantForbidden: true,
			wantErrPart:   "cannot sign in here",
			wantCode:      sessioninfo.RefusedUnlistedTenant,
		},
		{
			name:        "listed tenants admit a listed one",
			tenants:     Tenants(Tenant(tenantLake), Tenant(tenantRiver)),
			tokenClaims: claimsOf(tenantRiver, nil),
		},
		{
			name:          "listed tenants refuse one outside the list",
			tenants:       Tenants(Tenant(tenantLake), Tenant(tenantRiver)),
			tokenClaims:   claimsOf(tenantOther, nil),
			wantErr:       true,
			wantForbidden: true,
			wantErrPart:   "cannot sign in here",
			wantCode:      sessioninfo.RefusedUnlistedTenant,
		},
		{
			name:    "under a shared endpoint a token whose issuer is another tenant's fails verification",
			tenants: AnyTenant(),
			tokenClaims: claimsOf(tenantRiver, func(idp *oidctest.FakeIDP, c map[string]any) {
				c["iss"] = idp.TenantIssuer(tenantOther)
			}),
			wantErr:     true,
			wantErrPart: "the ID token's issuer is not its tenant's",
			wantCode:    sessioninfo.RefusedIDTokenVerification,
		},
		{
			name:    "under a shared endpoint a token from another authority fails verification, since the shared document holds no token to an issuer",
			tenants: AnyTenant(),
			tokenClaims: claimsOf(tenantRiver, func(_ *oidctest.FakeIDP, c map[string]any) {
				c["iss"] = "https://login.attacker.example/" + tenantRiver + "/v2.0"
			}),
			wantErr:     true,
			wantErrPart: "the ID token's issuer is not its tenant's",
			wantCode:    sessioninfo.RefusedIDTokenVerification,
		},
		{
			name:        "under a shared endpoint a token naming no tenant fails verification",
			tenants:     AnyTenant(),
			tokenClaims: claimsOf("", func(_ *oidctest.FakeIDP, c map[string]any) { delete(c, "tid") }),
			wantErr:     true,
			wantErrPart: "the ID token names no tenant",
			wantCode:    sessioninfo.RefusedIDTokenVerification,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			ctx := t.Context()

			tenants := tt.tenants
			if len(tenants.listed) == 0 && !tenants.open() {
				tenants = Tenant(tenantLake)
			}
			idp := oidctest.NewFakeEntra(t, testClientID)
			idp.TokenClaims = func() map[string]any { return tt.tokenClaims(idp) }
			idp.TokenStatus = tt.tokenStatus
			idp.Mint = tt.mint

			o := newVerifier(t, idp, tenants, "azure")

			_, callback := startLogin(t, o)
			if tt.dropCookie {
				callback.Header.Del("Cookie")
			}
			if tt.mutateReq != nil {
				tt.mutateReq(callback)
			}

			var claims json.RawMessage
			rec := httptest.NewRecorder()
			returnURL, sid, err := o.Verify(ctx, rec, callback.WithContext(ctx), &claims)
			if (err != nil) != tt.wantErr {
				t.Fatalf("OIDC.Verify() error = %v, wantErr %v", err, tt.wantErr)
			}
			if tt.wantErr {
				assertRefusal(t, err, tt.wantErrPart, tt.wantCode, tt.wantForbidden)

				return
			}
			wantTid, _ := tt.tokenClaims(idp)["tid"].(string)
			assertVerified(t, rec, returnURL, sid, claims, wantTid)
		})
	}
}

// assertRefusal fails unless err is the refusal wanted: its text, its code and whether
// it is forbidden.
func assertRefusal(t *testing.T, err error, wantErrPart string, wantCode sessioninfo.LoginRefusalCode, wantForbidden bool) {
	t.Helper()

	if wantErrPart != "" && !strings.Contains(err.Error(), wantErrPart) {
		t.Errorf("OIDC.Verify() error = %q, want it to contain %q", err.Error(), wantErrPart)
	}
	if got := sessioninfo.LoginRefusalCodeOf(err); got != wantCode {
		t.Errorf("OIDC.Verify() refusal code = %q, want %q: %v", got, wantCode, err)
	}
	if httpio.HasForbidden(err) != wantForbidden {
		t.Errorf("OIDC.Verify() forbidden = %v, want %v: %v", httpio.HasForbidden(err), wantForbidden, err)
	}
}

// assertVerified fails unless the completed round trip returned the return URL, the
// provider's session id and the claims of tenant wantTid, and cleared the state cookie.
func assertVerified(t *testing.T, rec *httptest.ResponseRecorder, returnURL, sid string, claims json.RawMessage, wantTid string) {
	t.Helper()

	if returnURL != "/app" {
		t.Errorf("OIDC.Verify() returnURL = %q, want %q", returnURL, "/app")
	}
	if sid != "idp-session-1" {
		t.Errorf("OIDC.Verify() sid = %q, want the session_state parameter", sid)
	}
	var decoded struct {
		PreferredUsername string   `json:"preferred_username"`
		Roles             []string `json:"roles"`
		Tid               string   `json:"tid"`
		Oid               string   `json:"oid"`
	}
	if err := json.Unmarshal(claims, &decoded); err != nil {
		t.Fatalf("json.Unmarshal(claims) error = %v", err)
	}
	if decoded.PreferredUsername != "user@example.com" || decoded.Tid != wantTid || decoded.Oid != "object-1" || len(decoded.Roles) != 1 {
		t.Errorf("verified claims = %+v", decoded)
	}
	// The single-use state cookie is cleared on the response: emptied and expired.
	cleared := false
	for _, c := range rec.Result().Cookies() {
		if c.Name == internalcookie.StateCookieName(internalcookie.AuthCookieName, "azure") && c.Value == "" && !c.Expires.IsZero() && c.Expires.Before(time.Now()) {
			cleared = true
		}
	}
	if !cleared {
		t.Error("the OIDC cookie was not deleted by the callback")
	}
}

// TestOIDC_Verify_KeyRotation proves the key set is read once and cached, a token under
// a key the provider rotated to is accepted after one refresh, and a token under a key
// the provider never published is refused after one refresh.
func TestOIDC_Verify_KeyRotation(t *testing.T) {
	t.Parallel()
	ctx := t.Context()

	idp := oidctest.NewFakeEntra(t, testClientID)
	idp.TokenClaims = func() map[string]any {
		return map[string]any{"preferred_username": "user@example.com", "tid": tenantLake, "oid": "object-1"}
	}
	o := newVerifier(t, idp, Tenant(tenantLake), "azure")
	verify := func() error {
		_, callback := startLogin(t, o)
		var claims json.RawMessage
		_, _, err := o.Verify(ctx, httptest.NewRecorder(), callback.WithContext(ctx), &claims)

		return err
	}
	fetches := func(want int, when string) {
		t.Helper()
		if got := idp.KeyFetches(); got != want {
			t.Errorf("key set fetches %s = %d, want %d", when, got, want)
		}
	}

	if err := verify(); err != nil {
		t.Fatalf("Verify() error = %v, want the first token accepted", err)
	}
	fetches(1, "after the first token")
	if err := verify(); err != nil {
		t.Fatalf("Verify() error = %v, want the second token accepted", err)
	}
	fetches(1, "after a second token under the same key: the set is cached")

	idp.Rotate(t)
	if err := verify(); err != nil {
		t.Fatalf("Verify() under the rotated key error = %v, want it accepted after one refresh of the key set", err)
	}
	fetches(2, "after the rotation: one refresh")
	if err := verify(); err != nil {
		t.Fatalf("Verify() error = %v, want the next token under the rotated key accepted", err)
	}
	fetches(2, "after another token under the rotated key: the refreshed set is cached")

	rogue := oidctest.NewKey(t)
	idp.Mint = func(claims map[string]any) string { return oidctest.SignedBy(rogue, "rogue-key", claims) }
	if err := verify(); sessioninfo.LoginRefusalCodeOf(err) != sessioninfo.RefusedIDTokenVerification {
		t.Fatalf("Verify() under a key the provider never published error = %v, want %s", err, sessioninfo.RefusedIDTokenVerification)
	}
	fetches(3, "after a token under an unknown key id: one refresh, then refused")
}
