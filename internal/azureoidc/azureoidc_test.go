//go:build !skipAuth

package azureoidc

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
)

const testClientID = "test-client-id"

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

	idp := oidctest.NewFakeIDP(t, testClientID)
	o := New(oidctest.NewCookieClient(t), idp.Server.URL, testClientID, "test-secret", "https://app.example.com/callback")

	authURL, _ := startLogin(t, o)

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
}

func TestOIDC_Verify(t *testing.T) {
	t.Parallel()

	goodClaims := func() map[string]any {
		return map[string]any{
			"preferred_username": "user@example.com",
			"roles":              []string{"Admin"},
			"tid":                "tenant-1",
			"oid":                "object-1",
		}
	}

	tests := []struct {
		name          string
		tokenClaims   func() map[string]any
		tokenStatus   int
		mutateReq     func(r *http.Request)
		dropCookie    bool
		wantErr       bool
		wantForbidden bool
		wantErrPart   string
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
		},
		{
			name:        "token exchange failure",
			tokenClaims: goodClaims,
			tokenStatus: http.StatusInternalServerError,
			wantErr:     true,
			wantErrPart: "Failed to exchange token",
		},
		{
			name: "a token for another client fails verification",
			tokenClaims: func() map[string]any {
				c := goodClaims()
				c["aud"] = "other-client"

				return c
			},
			wantErr:     true,
			wantErrPart: "Failed to verify ID token",
		},
		{
			name: "a token from another issuer fails verification",
			tokenClaims: func() map[string]any {
				c := goodClaims()
				c["iss"] = "https://login.attacker.example"

				return c
			},
			wantErr:     true,
			wantErrPart: "Failed to verify ID token",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			ctx := t.Context()

			idp := oidctest.NewFakeIDP(t, testClientID)
			idp.TokenClaims = tt.tokenClaims
			idp.TokenStatus = tt.tokenStatus

			o := New(oidctest.NewCookieClient(t), idp.Server.URL, testClientID, "test-secret", "https://app.example.com/callback")

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
				if tt.wantErrPart != "" && !strings.Contains(err.Error(), tt.wantErrPart) {
					t.Errorf("OIDC.Verify() error = %q, want it to contain %q", err.Error(), tt.wantErrPart)
				}
				if httpio.HasForbidden(err) != tt.wantForbidden {
					t.Errorf("OIDC.Verify() forbidden = %v, want %v: %v", httpio.HasForbidden(err), tt.wantForbidden, err)
				}

				return
			}

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
			if decoded.PreferredUsername != "user@example.com" || decoded.Tid != "tenant-1" || decoded.Oid != "object-1" || len(decoded.Roles) != 1 {
				t.Errorf("verified claims = %+v", decoded)
			}
			// The single-use OIDC cookie is cleared on the response: emptied and expired.
			cleared := false
			for _, c := range rec.Result().Cookies() {
				if c.Name == internalcookie.OIDCCookieName && c.Value == "" && !c.Expires.IsZero() && c.Expires.Before(time.Now()) {
					cleared = true
				}
			}
			if !cleared {
				t.Error("the OIDC cookie was not deleted by the callback")
			}
		})
	}
}
