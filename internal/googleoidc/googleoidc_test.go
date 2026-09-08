//go:build !skipAuth

package googleoidc

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/cccteam/session/internal/oidctest"
)

const (
	testClientID     = "test-client-id"
	testHostedDomain = "example.com"
)

func newFakeIDP(t *testing.T) *oidctest.FakeIDP {
	t.Helper()

	return oidctest.NewFakeIDP(t, testClientID)
}

// startLogin runs AuthCodeURL and returns the parsed redirect URL plus a callback
// request pre-loaded with the OIDC cookie and the redirect's state value.
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

	callback = httptest.NewRequestWithContext(ctx, http.MethodGet, fmt.Sprintf("/callback?code=test-code&state=%s", url.QueryEscape(authURL.Query().Get("state"))), http.NoBody)
	for _, c := range rec.Result().Cookies() {
		callback.AddCookie(c)
	}

	return authURL, callback
}

func TestOIDC_AuthCodeURL(t *testing.T) {
	t.Parallel()

	idp := newFakeIDP(t)
	o := newWithIssuer(oidctest.NewCookieClient(t), idp.Server.URL, testClientID, "test-secret", "https://app.example.com/callback", testHostedDomain)

	authURL, _ := startLogin(t, o)

	q := authURL.Query()
	if got := q.Get("hd"); got != testHostedDomain {
		t.Errorf("hd parameter = %q, want %q", got, testHostedDomain)
	}
	if q.Get("state") == "" {
		t.Error("state parameter is empty")
	}
	if q.Get("code_challenge") == "" || q.Get("code_challenge_method") != "S256" {
		t.Errorf("PKCE challenge missing or not S256: method = %q", q.Get("code_challenge_method"))
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
			"sub":            "google-sub-1",
			"email":          "user@example.com",
			"email_verified": true,
			"hd":             testHostedDomain,
		}
	}

	tests := []struct {
		name        string
		tokenClaims func() map[string]any
		tokenStatus int
		mutateReq   func(r *http.Request)
		dropCookie  bool
		wantErr     bool
		wantErrPart string
	}{
		{
			name:        "happy path",
			tokenClaims: goodClaims,
		},
		{
			name:        "missing OIDC cookie",
			tokenClaims: goodClaims,
			dropCookie:  true,
			wantErr:     true,
			wantErrPart: "No OIDC cookie",
		},
		{
			name:        "state mismatch",
			tokenClaims: goodClaims,
			mutateReq: func(r *http.Request) {
				q := r.URL.Query()
				q.Set("state", "tampered-state")
				r.URL.RawQuery = q.Encode()
			},
			wantErr:     true,
			wantErrPart: "Invalid 'state' parameter value",
		},
		{
			name:        "token exchange failure",
			tokenClaims: goodClaims,
			tokenStatus: http.StatusInternalServerError,
			wantErr:     true,
			wantErrPart: "Failed to exchange token",
		},
		{
			name: "wrong audience fails verification",
			tokenClaims: func() map[string]any {
				c := goodClaims()
				c["aud"] = "other-client"

				return c
			},
			wantErr:     true,
			wantErrPart: "Failed to verify ID token",
		},
		{
			name: "hd claim absent (consumer account) fails closed",
			tokenClaims: func() map[string]any {
				c := goodClaims()
				delete(c, "hd")

				return c
			},
			wantErr:     true,
			wantErrPart: "not a member of the required Google Workspace domain",
		},
		{
			name: "hd claim for another domain is rejected",
			tokenClaims: func() map[string]any {
				c := goodClaims()
				c["hd"] = "attacker.example.net"

				return c
			},
			wantErr:     true,
			wantErrPart: "not a member of the required Google Workspace domain",
		},
		{
			name: "hd claim comparison is case-insensitive",
			tokenClaims: func() map[string]any {
				c := goodClaims()
				c["hd"] = "Example.COM"

				return c
			},
		},
		{
			name: "unverified email is rejected",
			tokenClaims: func() map[string]any {
				c := goodClaims()
				c["email_verified"] = false

				return c
			},
			wantErr:     true,
			wantErrPart: "email is not verified",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			ctx := t.Context()

			idp := newFakeIDP(t)
			idp.TokenClaims = tt.tokenClaims
			idp.TokenStatus = tt.tokenStatus

			o := newWithIssuer(oidctest.NewCookieClient(t), idp.Server.URL, testClientID, "test-secret", "https://app.example.com/callback", testHostedDomain)

			_, callback := startLogin(t, o)
			if tt.dropCookie {
				callback.Header.Del("Cookie")
			}
			if tt.mutateReq != nil {
				tt.mutateReq(callback)
			}

			var claims json.RawMessage
			returnURL, err := o.Verify(ctx, httptest.NewRecorder(), callback.WithContext(ctx), &claims)
			if (err != nil) != tt.wantErr {
				t.Fatalf("OIDC.Verify() error = %v, wantErr %v", err, tt.wantErr)
			}
			if tt.wantErr {
				if tt.wantErrPart != "" && !strings.Contains(err.Error(), tt.wantErrPart) {
					t.Errorf("OIDC.Verify() error = %q, want it to contain %q", err.Error(), tt.wantErrPart)
				}

				return
			}

			if returnURL != "/app" {
				t.Errorf("OIDC.Verify() returnURL = %q, want %q", returnURL, "/app")
			}
			var decoded struct {
				Sub   string `json:"sub"`
				Email string `json:"email"`
			}
			if err := json.Unmarshal(claims, &decoded); err != nil {
				t.Fatalf("json.Unmarshal(claims) error = %v", err)
			}
			if decoded.Sub != "google-sub-1" || decoded.Email != "user@example.com" {
				t.Errorf("verified claims = %+v", decoded)
			}
		})
	}
}
