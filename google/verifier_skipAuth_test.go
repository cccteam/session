//go:build skipAuth

package google

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/cccteam/session/internal/oidctest"
	"github.com/google/go-cmp/cmp"
)

// The simulated login is what every developer runs against; the claims it fabricates
// must be the ones the login handler and role sync expect from a real Google token.
func TestOIDC_Verify_simulatedClaims(t *testing.T) {
	type claims struct {
		Email         string `json:"email"`
		EmailVerified bool   `json:"email_verified"`
		Hd            string `json:"hd"`
		Sub           string `json:"sub"`
	}

	tests := []struct {
		name         string
		username     string
		hostedDomain string
		returnURL    string
		wantClaims   claims
		wantReturn   string
	}{
		{
			name:         "the username is the verified email, the hosted domain is the configured one, and the sub is stable",
			username:     "dev@example.com",
			hostedDomain: "example.com",
			returnURL:    "/app",
			wantClaims:   claims{Email: "dev@example.com", EmailVerified: true, Hd: "example.com", Sub: "skipauth-dev@example.com"},
			wantReturn:   "/app",
		},
		{
			name:         "a different username derives a different sub",
			username:     "other@example.com",
			hostedDomain: "example.com",
			returnURL:    "/settings",
			wantClaims:   claims{Email: "other@example.com", EmailVerified: true, Hd: "example.com", Sub: "skipauth-other@example.com"},
			wantReturn:   "/settings",
		},
		{
			name:         "the return URL is sanitized so the simulator cannot redirect off-site",
			username:     "dev@example.com",
			hostedDomain: "example.com",
			returnURL:    "//evil.example/phish",
			wantClaims:   claims{Email: "dev@example.com", EmailVerified: true, Hd: "example.com", Sub: "skipauth-dev@example.com"},
			wantReturn:   "/",
		},
		{
			name:         "a return URL that a redirect would clean into a scheme-relative one is sanitized",
			username:     "dev@example.com",
			hostedDomain: "example.com",
			returnURL:    `/./\evil.example/phish`,
			wantClaims:   claims{Email: "dev@example.com", EmailVerified: true, Hd: "example.com", Sub: "skipauth-dev@example.com"},
			wantReturn:   "/",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Setenv("APP_USERNAME", tt.username)

			o := NewOIDC(oidctest.NewCookieClient(t).ForRegistration("google"), "", "", "/auth/callback", Workspace("test", tt.hostedDomain))

			ctx := t.Context()
			rec := httptest.NewRecorder()
			redirect, err := o.AuthCodeURL(ctx, rec, tt.returnURL, "")
			if err != nil {
				t.Fatalf("OIDC.AuthCodeURL() error = %v", err)
			}
			if redirect != "/auth/callback" {
				t.Errorf("OIDC.AuthCodeURL() = %q, want the callback itself", redirect)
			}
			callback := httptest.NewRequestWithContext(ctx, http.MethodGet, "/auth/callback", http.NoBody)
			for _, c := range rec.Result().Cookies() {
				callback.AddCookie(c)
			}

			got := claims{}
			returnURL, _, err := o.Verify(ctx, httptest.NewRecorder(), callback, &got)
			if err != nil {
				t.Fatalf("OIDC.Verify() error = %v", err)
			}
			if returnURL != tt.wantReturn {
				t.Errorf("OIDC.Verify() returnURL = %q, want %q", returnURL, tt.wantReturn)
			}
			if diff := cmp.Diff(tt.wantClaims, got); diff != "" {
				t.Errorf("OIDC.Verify() claims mismatch (-want +got):\n%s", diff)
			}
		})
	}
}

func TestOIDC_Verify_requiresTheOIDCCookie(t *testing.T) {
	t.Setenv("APP_USERNAME", "dev@example.com")

	o := NewOIDC(oidctest.NewCookieClient(t).ForRegistration("google"), "", "", "/auth/callback", Workspace("test", "example.com"))
	callback := httptest.NewRequestWithContext(t.Context(), http.MethodGet, "/auth/callback", http.NoBody)

	var got map[string]any
	if _, _, err := o.Verify(t.Context(), httptest.NewRecorder(), callback, &got); err == nil {
		t.Error("OIDC.Verify() without the OIDC cookie error = nil, want error")
	}
}

// TestOIDC_Verify_simulatedHostedDomain proves the hd claim the simulated sign-in
// asserts per shape of the slot: a named Workspace's first domain, a reserved name under
// any Workspace, and none under any Google account.
func TestOIDC_Verify_simulatedHostedDomain(t *testing.T) {
	tests := []struct {
		name       string
		workspaces WorkspaceSet
		wantHd     string
	}{
		{name: "one Workspace asserts its first domain", workspaces: Workspace("test", "example.com", "example.org"), wantHd: "example.com"},
		{name: "listed Workspaces assert the first one's first domain", workspaces: Workspaces(Workspace("a", "a.example"), Workspace("b", "b.example")), wantHd: "a.example"},
		{name: "any Workspace asserts a reserved name", workspaces: AnyWorkspace(), wantHd: "skipauth.invalid"},
		{name: "any Google account asserts no domain", workspaces: AnyGoogleAccount(), wantHd: ""},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Setenv("APP_USERNAME", "dev@example.com")
			o := NewOIDC(oidctest.NewCookieClient(t).ForRegistration("google"), "", "", "/auth/callback", tt.workspaces)
			ctx := t.Context()
			rec := httptest.NewRecorder()
			if _, err := o.AuthCodeURL(ctx, rec, "/", ""); err != nil {
				t.Fatalf("OIDC.AuthCodeURL() error = %v", err)
			}
			callback := httptest.NewRequestWithContext(ctx, http.MethodGet, "/auth/callback", http.NoBody)
			for _, c := range rec.Result().Cookies() {
				callback.AddCookie(c)
			}

			got := claims{}
			if _, _, err := o.Verify(ctx, httptest.NewRecorder(), callback, &got); err != nil {
				t.Fatalf("OIDC.Verify() error = %v", err)
			}

			if got.Hd != tt.wantHd {
				t.Errorf("simulated hd = %q, want %q", got.Hd, tt.wantHd)
			}
		})
	}
}
