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

			o := NewOIDC(oidctest.NewCookieClient(t), "", "", "/auth/callback", tt.hostedDomain)

			ctx := t.Context()
			rec := httptest.NewRecorder()
			redirect, err := o.AuthCodeURL(ctx, rec, tt.returnURL)
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

// Two registrations in one process sign in two people: a registration reads its own
// username variable first, and hands the simulated groups lookup its name in place of
// an access token.
func TestOIDC_Verify_simulatedRegistration(t *testing.T) {
	tests := []struct {
		name         string
		registration string
		wantEmail    string
	}{
		{name: "a registration with a username variable of its own signs that person in", registration: "google", wantEmail: "navigator"},
		{name: "a registration without one signs APP_USERNAME in", registration: "directory", wantEmail: "client"},
		{name: "no registration signs APP_USERNAME in", registration: "", wantEmail: "client"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Setenv("APP_USERNAME", "client")
			t.Setenv("APP_GOOGLE_USERNAME", "navigator")

			o := NewOIDC(oidctest.NewCookieClient(t), "", "", "/auth/callback", "example.com")
			o.simulateAs(tt.registration)

			ctx := t.Context()
			rec := httptest.NewRecorder()
			if _, err := o.AuthCodeURL(ctx, rec, "/app"); err != nil {
				t.Fatalf("OIDC.AuthCodeURL() error = %v", err)
			}
			callback := httptest.NewRequestWithContext(ctx, http.MethodGet, "/auth/callback", http.NoBody)
			for _, c := range rec.Result().Cookies() {
				callback.AddCookie(c)
			}

			got := struct {
				Email string `json:"email"`
				Sub   string `json:"sub"`
			}{}
			_, token, err := o.Verify(ctx, httptest.NewRecorder(), callback, &got)
			if err != nil {
				t.Fatalf("OIDC.Verify() error = %v", err)
			}
			if got.Email != tt.wantEmail || got.Sub != "skipauth-"+tt.wantEmail {
				t.Errorf("OIDC.Verify() claims = %+v, want %s signed in", got, tt.wantEmail)
			}
			if token != tt.registration {
				t.Errorf("OIDC.Verify() token = %q, want the registration %q for the simulated groups lookup", token, tt.registration)
			}
		})
	}
}

func TestOIDC_Verify_requiresTheOIDCCookie(t *testing.T) {
	t.Setenv("APP_USERNAME", "dev@example.com")

	o := NewOIDC(oidctest.NewCookieClient(t), "", "", "/auth/callback", "example.com")
	callback := httptest.NewRequestWithContext(t.Context(), http.MethodGet, "/auth/callback", http.NoBody)

	var got map[string]any
	if _, _, err := o.Verify(t.Context(), httptest.NewRecorder(), callback, &got); err == nil {
		t.Error("OIDC.Verify() without the OIDC cookie error = nil, want error")
	}
}
