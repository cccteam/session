//go:build skipAuth

package azure

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/cccteam/session/internal/oidctest"
	"github.com/gofrs/uuid"
	"github.com/google/go-cmp/cmp"
)

// Two registrations in one process sign in two people: a registration reads its own
// username and roles variables first.
func TestOIDC_Verify_simulatedRegistration(t *testing.T) {
	tests := []struct {
		name         string
		registration string
		wantUsername string
		wantRoles    []string
	}{
		{name: "a registration with variables of its own signs that person in with those roles", registration: "lakeside-entra", wantUsername: "pat@lakeside.edu", wantRoles: []string{"Admin", "Reader"}},
		{name: "a registration without them signs APP_USERNAME in with APP_ROLES", registration: "riverside", wantUsername: "client", wantRoles: []string{"Viewer"}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Setenv("APP_USERNAME", "client")
			t.Setenv("APP_ROLES", "Viewer")
			t.Setenv("APP_LAKESIDE_ENTRA_USERNAME", "pat@lakeside.edu")
			t.Setenv("APP_LAKESIDE_ENTRA_ROLES", "Admin, Reader")

			o := NewOIDC(oidctest.NewCookieClient(t), "", "", "", "/auth/callback")
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
				PreferredUsername string   `json:"preferred_username"`
				Roles             []string `json:"roles"`
			}{}
			if _, _, err := o.Verify(ctx, httptest.NewRecorder(), callback, &got); err != nil {
				t.Fatalf("OIDC.Verify() error = %v", err)
			}
			if got.PreferredUsername != tt.wantUsername {
				t.Errorf("preferred_username = %q, want %q", got.PreferredUsername, tt.wantUsername)
			}
			if diff := cmp.Diff(tt.wantRoles, got.Roles); diff != "" {
				t.Errorf("roles mismatch (-want +got):\n%s", diff)
			}
		})
	}
}

func TestOIDC_Verify_simulatedClaims(t *testing.T) {
	type claims struct {
		PreferredUsername string   `json:"preferred_username"`
		Roles             []string `json:"roles"`
		Tid               string   `json:"tid"`
		Oid               string   `json:"oid"`
	}

	// The tid and oid wants are hardcoded on purpose: the derivation is a contract.
	// A change to skipAuthTenantID, skipAuthOidNamespace, or the derivation scheme
	// re-keys every simulated user and orphans anchor rows in existing dev databases.
	tests := []struct {
		name       string
		username   string
		roles      string
		wantClaims claims
	}{
		{
			name:     "derives a stable oid from the username",
			username: "dev@example.com",
			roles:    "Admin,Viewer",
			wantClaims: claims{
				PreferredUsername: "dev@example.com",
				Roles:             []string{"Admin", "Viewer"},
				Tid:               "034cdd64-5dd9-4a3b-90fb-c76d3a499433",
				Oid:               "d6d5798a-0f75-5676-b69f-9547dda53c7b",
			},
		},
		{
			name:     "a different username derives a different oid in the same tenant",
			username: "other@example.com",
			roles:    "Viewer",
			wantClaims: claims{
				PreferredUsername: "other@example.com",
				Roles:             []string{"Viewer"},
				Tid:               "034cdd64-5dd9-4a3b-90fb-c76d3a499433",
				Oid:               "cd1dc23a-42bf-55fb-98c0-da140a490a55",
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Setenv("APP_USERNAME", tt.username)
			t.Setenv("APP_ROLES", tt.roles)

			o := NewOIDC(oidctest.NewCookieClient(t), "", "", "", "/auth/callback")

			ctx := t.Context()
			rec := httptest.NewRecorder()
			if _, err := o.AuthCodeURL(ctx, rec, "/app"); err != nil {
				t.Fatalf("OIDC.AuthCodeURL() error = %v", err)
			}
			callback := httptest.NewRequestWithContext(ctx, http.MethodGet, "/auth/callback", http.NoBody)
			for _, c := range rec.Result().Cookies() {
				callback.AddCookie(c)
			}

			got := claims{}
			returnURL, sid, err := o.Verify(ctx, httptest.NewRecorder(), callback, &got)
			if err != nil {
				t.Fatalf("OIDC.Verify() error = %v", err)
			}
			if returnURL != "/app" {
				t.Errorf("OIDC.Verify() returnURL = %q, want %q", returnURL, "/app")
			}
			if _, err := uuid.FromString(sid); err != nil {
				t.Errorf("OIDC.Verify() sid = %q, want a UUID: %v", sid, err)
			}
			if diff := cmp.Diff(tt.wantClaims, got); diff != "" {
				t.Errorf("OIDC.Verify() claims mismatch (-want +got):\n%s", diff)
			}
		})
	}
}
