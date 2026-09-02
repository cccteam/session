//go:build skipAuth

package azureoidc

import (
	"crypto/rand"
	"encoding/base64"
	"net/http"
	"net/http/httptest"
	"testing"

	internalcookie "github.com/cccteam/session/internal/cookie"
	"github.com/gofrs/uuid"
	"github.com/google/go-cmp/cmp"
)

func newTestCookieClient(t *testing.T) *internalcookie.Client {
	t.Helper()

	key := make([]byte, 64)
	if _, err := rand.Read(key); err != nil {
		t.Fatalf("rand.Read() error = %v", err)
	}
	client, err := internalcookie.NewCookieClient(base64.StdEncoding.EncodeToString(key))
	if err != nil {
		t.Fatalf("internalcookie.NewCookieClient() error = %v", err)
	}

	return client
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

			o := New(newTestCookieClient(t), "", "", "", "/auth/callback")

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
