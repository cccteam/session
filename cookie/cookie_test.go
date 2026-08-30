package cookie

import (
	"encoding/base64"
	"net/http/httptest"
	"testing"
	"time"
)

func TestClient_Delete(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name       string
		cookieName string
		domain     string
	}{
		{
			name:       "host-only cookie",
			cookieName: "OIDC",
			domain:     "",
		},
		{
			name:       "domain cookie",
			cookieName: "OIDC",
			domain:     "example.com",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			client, err := New(base64.StdEncoding.EncodeToString(make([]byte, 32)))
			if err != nil {
				t.Fatalf("New() error = %v", err)
			}

			w := httptest.NewRecorder()
			client.Delete(w, tt.cookieName, tt.domain)

			res := w.Result()
			defer res.Body.Close()

			cookies := res.Cookies()
			if len(cookies) != 1 {
				t.Fatalf("Delete() wrote %d cookies, want 1", len(cookies))
			}
			c := cookies[0]
			if c.Name != tt.cookieName {
				t.Errorf("Delete() cookie name = %q, want %q", c.Name, tt.cookieName)
			}
			if c.Domain != tt.domain {
				t.Errorf("Delete() cookie domain = %q, want %q", c.Domain, tt.domain)
			}
			if c.Path != "/" {
				t.Errorf("Delete() cookie path = %q, want %q", c.Path, "/")
			}
			if c.Value != "" {
				t.Errorf("Delete() cookie value = %q, want empty", c.Value)
			}
			if !c.Expires.Before(time.Now()) {
				t.Errorf("Delete() cookie expires = %v, want in the past", c.Expires)
			}
		})
	}
}
