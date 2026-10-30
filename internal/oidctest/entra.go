// The Entra-shaped fake: tenant-scoped discovery, the shared endpoints with their
// templated issuer, and one key set for every tenant, as the Microsoft identity
// platform serves them.

package oidctest

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// entraTemplatedIssuer is the issuer the shared endpoints' documents name: a
// placeholder for the tenant, as Microsoft's organizations, common and consumers
// documents literally carry.
const entraTemplatedIssuer = "{tenantid}"

// NewFakeEntra starts a provider shaped like the Microsoft identity platform: every
// tenant segment serves its own discovery document at /<tenant>/v2.0 naming the issuer
// <server>/<tenant>/v2.0, the shared segments organizations, common and consumers name
// the issuer with the {tenantid} placeholder, the token endpoint of every segment signs
// with one key, and a token's issuer defaults to <server>/<tid>/v2.0 for the tid claim
// the test gives it. Tokens are issued for clientID. It is closed with the test.
func NewFakeEntra(t *testing.T, clientID string) *FakeIDP {
	t.Helper()

	f := &FakeIDP{keys: []signingKey{{kid: "test-key", key: NewKey(t)}}, clientID: clientID}

	mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		segment, rest, _ := strings.Cut(strings.TrimPrefix(r.URL.Path, "/"), "/")
		base := f.Server.URL + "/" + segment
		switch rest {
		case "v2.0/.well-known/openid-configuration":
			issuer := base + "/v2.0"
			if segment == "organizations" || segment == "common" || segment == "consumers" {
				issuer = f.Server.URL + "/" + entraTemplatedIssuer + "/v2.0"
			}
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(map[string]any{
				"issuer":                 issuer,
				"authorization_endpoint": base + "/oauth2/v2.0/authorize",
				"token_endpoint":         base + "/oauth2/v2.0/token",
				"jwks_uri":               base + "/discovery/v2.0/keys",
			})
		case "discovery/v2.0/keys":
			f.serveKeys(w)
		case "oauth2/v2.0/token":
			f.serveToken(w, r, func(claims map[string]any) string {
				if tid, ok := claims["tid"].(string); ok && tid != "" {
					return f.TenantIssuer(tid)
				}

				return base + "/v2.0"
			})
		default:
			http.NotFound(w, r)
		}
	})

	f.Server = httptest.NewServer(mux)
	t.Cleanup(f.Server.Close)

	return f
}

// TenantIssuer is the issuer of tenant tid's tokens at this provider.
func (f *FakeIDP) TenantIssuer(tid string) string {
	return f.Server.URL + "/" + strings.ToLower(tid) + "/v2.0"
}
