//go:build !skipAuth

// The skipAuth build tag swaps the OIDC verifiers for simulators that never reach an
// identity provider, so these round trips run against the production verifiers only.

package e2e

import (
	"context"
	"net/http"
	"net/http/httptest"
	"net/url"
	"sync"
	"testing"

	"github.com/cccteam/ccc"
	"github.com/cccteam/session"
	"github.com/cccteam/session/internal/googleoidc"
	"github.com/cccteam/session/internal/oidctest"
	"github.com/cccteam/session/sessioninfo"
	"github.com/cccteam/session/sessionstorage"
	"github.com/go-chi/chi/v5"
)

// googleIssuerMu serializes the scenarios' constructions of a Google sign-in, which read
// the package-level issuer the fake identity provider stands in for.
var googleIssuerMu sync.Mutex

const (
	azureTenant  = "11111111-1111-1111-1111-111111111111"
	hostedDomain = "lakeside.edu"
)

// oidcApp is an application with Azure and Google sign-in on one Auth, each against its
// own fake identity provider.
type oidcApp struct {
	*authApp
	azure, google *oidctest.FakeIDP
}

func newOIDCApp(ctx context.Context, t *testing.T) *oidcApp {
	t.Helper()

	h := &hooks{}
	db, store := newAuthStore(ctx, t, h)
	azure := oidctest.NewFakeIDP(t, "azure-client")
	google := oidctest.NewFakeIDP(t, "google-client")

	googleIssuerMu.Lock()
	issuer := googleoidc.IssuerURL
	googleoidc.IssuerURL = google.Server.URL
	auth, err := session.NewAuth[session.NoCustomData, session.NoCustomData](store, cookieKey, []session.SignInMethod{
		session.AzureSignIn(session.DisableRoleSync(), azure.Server.URL, "azure-client", "secret", "https://app.example/azure/callback"),
		session.GoogleSignIn(session.DisableRoleSync(), "google-client", "secret", "https://app.example/google/callback", hostedDomain),
	}, session.WithIdentityLinked(h.identityLinked))
	googleoidc.IssuerURL = issuer
	googleIssuerMu.Unlock()
	if err != nil {
		t.Fatalf("session.NewAuth() error = %v", err)
	}

	r := chi.NewRouter()
	mountAuth(r, auth, func(r chi.Router) {
		r.Get("/azure/login", auth.Azure().Login())
		r.Get("/azure/callback", auth.Azure().Callback())
		r.Get("/google/login", auth.Google().Login())
		r.Get("/google/callback", auth.Google().Callback())
	})
	server := httptest.NewTLSServer(r)
	t.Cleanup(server.Close)

	return &oidcApp{authApp: &authApp{db: db, server: server, api: auth.API(), hooks: h}, azure: azure, google: google}
}

// oidcSignIn runs a login round trip through provider at prefix (/azure or /google)
// with the ID token claims given, and returns where the callback sent the browser.
func (b *browser) oidcSignIn(ctx context.Context, provider *oidctest.FakeIDP, prefix string, claims map[string]any) *url.URL {
	b.t.Helper()

	authorize := b.location(ctx, prefix+"/login?returnUrl="+url.QueryEscape("/home"))
	state := authorize.Query().Get("state")
	if authorize.Host != mustHost(b.t, provider.Server.URL) || state == "" || authorize.Query().Get("code_challenge") == "" {
		b.t.Fatalf("authorization URL = %s, want the provider's with a state and a PKCE challenge", authorize)
	}
	provider.TokenClaims = func() map[string]any { return claims }

	return b.location(ctx, prefix+"/callback?code=c&state="+url.QueryEscape(state))
}

func mustHost(t *testing.T, raw string) string {
	t.Helper()

	u, err := url.Parse(raw)
	if err != nil {
		t.Fatalf("url.Parse() error = %v", err)
	}

	return u.Host
}

func azureClaims(tid, oid, username string) map[string]any {
	return map[string]any{"sub": "pairwise-" + oid, "tid": tid, "oid": oid, "preferred_username": username, "email": username, "amr": []string{"pwd", "mfa"}}
}

func googleClaims(sub, email string) map[string]any {
	return map[string]any{"sub": sub, "email": email, "email_verified": true, "hd": hostedDomain}
}

func TestAuthSeams_AzureAndGoogle(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		run  func(ctx context.Context, t *testing.T, a *oidcApp)
	}{
		{
			name: "Azure and Google identities reach one account by their own keys, (tid, oid) and sub, never by email",
			run: func(ctx context.Context, t *testing.T, a *oidcApp) {
				var account ccc.UUID
				a.hooks.set(func(h *hooks) {
					h.resolve = func(req *sessioninfo.NewSessionRequest) *sessionstorage.Resolution {
						switch {
						case req.Identity.Method == sessioninfo.MethodAzure && req.Identity.Connection == azureTenant:
							return &sessionstorage.Resolution{Outcome: sessionstorage.ProvisionAccount, NewUser: &sessionstorage.InsertSessionUser{Username: req.Identity.Email}}
						case req.Identity.Method == sessioninfo.MethodGoogle:
							return &sessionstorage.Resolution{Outcome: sessionstorage.LinkIdentity, UserID: account}
						default:
							return &sessionstorage.Resolution{Outcome: sessionstorage.RejectIdentity}
						}
					}
				})

				b := a.browser(t)
				assertRedirect(t, b.oidcSignIn(ctx, a.azure, "/azure", azureClaims(azureTenant, "oid-pat", "pat@lakeside.edu")), "/home", url.Values{})
				v := b.view(ctx)
				assertEventsSeen(t, v, "azure:"+azureTenant)
				account = ccc.Must(ccc.UUIDFromString(v.UserID))

				g := a.browser(t)
				assertRedirect(t, g.oidcSignIn(ctx, a.google, "/google", googleClaims("google-sub-pat", "pat@lakeside.edu")), "/home", url.Values{})
				gv := g.view(ctx)
				if gv.UserID != v.UserID {
					t.Errorf("Google sign-in account = %s, want the Azure-provisioned %s", gv.UserID, v.UserID)
				}
				assertEventsSeen(t, gv, "google")

				// The same oid in another tenant is another identity, whatever its email.
				other := a.browser(t)
				assertRedirect(t, other.oidcSignIn(ctx, a.azure, "/azure", azureClaims("22222222-2222-2222-2222-222222222222", "oid-pat", "pat@lakeside.edu")), "/login",
					url.Values{"code": {"identity_rejected"}})

				// Both links are now the account's: signing in again asks the resolver nothing.
				before, _ := a.hooks.counts()
				again := a.browser(t)
				again.oidcSignIn(ctx, a.azure, "/azure", azureClaims(azureTenant, "oid-pat", "renamed@lakeside.edu"))
				if got := again.view(ctx).UserID; got != v.UserID {
					t.Errorf("repeat Azure sign-in account = %s, want %s", got, v.UserID)
				}
				if after, linked := a.hooks.counts(); after != before || len(linked) != 2 {
					t.Errorf("resolver runs = %d (was %d), IdentityLinked reports = %d; want no new run and two reports", after, before, len(linked))
				}
			},
		},
		{
			name: "an ID token the provider did not issue for this client is refused with its code and starts nothing",
			run: func(ctx context.Context, t *testing.T, a *oidcApp) {
				claims := azureClaims(azureTenant, "oid-x", "x@lakeside.edu")
				claims["aud"] = "another-client"

				b := a.browser(t)
				assertRedirect(t, b.oidcSignIn(ctx, a.azure, "/azure", claims), "/login", url.Values{"code": {"verify_id_token_failed"}})
				b.expect(ctx, http.StatusUnauthorized, http.MethodGet, "/whoami", nil)
				if resolved, _ := a.hooks.counts(); resolved != 0 {
					t.Errorf("account resolver ran %d times, want never", resolved)
				}
			},
		},
		{
			name: "a Google account outside the hosted domain is refused before any account is resolved",
			run: func(ctx context.Context, t *testing.T, a *oidcApp) {
				claims := googleClaims("google-sub-x", "x@elsewhere.example")
				claims["hd"] = "elsewhere.example"

				b := a.browser(t)
				assertRedirect(t, b.oidcSignIn(ctx, a.google, "/google", claims), "/login", url.Values{"code": {"not_workspace_member"}})
				if resolved, _ := a.hooks.counts(); resolved != 0 {
					t.Errorf("account resolver ran %d times, want never", resolved)
				}
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			ctx := t.Context()

			tt.run(ctx, t, newOIDCApp(ctx, t))
		})
	}
}
