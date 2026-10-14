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
	"github.com/cccteam/session/azure"
	"github.com/cccteam/session/google"
	"github.com/cccteam/session/internal/oidctest"
	"github.com/cccteam/session/signin"
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
type oidcApp[Tx any] struct {
	*authApp[Tx]
	azure, google *oidctest.FakeIDP
}

func newOIDCApp[Tx any](ctx context.Context, t *testing.T, be backend[Tx]) *oidcApp[Tx] {
	t.Helper()

	h := &hooks[Tx]{rows: be.rows}
	db, store := be.newStore(ctx, t)
	azureIDP := oidctest.NewFakeIDP(t, "azure-client")
	googleIDP := oidctest.NewFakeIDP(t, "google-client")

	auth, err := session.NewAuth[appSessionData, appUserData](withCustomData(t, store, h), cookieKey, h.signInPolicy, session.WithIdentityLinked(h.identityLinked))
	if err != nil {
		t.Fatalf("session.NewAuth() error = %v", err)
	}
	azureMethod := azure.SignIn(auth, "azure", h.azureResolver, &azure.Config{
		RoleSync: signin.DisableRoleSync(), IssuerURL: azureIDP.Server.URL,
		ClientID: "azure-client", ClientSecret: "secret", RedirectURL: "https://app.example/azure/callback",
	})
	googleIssuerMu.Lock()
	issuer := google.IssuerURL
	google.IssuerURL = googleIDP.Server.URL
	googleMethod := google.SignIn(auth, "google", h.googleResolver, &google.Config{
		RoleSync: google.DisableRoleSync(), HostedDomain: hostedDomain,
		ClientID: "google-client", ClientSecret: "secret", RedirectURL: "https://app.example/google/callback",
	})
	google.IssuerURL = issuer
	googleIssuerMu.Unlock()

	r := chi.NewRouter()
	mountAuth(r, auth, func(r chi.Router) {
		r.Get("/azure/login", azureMethod.Login())
		r.Get("/azure/callback", azureMethod.Callback())
		r.Get("/azure/logout", azureMethod.FrontChannelLogout())
		r.Get("/google/login", googleMethod.Login())
		r.Get("/google/callback", googleMethod.Callback())
	})
	server := httptest.NewTLSServer(r)
	t.Cleanup(server.Close)

	return &oidcApp[Tx]{authApp: &authApp[Tx]{db: db, rows: be.rows, server: server, api: auth.API(), hooks: h}, azure: azureIDP, google: googleIDP}
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

// withSID adds the provider's session id (the sid claim) to claims.
func withSID(claims map[string]any, sid string) map[string]any {
	claims["sid"] = sid

	return claims
}

func googleClaims(sub, email string) map[string]any {
	return map[string]any{"sub": sub, "email": email, "email_verified": true, "hd": hostedDomain}
}

// TestAuthSeams_AzureAndGoogle runs the Azure and Google scenarios on each backend.
func TestAuthSeams_AzureAndGoogle(t *testing.T) {
	t.Parallel()

	t.Run(postgresBackend.name, func(t *testing.T) {
		t.Parallel()
		runAzureGoogleSeams(t, postgresBackend)
	})
	t.Run(spannerBackend.name, func(t *testing.T) {
		t.Parallel()
		runAzureGoogleSeams(t, spannerBackend)
	})
}

func runAzureGoogleSeams[Tx any](t *testing.T, be backend[Tx]) {
	tests := []struct {
		name string
		run  func(ctx context.Context, t *testing.T, a *oidcApp[Tx])
	}{
		{
			name: "Azure and Google identities reach one user by their own keys, (tid, oid) and sub, never by email",
			run: func(ctx context.Context, t *testing.T, a *oidcApp[Tx]) {
				var (
					user    ccc.UUID
					trusted bool
				)
				a.hooks.set(func(h *hooks[Tx]) {
					h.resolveAzure = func(identity *azure.Identity) *signin.Resolution {
						if identity.TenantID != azureTenant {
							return signin.Reject("")
						}

						return signin.Provision(&signin.NewUser{Username: identity.Email}, nil)
					}
					h.resolveGoogle = func(*google.Identity) *signin.Resolution {
						return signin.Link(user, trusted)
					}
				})

				b := a.browser(t)
				assertRedirect(t, b.oidcSignIn(ctx, a.azure, "/azure", azureClaims(azureTenant, "oid-pat", "pat@lakeside.edu")), "/home", url.Values{})
				v := b.view(ctx)
				assertEventsSeen(t, v, "azure:"+azureTenant)
				a.hooks.set(func(*hooks[Tx]) { user = ccc.Must(ccc.UUIDFromString(v.UserID)) })

				// Pat has no password, so a Google identity reaches the Azure-provisioned user
				// only when the resolver vouches for it: untrusted, the link is refused.
				g := a.browser(t)
				assertRedirect(t, g.oidcSignIn(ctx, a.google, "/google", googleClaims("google-sub-pat", "pat@lakeside.edu")), "/login",
					url.Values{"code": {"identity_rejected"}})
				a.hooks.set(func(*hooks[Tx]) { trusted = true })
				assertRedirect(t, g.oidcSignIn(ctx, a.google, "/google", googleClaims("google-sub-pat", "pat@lakeside.edu")), "/home", url.Values{})
				gv := g.view(ctx)
				if gv.UserID != v.UserID {
					t.Errorf("Google sign-in user = %s, want the Azure-provisioned %s", gv.UserID, v.UserID)
				}
				assertEventsSeen(t, gv, "google")

				// The same oid in another tenant is another identity, whatever its email.
				other := a.browser(t)
				assertRedirect(t, other.oidcSignIn(ctx, a.azure, "/azure", azureClaims("22222222-2222-2222-2222-222222222222", "oid-pat", "pat@lakeside.edu")), "/login",
					url.Values{"code": {"identity_rejected"}})

				// Both links are now the user's: signing in again asks the resolver nothing.
				before, _ := a.hooks.counts()
				again := a.browser(t)
				again.oidcSignIn(ctx, a.azure, "/azure", azureClaims(azureTenant, "oid-pat", "renamed@lakeside.edu"))
				if got := again.view(ctx).UserID; got != v.UserID {
					t.Errorf("repeat Azure sign-in user = %s, want %s", got, v.UserID)
				}
				if after, linked := a.hooks.counts(); after != before || len(linked) != 2 {
					t.Errorf("resolver runs = %d (was %d), IdentityLinked reports = %d; want no new run and two reports", after, before, len(linked))
				}
			},
		},
		{
			name: "an ID token the provider did not issue for this client is refused with its code and starts nothing",
			run: func(ctx context.Context, t *testing.T, a *oidcApp[Tx]) {
				claims := azureClaims(azureTenant, "oid-x", "x@lakeside.edu")
				claims["aud"] = "another-client"

				b := a.browser(t)
				assertRedirect(t, b.oidcSignIn(ctx, a.azure, "/azure", claims), "/login", url.Values{"code": {"verify_id_token_failed"}})
				b.expect(ctx, http.StatusUnauthorized, http.MethodGet, "/whoami", nil)
				if resolved, _ := a.hooks.counts(); resolved != 0 {
					t.Errorf("user resolver ran %d times, want never", resolved)
				}
			},
		},
		{
			name: "an Entra front-channel logout ends the sessions whose sign-in carried its sid and no other, called by the provider without a session",
			run: func(ctx context.Context, t *testing.T, a *oidcApp[Tx]) {
				a.hooks.set(func(h *hooks[Tx]) {
					h.resolveAzure = func(identity *azure.Identity) *signin.Resolution {
						return signin.Provision(&signin.NewUser{Username: identity.Email}, nil)
					}
				})

				named := a.browser(t)
				assertRedirect(t, named.oidcSignIn(ctx, a.azure, "/azure", withSID(azureClaims(azureTenant, "oid-pat", "pat@lakeside.edu"), "sid-pat-1")), "/home", url.Values{})
				other := a.browser(t)
				assertRedirect(t, other.oidcSignIn(ctx, a.azure, "/azure", withSID(azureClaims(azureTenant, "oid-pat", "pat@lakeside.edu"), "sid-pat-2")), "/home", url.Values{})
				named.view(ctx)
				other.view(ctx)
				// An impersonation started on the session under sid-pat-1 keeps that id, so
				// the logout reaches it too.
				sam := a.seed(ctx, t, "sam@lakeside.edu")
				acting := named.clone()
				acting.expect(ctx, http.StatusNoContent, http.MethodPost, "/impersonate", map[string]string{"user": "sam@lakeside.edu"})
				if v := acting.view(ctx); v.UserID != sam.String() {
					t.Fatalf("impersonated session = %+v, want user %s", v, sam)
				}

				// Entra calls the logout URL in a frame: a client with no cookies.
				provider := a.browser(t)
				provider.expect(ctx, http.StatusOK, http.MethodGet, "/azure/logout?sid=sid-pat-1&iss="+url.QueryEscape(a.azure.Server.URL), nil)

				named.expect(ctx, http.StatusUnauthorized, http.MethodGet, "/whoami", nil)
				acting.expect(ctx, http.StatusUnauthorized, http.MethodGet, "/whoami", nil)
				if imps, err := a.api.ActiveImpersonations(ctx, nil); err != nil || len(imps) != 0 {
					t.Errorf("ActiveImpersonations() = %v, %v, want none: the impersonation ended with the logout", imps, err)
				}
				if v := other.view(ctx); v.Username != "pat@lakeside.edu" {
					t.Errorf("the session under another sid = %+v, want it still signed in", v)
				}
				provider.expect(ctx, http.StatusBadRequest, http.MethodGet, "/azure/logout", nil)
				provider.expect(ctx, http.StatusBadRequest, http.MethodGet, "/azure/logout?sid=sid-pat-2&iss="+url.QueryEscape("https://other.example"), nil)
			},
		},
		{
			name: "a Google user outside the hosted domain is refused before any user is resolved",
			run: func(ctx context.Context, t *testing.T, a *oidcApp[Tx]) {
				claims := googleClaims("google-sub-x", "x@elsewhere.example")
				claims["hd"] = "elsewhere.example"

				b := a.browser(t)
				assertRedirect(t, b.oidcSignIn(ctx, a.google, "/google", claims), "/login", url.Values{"code": {"not_workspace_member"}})
				if resolved, _ := a.hooks.counts(); resolved != 0 {
					t.Errorf("user resolver ran %d times, want never", resolved)
				}
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			ctx := t.Context()

			tt.run(ctx, t, newOIDCApp(ctx, t, be))
		})
	}
}
