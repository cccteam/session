//go:build !skipAuth

// Package azure is the Microsoft Entra ID (Azure) sign-in method: the OpenID Connect
// authorization code flow with PKCE against the tenant, and its registration on an
// Auth session.
package azure

import (
	"context"
	"net/http"

	internalcookie "github.com/cccteam/session/internal/cookie"
	"github.com/cccteam/session/oidc"
	"github.com/cccteam/session/signin"
	gooidc "github.com/coreos/go-oidc/v3/oidc"
	"github.com/go-playground/errors/v5"
)

var _ Authenticator = &OIDC{}

// OIDC is the Authenticator over Microsoft Entra ID: the shared OpenID Connect flow,
// keeping its state in the Azure state cookie.
type OIDC struct {
	*oidc.Flow
}

// NewOIDC returns a new OIDC Authenticator for the tenant at issuerURL.
func NewOIDC(cookies signin.StateCookies, issuerURL, clientID, clientSecret, redirectURL string) *OIDC {
	loader := oidc.New(issuerURL, clientID, clientSecret, redirectURL, []string{gooidc.ScopeOpenID, "profile"})

	return &OIDC{Flow: oidc.NewFlow(cookies, internalcookie.AzureStateCookieName, loader)}
}

// simulateAs is the simulated build's hook (verifier_skipAuth.go), where the
// registration's name selects the person who signs in. This verifier asks the tenant
// who signed in, so the name changes nothing here.
func (o *OIDC) simulateAs(string) {
	// Nothing to record: the provider answers.
}

// AuthCodeURL returns the URL to redirect to in order to initiate the OIDC authentication process
func (o *OIDC) AuthCodeURL(ctx context.Context, w http.ResponseWriter, returnURL string) (string, error) {
	u, err := o.Begin(ctx, w, returnURL)
	if err != nil {
		return "", errors.Wrap(err, "oidc.Flow.Begin()")
	}

	return u, nil
}

// Verify completes the round trip (see oidc.Flow.Complete), populates 'claims' with the
// ID Token's claims and returns:
//   - the URL to redirect to following successful authentication
//   - the 'sid' value from the session_state query parameter
func (o *OIDC) Verify(ctx context.Context, w http.ResponseWriter, r *http.Request, claims any) (returnURL, sid string, err error) {
	done, err := o.Complete(ctx, w, r)
	if err != nil {
		return "", "", errors.Wrap(err, "oidc.Flow.Complete()")
	}
	if err := done.Claims(claims); err != nil {
		return "", "", errors.Wrap(err, "oidc.Completed.Claims()")
	}

	return done.ReturnURL, r.URL.Query().Get("session_state"), nil
}
