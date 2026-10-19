//go:build !skipAuth

// Package azure is the Microsoft Entra ID (Azure) sign-in method: the OpenID Connect
// authorization code flow with PKCE against the tenants the registration admits, and
// its registration on an Auth session.
package azure

import (
	"context"
	"net/http"

	"github.com/cccteam/httpio"
	"github.com/cccteam/session/oidc"
	"github.com/cccteam/session/sessioninfo"
	"github.com/cccteam/session/signin"
	gooidc "github.com/coreos/go-oidc/v3/oidc"
	"github.com/go-playground/errors/v5"
)

var _ Authenticator = &OIDC{}

// OIDC is the Authenticator over Microsoft Entra ID: the shared OpenID Connect flow,
// keeping its state in the Azure state cookie, against the tenants the registration
// admits.
type OIDC struct {
	*oidc.Flow
	authority string
	tenants   TenantSet
}

// NewOIDC returns a new OIDC Authenticator for tenants under authority (the base URL
// of the Microsoft identity platform, see Config.Authority). One tenant is served at
// its own endpoint, whose document names the tenant's issuer and holds every token to
// it; several tenants, any tenant or personal accounts are served at the shared
// endpoint the shape calls for, whose document names its issuer with a placeholder, so
// Verify checks the token's issuer against the token's tenant itself and the tenant
// against the slot.
func NewOIDC(cookies signin.StateCookies, authority string, tenants TenantSet, clientID, clientSecret, redirectURL string) *OIDC {
	scopes := []string{gooidc.ScopeOpenID, "profile"}
	discovery := tenants.discoveryURL(authority)
	var loader oidc.Loader
	if tenants.shared() {
		loader = oidc.NewSharedEndpoint(discovery, clientID, clientSecret, redirectURL, scopes)
	} else {
		loader = oidc.New(discovery, clientID, clientSecret, redirectURL, scopes)
	}

	return &OIDC{Flow: oidc.NewFlow(cookies, loader), authority: authority, tenants: tenants}
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

// Verify completes the round trip (see oidc.Flow.Complete) and, beyond its checks,
// requires the token's issuer to be its tenant's under the authority
// (verify_id_token_failed otherwise, since a shared endpoint's document holds no token
// to an issuer) and the tenant to be one the slot admits (unlisted_tenant, or
// personal_account for a personal account under a work or school shape). It populates
// 'claims' with the ID Token's claims and returns:
//   - the URL to redirect to following successful authentication
//   - the 'sid' value from the session_state query parameter
func (o *OIDC) Verify(ctx context.Context, w http.ResponseWriter, r *http.Request, claims any) (returnURL, sid string, err error) {
	done, err := o.Complete(ctx, w, r)
	if err != nil {
		return "", "", errors.Wrap(err, "oidc.Flow.Complete()")
	}

	var tenant struct {
		Iss string `json:"iss"`
		Tid string `json:"tid"`
	}
	if err := done.Claims(&tenant); err != nil {
		return "", "", errors.Wrap(err, "oidc.Completed.Claims()")
	}
	if tenant.Tid == "" {
		return "", "", sessioninfo.NewLoginRefusal(sessioninfo.RefusedIDTokenVerification, httpio.NewUnauthorizedMessage("the ID token names no tenant"))
	}
	if _, err := admit(o.authority, o.tenants, tenant.Iss, tenant.Tid); err != nil {
		return "", "", err
	}

	if err := done.Claims(claims); err != nil {
		return "", "", errors.Wrap(err, "oidc.Completed.Claims()")
	}

	return done.ReturnURL, r.URL.Query().Get("session_state"), nil
}
