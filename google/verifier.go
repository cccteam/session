//go:build !skipAuth

// Package google is the Google Workspace sign-in method: the OpenID Connect
// authorization code flow with PKCE (Proof Key for Code Exchange), restricted to a
// single Google Workspace hosted domain.
package google

import (
	"context"
	"net/http"
	"strings"

	"github.com/cccteam/httpio"
	internalcookie "github.com/cccteam/session/internal/cookie"
	"github.com/cccteam/session/oidc"
	"github.com/cccteam/session/sessioninfo"
	"github.com/cccteam/session/signin"
	gooidc "github.com/coreos/go-oidc/v3/oidc"
	"github.com/go-playground/errors/v5"
	"golang.org/x/oauth2"
)

// IssuerURL is Google's OIDC issuer. Google uses one issuer for every Workspace
// organization; the hd claim names the organization. It is a variable only so this
// module's end-to-end tests can point a sign-in at a fake identity provider. NewOIDC
// reads it when the authenticator is built.
var IssuerURL = "https://accounts.google.com"

var _ Authenticator = &OIDC{}

// OIDC is the Authenticator over Google Workspace: the shared OpenID Connect flow,
// keeping its state in the Google state cookie, restricted to one hosted domain.
type OIDC struct {
	*oidc.Flow
	hostedDomain string
}

// NewOIDC returns a new OIDC Authenticator. hostedDomain is the Google Workspace domain the
// flow is restricted to: it is sent as the hd hint on the authorization request and
// enforced against the verified ID token's hd claim. scopes are asked for beside the
// sign-in's own (openid, email, profile); the access token Verify returns carries them.
func NewOIDC(cookies signin.StateCookies, clientID, clientSecret, redirectURL, hostedDomain string, scopes ...string) *OIDC {
	return newWithIssuer(cookies, IssuerURL, clientID, clientSecret, redirectURL, hostedDomain, scopes...)
}

// newWithIssuer exists so tests can point the authenticator at a fake IdP; production
// code always goes through NewOIDC and Google's fixed issuer.
func newWithIssuer(cookies signin.StateCookies, issuer, clientID, clientSecret, redirectURL, hostedDomain string, scopes ...string) *OIDC {
	loader := oidc.New(issuer, clientID, clientSecret, redirectURL, append([]string{gooidc.ScopeOpenID, "email", "profile"}, scopes...))

	return &OIDC{Flow: oidc.NewFlow(cookies, internalcookie.GoogleStateCookieName, loader), hostedDomain: hostedDomain}
}

// AuthCodeURL returns the URL to redirect to in order to initiate the OIDC authentication process
func (o *OIDC) AuthCodeURL(ctx context.Context, w http.ResponseWriter, returnURL string) (string, error) {
	// The hd parameter pre-selects the Workspace domain's users in Google's user
	// chooser. It is a UX hint only — the trusted enforcement is the hd claim check in
	// Verify.
	u, err := o.Begin(ctx, w, returnURL, oauth2.SetAuthURLParam("hd", o.hostedDomain))
	if err != nil {
		return "", errors.Wrap(err, "oidc.Flow.Begin()")
	}

	return u, nil
}

// Verify completes the round trip (see oidc.Flow.Complete) and, beyond its checks,
// rejects tokens whose hd claim does not match the configured hosted domain (a consumer
// user carries no hd claim at all and fails closed) and tokens without a verified
// email. It populates 'claims' with the ID Token's claims and returns the URL to
// redirect to following successful authentication, with the access token of the code
// exchange. Google issues no sid claim and supports no IdP-initiated logout, so no OIDC
// session ID is returned.
func (o *OIDC) Verify(ctx context.Context, w http.ResponseWriter, r *http.Request, claims any) (returnURL, accessToken string, err error) {
	done, err := o.Complete(ctx, w, r)
	if err != nil {
		return "", "", errors.Wrap(err, "oidc.Flow.Complete()")
	}

	// Enforce the hosted-domain restriction on the verified token. Unlike the hd
	// request parameter, the hd claim is inside the Google-signed token and can be
	// trusted; a consumer user has no hd claim and fails closed.
	var gClaims struct {
		Hd            string `json:"hd"`
		EmailVerified bool   `json:"email_verified"`
	}
	if err := done.Claims(&gClaims); err != nil {
		return "", "", errors.Wrap(err, "oidc.Completed.Claims()")
	}
	if !strings.EqualFold(gClaims.Hd, o.hostedDomain) {
		return "", "", sessioninfo.NewLoginRefusal(sessioninfo.RefusedNotWorkspaceMember, httpio.NewForbiddenMessage("User is not a member of the required Google Workspace domain"))
	}
	if !gClaims.EmailVerified {
		return "", "", sessioninfo.NewLoginRefusal(sessioninfo.RefusedEmailNotVerified, httpio.NewForbiddenMessage("User email is not verified"))
	}

	if err := done.Claims(claims); err != nil {
		return "", "", errors.Wrap(err, "oidc.Completed.Claims()")
	}

	return done.ReturnURL, done.Token.AccessToken, nil
}
