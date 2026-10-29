//go:build !skipAuth

// Package google is the Google Workspace sign-in method: the OpenID Connect
// authorization code flow with PKCE (Proof Key for Code Exchange), restricted to the
// Workspaces the registration admits and keyed by the connection the slot selects for
// the account.
package google

import (
	"context"
	"net/http"

	"github.com/cccteam/httpio"
	"github.com/cccteam/session/oidc"
	"github.com/cccteam/session/sessioninfo"
	"github.com/cccteam/session/signin"
	gooidc "github.com/coreos/go-oidc/v3/oidc"
	"github.com/go-playground/errors/v5"
	"golang.org/x/oauth2"
)

var _ Authenticator = &OIDC{}

// OIDC is the Authenticator over Google: the shared OpenID Connect flow, keeping its
// state in the registration's state cookie, restricted to the Workspaces the
// registration admits.
type OIDC struct {
	*oidc.Flow
	workspaces WorkspaceSet
}

// NewOIDC returns a new OIDC Authenticator. workspaces is the registration's
// organization slot: the authorization request hints the domain (one Workspace with
// one domain), any Workspace account (several domains or any Workspace) or nothing
// (any Google account) to Google's chooser, and the verified ID token's hd claim must
// select an entry of the slot. scopes are asked for beside the sign-in's own (openid,
// email, profile); the access token Verify returns carries them.
func NewOIDC(cookies signin.StateCookies, clientID, clientSecret, redirectURL string, workspaces WorkspaceSet, scopes ...string) *OIDC {
	return newWithIssuer(cookies, IssuerURL, clientID, clientSecret, redirectURL, workspaces, scopes...)
}

// newWithIssuer exists so tests can point the authenticator at a fake IdP; production
// code always goes through NewOIDC and Google's fixed issuer.
func newWithIssuer(cookies signin.StateCookies, issuer, clientID, clientSecret, redirectURL string, workspaces WorkspaceSet, scopes ...string) *OIDC {
	loader := oidc.New(issuer, clientID, clientSecret, redirectURL, append([]string{gooidc.ScopeOpenID, "email", "profile"}, scopes...))

	return &OIDC{Flow: oidc.NewFlow(cookies, loader), workspaces: workspaces}
}

// simulateAs is the simulated build's hook (verifier_skipAuth.go), where the
// registration's name selects the person who signs in. This verifier asks Google who
// signed in, so the name changes nothing here.
func (o *OIDC) simulateAs(string) {
	// Nothing to record: the provider answers.
}

// AuthCodeURL returns the URL to redirect to in order to initiate the OIDC
// authentication process. A login hint is passed to Google as login_hint, so Google
// picks that account and skips its chooser; SelectAccount is passed as
// prompt=select_account, so Google shows its chooser even when one signed-in account
// would otherwise be taken without asking.
func (o *OIDC) AuthCodeURL(ctx context.Context, w http.ResponseWriter, returnURL string, options signin.LoginOptions) (string, error) {
	// The hd parameter narrows Google's account chooser to the Workspace domain, or
	// to Workspace accounts at large when the registration admits several. It is a UX
	// hint only — the trusted enforcement is the hd claim check in Verify.
	var params []oauth2.AuthCodeOption
	if hint, ok := o.workspaces.hdHint(); ok {
		params = append(params, oauth2.SetAuthURLParam("hd", hint))
	}
	if options.LoginHint != "" {
		params = append(params, oauth2.SetAuthURLParam("login_hint", options.LoginHint))
	}
	if options.SelectAccount {
		params = append(params, oauth2.SetAuthURLParam("prompt", "select_account"))
	}
	u, err := o.Begin(ctx, w, returnURL, params...)
	if err != nil {
		return "", errors.Wrap(err, "oidc.Flow.Begin()")
	}

	return u, nil
}

// Verify completes the round trip (see oidc.Flow.Complete) and, beyond its checks,
// rejects tokens whose hd claim selects no entry of the registration's Workspaces (an
// account outside any Workspace carries no hd claim at all, and reaches only a slot
// that admits any Google account) and tokens without a verified email. It populates
// 'claims' with the ID Token's claims and returns the URL to
// redirect to following successful authentication, with the access token of the code
// exchange. Google issues no sid claim and supports no IdP-initiated logout, so no OIDC
// session ID is returned.
func (o *OIDC) Verify(ctx context.Context, w http.ResponseWriter, r *http.Request, claims any) (returnURL, accessToken string, err error) {
	done, err := o.Complete(ctx, w, r)
	if err != nil {
		return "", "", errors.Wrap(err, "oidc.Flow.Complete()")
	}

	// Enforce the slot on the verified token. Unlike the hd request parameter, the hd
	// claim is inside the Google-signed token and can be trusted; an account outside a
	// Workspace has no hd claim and reaches only a slot that admits any Google account.
	var gClaims struct {
		Hd            string `json:"hd"`
		EmailVerified bool   `json:"email_verified"`
	}
	if err := done.Claims(&gClaims); err != nil {
		return "", "", errors.Wrap(err, "oidc.Completed.Claims()")
	}
	if _, ok := o.workspaces.connectionFor(gClaims.Hd); !ok {
		return "", "", errNotWorkspaceMember()
	}
	if !gClaims.EmailVerified {
		return "", "", sessioninfo.NewLoginRefusal(sessioninfo.RefusedEmailNotVerified, httpio.NewForbiddenMessage("User email is not verified"))
	}

	if err := done.Claims(claims); err != nil {
		return "", "", errors.Wrap(err, "oidc.Completed.Claims()")
	}

	return done.ReturnURL, done.Token.AccessToken, nil
}
