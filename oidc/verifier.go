//go:build !skipAuth

package oidc

import (
	"context"
	"net/http"

	"github.com/cccteam/session/signin"
	"github.com/go-playground/errors/v5"
	"golang.org/x/oauth2"
)

var _ Authenticator = &Verifier{}

// Verifier is the generic method's Authenticator: the shared flow against the provider
// the issuer names, keeping its state in the registration's state cookie.
type Verifier struct {
	*Flow
}

// NewVerifier returns the verifier for the provider at issuer, whose discovery document
// must name that issuer and whose tokens must carry it. An empty clientSecret is a
// public client: the code exchange carries the client ID alone. scopes are asked for
// beside openid, email and profile when none are given.
func NewVerifier(cookies signin.StateCookies, issuer, clientID, clientSecret, redirectURL string, scopes []string) *Verifier {
	return &Verifier{Flow: NewFlow(cookies, New(issuer, clientID, clientSecret, redirectURL, scopesOf(scopes)))}
}

// simulateAs is the simulated build's hook (verifier_skipAuth.go), where the
// registration's name selects the person who signs in. This verifier asks the provider
// who signed in, so the name changes nothing here.
func (v *Verifier) simulateAs(string) {
	// Nothing to record: the provider answers.
}

// AuthCodeURL writes the state cookie and returns the provider's authorization URL. A
// login hint is passed as login_hint and SelectAccount as prompt=select_account; the
// provider reads them or not, and the identity comes from the verified token.
func (v *Verifier) AuthCodeURL(ctx context.Context, w http.ResponseWriter, returnURL string, options signin.LoginOptions) (string, error) {
	var params []oauth2.AuthCodeOption
	if options.LoginHint != "" {
		params = append(params, oauth2.SetAuthURLParam("login_hint", options.LoginHint))
	}
	if options.SelectAccount {
		params = append(params, oauth2.SetAuthURLParam("prompt", "select_account"))
	}
	u, err := v.Begin(ctx, w, returnURL, params...)
	if err != nil {
		return "", errors.Wrap(err, "oidc.Flow.Begin()")
	}

	return u, nil
}

// Verify completes the round trip (see Flow.Complete), populates claims with the ID
// token's claims and returns the path the browser goes to next.
func (v *Verifier) Verify(ctx context.Context, w http.ResponseWriter, r *http.Request, claims any) (string, error) {
	done, err := v.Complete(ctx, w, r)
	if err != nil {
		return "", errors.Wrap(err, "oidc.Flow.Complete()")
	}
	if err := done.Claims(claims); err != nil {
		return "", errors.Wrap(err, "oidc.Completed.Claims()")
	}

	return done.ReturnURL, nil
}
