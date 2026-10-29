//go:build skipAuth

// Package google is the Google Workspace sign-in method, where
// authentication is skipped for development by using the skipAuth build tag
package google

import (
	"context"
	"encoding/json"
	"net/http"

	"github.com/cccteam/httpio"
	"github.com/cccteam/session/cookie"
	internalcookie "github.com/cccteam/session/internal/cookie"
	"github.com/cccteam/session/internal/simulated"
	"github.com/cccteam/session/sessioninfo"
	"github.com/cccteam/session/signin"
	"github.com/go-playground/errors/v5"
)

var _ Authenticator = &OIDC{}

const defaultLoginURL = "/login"

// OIDC implements the Authenticator interface for OpenID Connect authentication.
type OIDC struct {
	redirectURL string
	workspaces  WorkspaceSet
	cookies     signin.StateCookies
	loginURL    string
	// registration names the registration the simulated sign-in serves, which selects
	// the environment it reads the person from (internal/simulated).
	registration string
}

// NewOIDC returns a new OIDC Authenticator. The scopes are accepted and unused: the
// simulated Verify hands back no access token, and the simulated group lookup reads
// APP_ROLES instead.
func NewOIDC(cookies signin.StateCookies, _, _, redirectURL string, workspaces WorkspaceSet, _ ...string) *OIDC {
	return &OIDC{
		redirectURL: redirectURL,
		workspaces:  workspaces,
		cookies:     cookies,
	}
}

// SetLoginURL sets the URL to redirect to when an error occurs during the OIDC authentication process
func (o *OIDC) SetLoginURL(url string) {
	o.loginURL = url
}

// simulateAs names the registration this simulated sign-in serves: it signs in
// APP_<NAME>_USERNAME when the variable is set, APP_USERNAME otherwise.
func (o *OIDC) simulateAs(registration string) {
	o.registration = registration
}

// LoginURL returns the URL to redirect to when an error occurs during the OIDC authentication process
func (o *OIDC) LoginURL() string {
	if o.loginURL == "" {
		return defaultLoginURL
	}

	return o.loginURL
}

// AuthCodeURL returns the URL to redirect to in order to initiate the OIDC
// authentication process. The login options are accepted and unused: nothing is chosen.
func (o *OIDC) AuthCodeURL(_ context.Context, w http.ResponseWriter, returnURL string, _ signin.LoginOptions) (string, error) {
	cval := cookie.NewValues().SetString(internalcookie.ReturnURL, returnURL)

	o.cookies.WriteStateCookie(w, cval)

	return o.redirectURL, nil
}

// Verify performs the necessary verification and processing of the OIDC callback request.
// It populates 'claims' with simulated ID Token claims and returns the URL to redirect
// to following successful authentication. Nothing was exchanged, so there is no access
// token: in its place the simulated lookup is handed the registration's name, which it
// reads the person's groups by (APP_<NAME>_ROLES, else APP_ROLES).
func (o *OIDC) Verify(_ context.Context, w http.ResponseWriter, r *http.Request, claims any) (returnURL, accessToken string, err error) {
	type claimsSimulated struct {
		Iss           string `json:"iss"`
		Email         string `json:"email"`
		EmailVerified bool   `json:"email_verified"`
		Hd            string `json:"hd"`
		Sub           string `json:"sub"`
	}
	username := simulated.Username(o.registration)
	c := claimsSimulated{
		Iss:           IssuerURL,
		Email:         username,
		EmailVerified: true,
		Hd:            o.workspaces.simulatedHostedDomain(),
		Sub:           "skipauth-" + username,
	}

	// Transfer the claims values to the input 'claims' variable
	cByte, err := json.Marshal(c)
	if err != nil {
		return "", "", errors.Wrap(err, "json.Marshal()")
	}
	if err := json.Unmarshal(cByte, claims); err != nil {
		return "", "", errors.Wrap(err, "json.Unmarshal()")
	}

	cval, cookieName, err := o.cookies.ReadStateCookie(r)
	if err != nil {
		return "", "", errors.Wrap(err, "cookie.Client.ReadStateCookie()")
	}
	if cookieName == "" {
		return "", "", sessioninfo.NewLoginRefusal(sessioninfo.RefusedNoOIDCCookie, httpio.NewForbiddenMessage("No OIDC cookie"))
	}
	o.cookies.DeleteStateCookie(w, cookieName)

	returnURL, _ = cval.GetString(internalcookie.ReturnURL)
	returnURL = internalcookie.SanitizeReturnURL(returnURL)

	return returnURL, o.registration, nil
}
