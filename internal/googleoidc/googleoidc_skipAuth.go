//go:build skipAuth

// Package googleoidc implements a client for Google OIDC Authorization where
// authentication is skipped for development by using the skipAuth build tag
package googleoidc

import (
	"context"
	"encoding/json"
	"net/http"
	"os"

	"github.com/cccteam/httpio"
	"github.com/cccteam/session/cookie"
	internalcookie "github.com/cccteam/session/internal/cookie"
	"github.com/cccteam/session/sessioninfo"
	"github.com/go-playground/errors/v5"
)

var _ Authenticator = &OIDC{}

const defaultLoginURL = "/login"

// OIDC implements the Authenticator interface for OpenID Connect authentication.
type OIDC struct {
	redirectURL  string
	hostedDomain string
	cookieClient *internalcookie.Client
	loginURL     string
}

// New returns a new OIDC Authenticator. The scopes are accepted and unused: the
// simulated Verify hands back no access token, and the simulated group lookup reads
// APP_ROLES instead.
func New(cookieClient *internalcookie.Client, _, _, redirectURL, hostedDomain string, _ ...string) *OIDC {
	return &OIDC{
		redirectURL:  redirectURL,
		hostedDomain: hostedDomain,
		cookieClient: cookieClient,
	}
}

// SetLoginURL sets the URL to redirect to when an error occurs during the OIDC authentication process
func (o *OIDC) SetLoginURL(url string) {
	o.loginURL = url
}

// LoginURL returns the URL to redirect to when an error occurs during the OIDC authentication process
func (o *OIDC) LoginURL() string {
	if o.loginURL == "" {
		return defaultLoginURL
	}

	return o.loginURL
}

// AuthCodeURL returns the URL to redirect to in order to initiate the OIDC authentication process
func (o *OIDC) AuthCodeURL(_ context.Context, w http.ResponseWriter, returnURL string) (string, error) {
	cval := cookie.NewValues().SetString(internalcookie.ReturnURL, returnURL)

	o.cookieClient.WriteStateCookie(w, internalcookie.GoogleStateCookieName, cval)

	return o.redirectURL, nil
}

// Verify performs the necessary verification and processing of the OIDC callback request.
// It populates 'claims' with simulated ID Token claims and returns the URL to redirect
// to following successful authentication. There is no access token: nothing was
// exchanged, and the simulated group lookup needs none.
func (o *OIDC) Verify(_ context.Context, w http.ResponseWriter, r *http.Request, claims any) (returnURL, accessToken string, err error) {
	type claimsSimulated struct {
		Email         string `json:"email"`
		EmailVerified bool   `json:"email_verified"`
		Hd            string `json:"hd"`
		Sub           string `json:"sub"`
	}
	c := claimsSimulated{
		Email:         os.Getenv("APP_USERNAME"),
		EmailVerified: true,
		Hd:            o.hostedDomain,
		Sub:           "skipauth-" + os.Getenv("APP_USERNAME"),
	}

	// Transfer the claims values to the input 'claims' variable
	cByte, err := json.Marshal(c)
	if err != nil {
		return "", "", errors.Wrap(err, "json.Marshal()")
	}
	if err := json.Unmarshal(cByte, claims); err != nil {
		return "", "", errors.Wrap(err, "json.Unmarshal()")
	}

	cval, cookieName, err := o.cookieClient.ReadStateCookie(r, internalcookie.GoogleStateCookieName)
	if err != nil {
		return "", "", errors.Wrap(err, "cookie.Client.ReadStateCookie()")
	}
	if cookieName == "" {
		return "", "", sessioninfo.NewLoginRefusal(sessioninfo.RefusedNoOIDCCookie, httpio.NewForbiddenMessage("No OIDC cookie"))
	}
	o.cookieClient.DeleteStateCookie(w, cookieName)

	returnURL, _ = cval.GetString(internalcookie.ReturnURL)
	returnURL = internalcookie.SanitizeReturnURL(returnURL)

	return returnURL, "", nil
}
