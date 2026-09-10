//go:build skipAuth

// Package googleoidc implements a client for Google OIDC Authorization where
// authentication is skipped for development by using the skipAuth build tag
package googleoidc

import (
	"context"
	"encoding/json"
	"net/http"
	"os"

	"github.com/cccteam/session/cookie"
	internalcookie "github.com/cccteam/session/internal/cookie"
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

// New returns a new OIDC Authenticator
func New(cookieClient *internalcookie.Client, _, _, redirectURL, hostedDomain string) *OIDC {
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

	o.cookieClient.WriteOidcCookie(w, cval)

	return o.redirectURL, nil
}

// Verify performs the necessary verification and processing of the OIDC callback request.
// It populates 'claims' with simulated ID Token claims and returns the URL to redirect
// to following successful authentication.
func (o *OIDC) Verify(_ context.Context, w http.ResponseWriter, r *http.Request, claims any) (returnURL string, err error) {
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
		return "", errors.Wrap(err, "json.Marshal()")
	}
	if err := json.Unmarshal(cByte, claims); err != nil {
		return "", errors.Wrap(err, "json.Unmarshal()")
	}

	cval, ok, err := o.cookieClient.ReadOidcCookie(r)
	if err != nil {
		return "", errors.Wrap(err, "cookie.Client.ReadOidcCookie()")
	}
	if !ok {
		return "", errors.New("No OIDC cookie")
	}
	o.cookieClient.DeleteOidcCookie(w)

	returnURL, _ = cval.GetString(internalcookie.ReturnURL)
	returnURL = internalcookie.SanitizeReturnURL(returnURL)

	return returnURL, nil
}
