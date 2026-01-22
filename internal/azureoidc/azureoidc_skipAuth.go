//go:build skipAuth

// Package azureoidc implements a client for Azure OIDC Authorization where
// authentication is skipped for development by using the skipAuth build tag
package azureoidc

import (
	"context"
	"encoding/json"
	"net/http"
	"os"
	"strings"

	"github.com/cccteam/session/cookie"
	internalcookie "github.com/cccteam/session/internal/cookie"
	"github.com/go-playground/errors/v5"
	"github.com/gofrs/uuid"
)

var _ Authenticator = &OIDC{}

const defaultLoginURL = "/login"

// OIDC implements the Authenticator interface for OpenID Connect authentication.
type OIDC struct {
	redirectURL  string
	cookieClient *internalcookie.Client
	loginURL     string
}

// New returns a new OIDC Authenticator
func New(cookieClient *internalcookie.Client, _, _, _, redirectURL string) *OIDC {
	return &OIDC{
		redirectURL:  redirectURL,
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
// It populates 'claims' with the ID Token's claims and returns:
//   - the URL to redirect to following successful authentication
//   - the 'sid' value from the session_state query parameter
func (o *OIDC) Verify(_ context.Context, w http.ResponseWriter, r *http.Request, claims any) (returnURL, sid string, err error) {
	type claimsSimulated struct {
		PreferredUsername string   `json:"preferred_username"`
		Roles             []string `json:"roles"`
	}
	var c claimsSimulated
	c.PreferredUsername = os.Getenv("APP_USERNAME")
	c.Roles = strings.Split(os.Getenv("APP_ROLES"), ",")

	// Transfer the claims values to the input 'claims' variable
	cByte, err := json.Marshal(c)
	if err != nil {
		return "", "", errors.Wrap(err, "json.Marshal()")
	}
	if err := json.Unmarshal(cByte, claims); err != nil {
		return "", "", errors.Wrap(err, "json.Unmarshal()")
	}

	cval, ok, err := o.cookieClient.ReadOidcCookie(r)
	if err != nil {
		return "", "", errors.Wrap(err, "cookie.Client.ReadOidcCookie()")
	}
	if !ok {
		return "", "", errors.New("No OIDC cookie")
	}
	o.cookieClient.DeleteOidcCookie(w)

	returnURL, _ = cval.GetString(internalcookie.ReturnURL)
	if strings.TrimSpace(returnURL) == "" {
		returnURL = "/"
	}

	oidcID, err := uuid.NewV4()
	if err != nil {
		return "", "", errors.Wrap(err, "uuid.NewV4()")
	}

	return returnURL, oidcID.String(), nil
}
