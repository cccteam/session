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

// skipAuthTenantID is the tid claim stamped on every simulated login. skipAuth
// simulates a single directory tenant, matching a real deployment where all of an
// application's users share one tenant.
var skipAuthTenantID = uuid.Must(uuid.FromString("034cdd64-5dd9-4a3b-90fb-c76d3a499433"))

// skipAuthOidNamespace is the UUIDv5 namespace the simulated oid claim is derived
// under. Deriving oid from APP_USERNAME gives each simulated user one durable
// identity, so repeated logins resolve to the same OIDCUsers anchor row when the
// anchor is enabled. The namespace is part of the skipAuth contract: changing it
// changes every simulated oid, orphaning anchor rows in existing dev databases.
var skipAuthOidNamespace = uuid.Must(uuid.FromString("2aa10a18-1d51-4dcd-949a-b85cf4e628e3"))

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
// It populates 'claims' with simulated ID Token claims and returns:
//   - the URL to redirect to following successful authentication
//   - the 'sid' value from the session_state query parameter
//
// The simulated claims carry preferred_username and roles from APP_USERNAME and
// APP_ROLES, plus a deterministic (tid, oid) pair — the fixed skipAuth tenant and a
// UUIDv5 of APP_USERNAME — so logins satisfy the OIDC user anchor's fail-closed
// (tid, oid) requirement and each simulated user maps to one durable anchor row.
func (o *OIDC) Verify(_ context.Context, w http.ResponseWriter, r *http.Request, claims any) (returnURL, sid string, err error) {
	type claimsSimulated struct {
		PreferredUsername string   `json:"preferred_username"`
		Roles             []string `json:"roles"`
		Tid               string   `json:"tid"`
		Oid               string   `json:"oid"`
	}
	var c claimsSimulated
	c.PreferredUsername = os.Getenv("APP_USERNAME")
	c.Roles = strings.Split(os.Getenv("APP_ROLES"), ",")
	c.Tid = skipAuthTenantID.String()
	c.Oid = uuid.NewV5(skipAuthOidNamespace, c.PreferredUsername).String()

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
	returnURL = internalcookie.SanitizeReturnURL(returnURL)

	oidcID, err := uuid.NewV4()
	if err != nil {
		return "", "", errors.Wrap(err, "uuid.NewV4()")
	}

	return returnURL, oidcID.String(), nil
}
