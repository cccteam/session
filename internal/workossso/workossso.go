// Package workossso implements a client for the WorkOS Standalone SSO authorization code
// flow.
//
// WorkOS brokers each upstream identity provider (SAML or OIDC) and returns a normalized
// profile from a server-to-server code exchange authenticated with the API key, so there
// is no ID token to verify locally: the exchange itself, over TLS to the configured base
// URL with the secret API key, is what vouches for the profile.
package workossso

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/cccteam/httpio"
	"github.com/cccteam/session/cookie"
	internalcookie "github.com/cccteam/session/internal/cookie"
	"github.com/cccteam/session/sessioninfo"
	"github.com/go-playground/errors/v5"
	"github.com/gofrs/uuid"
)

var _ Authenticator = &Client{}

const (
	// DefaultBaseURL is the WorkOS API.
	DefaultBaseURL  = "https://api.workos.com"
	defaultLoginURL = "/login"
	// maxProfileBytes bounds the token response read from WorkOS.
	maxProfileBytes = 1 << 20
)

// Authenticator is the WorkOS SSO flow the session layer drives.
type Authenticator interface {
	// AuthorizationURL writes the state cookie and returns the URL that starts SSO for
	// the WorkOS organization.
	AuthorizationURL(ctx context.Context, w http.ResponseWriter, organization, returnURL string) (string, error)
	// Verify checks the callback against the state cookie, exchanges its code for the
	// profile and returns the sanitized return URL, the decoded profile and the raw
	// profile JSON exactly as WorkOS returned it.
	Verify(ctx context.Context, w http.ResponseWriter, r *http.Request) (returnURL string, profile *Profile, rawProfile json.RawMessage, err error)
	// LoginURL is where a refused or pending login is sent.
	LoginURL() string
}

// Profile is the normalized user profile WorkOS returns from the code exchange.
type Profile struct {
	// ID is the WorkOS profile ID.
	ID string `json:"id"`
	// IdpID is the user's identifier as asserted by the upstream IdP (for SAML, the
	// value WorkOS maps to idp_id, by default the NameID). It is unique within the
	// connection only.
	IdpID          string `json:"idp_id"`
	ConnectionID   string `json:"connection_id"`
	ConnectionType string `json:"connection_type"`
	OrganizationID string `json:"organization_id"`
	Email          string `json:"email"`
	FirstName      string `json:"first_name"`
	LastName       string `json:"last_name"`
}

// Client implements Authenticator for WorkOS Standalone SSO.
type Client struct {
	cookieClient *internalcookie.Client
	httpClient   *http.Client
	baseURL      string
	apiKey       string
	clientID     string
	redirectURL  string
	loginURL     string
}

// New returns a WorkOS SSO Authenticator. apiKey is the secret API key, used only for
// the code exchange.
func New(cookieClient *internalcookie.Client, apiKey, clientID, redirectURL string) *Client {
	return &Client{
		cookieClient: cookieClient,
		httpClient:   &http.Client{Timeout: 10 * time.Second},
		baseURL:      DefaultBaseURL,
		apiKey:       apiKey,
		clientID:     clientID,
		redirectURL:  redirectURL,
	}
}

// SetBaseURL sets the WorkOS API base URL. (default: https://api.workos.com)
func (c *Client) SetBaseURL(u string) {
	c.baseURL = strings.TrimSuffix(u, "/")
}

// SetLoginURL sets the URL a refused or pending login is sent to.
func (c *Client) SetLoginURL(u string) {
	c.loginURL = u
}

// LoginURL returns the URL a refused or pending login is sent to. (default: /login)
func (c *Client) LoginURL() string {
	if c.loginURL == "" {
		return defaultLoginURL
	}

	return c.loginURL
}

// AuthorizationURL returns the URL that starts SSO for the given WorkOS organization ID,
// after writing the state cookie (OIDC-workos) that binds the callback to this browser.
func (c *Client) AuthorizationURL(_ context.Context, w http.ResponseWriter, organization, returnURL string) (string, error) {
	if strings.TrimSpace(organization) == "" {
		return "", httpio.NewBadRequestMessage("organization is required")
	}

	// A random state protects the callback against CSRF.
	state, err := uuid.NewV4()
	if err != nil {
		return "", errors.Wrap(err, "uuid.NewV4()")
	}

	cval := cookie.NewValues().
		SetString(internalcookie.OIDCState, state.String()).
		SetString(internalcookie.ReturnURL, returnURL)

	c.cookieClient.WriteStateCookie(w, internalcookie.WorkOSStateCookieName, cval)

	q := url.Values{}
	q.Set("client_id", c.clientID)
	q.Set("redirect_uri", c.redirectURL)
	q.Set("response_type", "code")
	q.Set("organization", organization)
	q.Set("state", state.String())

	return c.baseURL + "/sso/authorize?" + q.Encode(), nil
}

// Verify validates the SSO callback request and exchanges its code for the user's
// profile. Every failure is a sessioninfo.LoginRefusal. It returns the sanitized URL to
// send the browser to after sign-in, the decoded profile, and the raw profile JSON
// exactly as WorkOS returned it (including raw_attributes).
func (c *Client) Verify(ctx context.Context, w http.ResponseWriter, r *http.Request) (returnURL string, profile *Profile, rawProfile json.RawMessage, err error) {
	cval, cookieName, err := c.cookieClient.ReadStateCookie(r, internalcookie.WorkOSStateCookieName)
	if err != nil {
		return "", nil, nil, errors.Wrap(err, "cookie.Client.ReadStateCookie()")
	}
	if cookieName == "" {
		return "", nil, nil, sessioninfo.NewLoginRefusal(sessioninfo.RefusedNoOIDCCookie, httpio.NewForbiddenMessage("No SSO cookie"))
	}
	c.cookieClient.DeleteStateCookie(w, cookieName)

	returnURL, _ = cval.GetString(internalcookie.ReturnURL)
	returnURL = internalcookie.SanitizeReturnURL(returnURL)

	state, err := cval.GetString(internalcookie.OIDCState)
	if err != nil || state == "" || r.URL.Query().Get("state") != state {
		return "", nil, nil, sessioninfo.NewLoginRefusal(sessioninfo.RefusedInvalidState, httpio.NewForbiddenMessage("Invalid 'state' parameter value"))
	}

	// WorkOS reports a failed or canceled upstream sign-in on the callback itself.
	if e := r.URL.Query().Get("error"); e != "" {
		return "", nil, nil, sessioninfo.NewLoginRefusal(sessioninfo.RefusedTokenExchange,
			httpio.NewUnauthorizedMessageWithError(errors.Newf("%s: %s", e, r.URL.Query().Get("error_description")), "SSO failed"))
	}

	code := r.URL.Query().Get("code")
	if code == "" {
		return "", nil, nil, sessioninfo.NewLoginRefusal(sessioninfo.RefusedTokenExchange, httpio.NewBadRequestMessage("Missing 'code' parameter"))
	}

	rawProfile, err = c.exchange(ctx, code)
	if err != nil {
		return "", nil, nil, sessioninfo.NewLoginRefusal(sessioninfo.RefusedTokenExchange, err)
	}

	profile = &Profile{}
	if err := json.Unmarshal(rawProfile, profile); err != nil {
		return "", nil, nil, sessioninfo.NewLoginRefusal(sessioninfo.RefusedClaimsParse, httpio.NewInternalServerErrorMessageWithError(err, "Failed to parse SSO profile"))
	}
	if profile.ConnectionID == "" || profile.IdpID == "" {
		return "", nil, nil, sessioninfo.NewLoginRefusal(sessioninfo.RefusedClaimsParse, httpio.NewInternalServerErrorMessage("SSO profile is missing connection_id or idp_id"))
	}

	return returnURL, profile, rawProfile, nil
}

// tokenRequest is the body of POST /sso/token.
type tokenRequest struct {
	ClientID     string `json:"client_id"`
	ClientSecret string `json:"client_secret"`
	GrantType    string `json:"grant_type"`
	Code         string `json:"code"`
}

// exchange trades the authorization code for the profile, returning the raw profile JSON.
func (c *Client) exchange(ctx context.Context, code string) (json.RawMessage, error) {
	// The API key travels in the body over TLS to WorkOS: that is how the exchange
	// authenticates.
	body, err := json.Marshal(tokenRequest{ClientID: c.clientID, ClientSecret: c.apiKey, GrantType: "authorization_code", Code: code}) //nolint:gosec // G117: the exchange's credential, sent only to WorkOS
	if err != nil {
		return nil, errors.Wrap(err, "json.Marshal()")
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.baseURL+"/sso/token", bytes.NewReader(body))
	if err != nil {
		return nil, errors.Wrap(err, "http.NewRequestWithContext()")
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json")

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, httpio.NewInternalServerErrorMessageWithError(err, "Failed to exchange code")
	}
	defer resp.Body.Close()

	respBody, err := io.ReadAll(io.LimitReader(resp.Body, maxProfileBytes))
	if err != nil {
		return nil, httpio.NewInternalServerErrorMessageWithError(err, "Failed to read token response")
	}
	if resp.StatusCode != http.StatusOK {
		return nil, httpio.NewInternalServerErrorMessageWithError(errors.Newf("status %d: %s", resp.StatusCode, bytes.TrimSpace(respBody)), "Failed to exchange code")
	}

	var tokenResp struct {
		Profile json.RawMessage `json:"profile"`
	}
	if err := json.Unmarshal(respBody, &tokenResp); err != nil {
		return nil, httpio.NewInternalServerErrorMessageWithError(err, "Failed to parse token response")
	}
	if len(tokenResp.Profile) == 0 || string(tokenResp.Profile) == "null" {
		return nil, httpio.NewInternalServerErrorMessage("No profile in token response")
	}

	return tokenResp.Profile, nil
}
