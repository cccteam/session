//go:build skipAuth

package oidc

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

var _ Authenticator = &Verifier{}

// simulatedSubjectPrefix is what the simulated sub claim starts with: the username
// follows, so each simulated user has one durable identity under the provider.
const simulatedSubjectPrefix = "skipauth-"

// Verifier is the generic method's Authenticator in the simulated build, where
// authentication is skipped for development: no provider is reached, and the callback
// signs in the person the environment names.
type Verifier struct {
	issuer      string
	redirectURL string
	cookies     signin.StateCookies
	loginURL    string
	// registration names the registration the simulated sign-in serves, which selects
	// the environment it reads the person and their roles from (internal/simulated).
	registration string
}

// NewVerifier returns the simulated verifier. The issuer is kept so the simulated
// claims name it, as a verified token's iss would; the client and the scopes are
// accepted and unused.
func NewVerifier(cookies signin.StateCookies, issuer, _, _, redirectURL string, _ []string) *Verifier {
	return &Verifier{issuer: issuer, redirectURL: redirectURL, cookies: cookies}
}

// SetLoginURL sets where refused and pending sign-ins are sent.
func (v *Verifier) SetLoginURL(url string) {
	v.loginURL = url
}

// simulateAs names the registration this simulated sign-in serves: it signs in
// APP_<NAME>_USERNAME in the roles APP_<NAME>_ROLES names when the variables are set,
// APP_USERNAME and APP_ROLES otherwise.
func (v *Verifier) simulateAs(registration string) {
	v.registration = registration
}

// LoginURL is where refused and pending sign-ins are sent.
func (v *Verifier) LoginURL() string {
	if v.loginURL == "" {
		return defaultLoginURL
	}

	return v.loginURL
}

// AuthCodeURL writes the state cookie and sends the browser straight to the callback:
// no provider is asked. The login options are accepted and unused: nothing is chosen.
func (v *Verifier) AuthCodeURL(_ context.Context, w http.ResponseWriter, returnURL string, _ signin.LoginOptions) (string, error) {
	v.cookies.WriteStateCookie(w, cookie.NewValues().SetString(internalcookie.ReturnURL, returnURL))

	return v.redirectURL, nil
}

// Verify populates claims with simulated ID token claims and returns the path the
// browser goes to next. The claims carry the registration's username as the preferred
// username, the email (verified) and the name, the roles its roles variable names, the
// registration's issuer, and a sub derived from the username, so repeated logins
// resolve to one identity.
func (v *Verifier) Verify(_ context.Context, w http.ResponseWriter, r *http.Request, claims any) (string, error) {
	username := simulated.Username(v.registration)
	simulatedClaims := map[string]any{
		"iss": v.issuer, "sub": simulatedSubjectPrefix + username, "email": username, "email_verified": true,
		"preferred_username": username, "name": username, "roles": simulated.Roles(v.registration),
	}
	raw, err := json.Marshal(simulatedClaims)
	if err != nil {
		return "", errors.Wrap(err, "json.Marshal()")
	}
	if err := json.Unmarshal(raw, claims); err != nil {
		return "", errors.Wrap(err, "json.Unmarshal()")
	}

	cval, cookieName, err := v.cookies.ReadStateCookie(r)
	if err != nil {
		return "", errors.Wrap(err, "signin.StateCookies.ReadStateCookie()")
	}
	if cookieName == "" {
		return "", sessioninfo.NewLoginRefusal(sessioninfo.RefusedNoOIDCCookie, httpio.NewForbiddenMessage("No OIDC cookie"))
	}
	v.cookies.DeleteStateCookie(w, cookieName)

	returnURL, _ := cval.GetString(internalcookie.ReturnURL)

	return internalcookie.SanitizeReturnURL(returnURL), nil
}
