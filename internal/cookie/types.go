package cookie

import (
	"slices"
	"time"

	"github.com/cccteam/ccc"
	"github.com/cccteam/session/cookie"
)

const (
	// SessionID is the key used to store the SessionID in a Secure Cookie
	SessionID cookie.Key = "sessionID"

	// SameSiteStrict is the key used to store the sameSiteStrict cookie setting
	SameSiteStrict cookie.Key = "sameSiteStrict"

	// OIDCState is the key used to store the state
	OIDCState cookie.Key = "state"

	// OIDCPkceVerifier is the key used to store the PKCE verifier
	OIDCPkceVerifier cookie.Key = "pkceVerifier"

	// ReturnURL is the key used to store the return URL
	ReturnURL cookie.Key = "returnURL"
)

const (
	// AuthCookieName is the cookie name of the Secure Cookie
	AuthCookieName = "auth"

	// XSRFCookieName is the cookie name of the XSRF Token Cookie
	XSRFCookieName = "XSRF-TOKEN"

	// OIDCCookieName is the cookie name of the OIDC Cookie
	OIDCCookieName = "OIDC"

	// XSRFHeaderName is the header name of the XSRF Token Cookie
	XSRFHeaderName = "X-XSRF-TOKEN"

	// OIDCCookieExpiration is the default expiration for the OIDC Cookie
	OIDCCookieExpiration = 10 * time.Minute
)

// SafeMethods are Idempotent methods as defined by RFC7231 section 4.2.2.
var SafeMethods = methods([]string{"GET", "HEAD", "OPTIONS", "TRACE"})

type methods []string

func (vals methods) Contain(s string) bool {
	return slices.Contains(vals, s)
}

// ValidSessionID checks that the sessionID is a valid uuid
func ValidSessionID(sessionID string) (ccc.UUID, bool) {
	sessionUUID, err := ccc.UUIDFromString(sessionID)
	if err != nil {
		return ccc.NilUUID, false
	}

	return sessionUUID, true
}
