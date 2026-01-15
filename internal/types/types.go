// Package types defines common types and constants used across the session package.
package types

import (
	"time"

	"github.com/cccteam/ccc"
)

const (
	// SCAuthCookieName is the cookie name of the Secure Cookie
	SCAuthCookieName SCKey = "auth"

	// SCSessionID is the key for storing SessionID in Secure Cookie
	SCSessionID SCKey = "sessionID"

	// SCSameSiteStrict is a key representing sameSiteStrict cookie setting
	SCSameSiteStrict SCKey = "sameSiteStrict"

	// STCookieName is the cookie name of the Secure Token Cookie
	STCookieName = "XSRF-TOKEN"

	// STHeaderName is the header name of the Secure Token Cookie
	STHeaderName = "X-XSRF-TOKEN"

	// STSessionID is the key used in store sessionID in Secure Token Cookie
	STSessionID SCKey = "sessionid"

	// STState is that state key name
	STState SCKey = "state"

	// STPkceVerifier is the PKCE verifier key name
	STPkceVerifier SCKey = "pkceVerifier"

	// STReturnURL is the return URL key name
	STReturnURL SCKey = "returnURL"

	// STOIDCCookieName is the cookie name of the OIDC Cookie
	STOIDCCookieName = "OIDC"

	// OIDCCookieExpiration is the default expiration for the OIDC Cookie
	OIDCCookieExpiration = 10 * time.Minute

	// CTXSessionID is the key for storing SessionID in context
	CTXSessionID CTXKey = "sessionID"
)

type (
	// SCKey is a type for storing values in the session cookie
	SCKey string

	// CTXKey is a type for storing values in the request context
	CTXKey string
)

// SafeMethods are Idempotent methods as defined by RFC7231 section 4.2.2.
var SafeMethods = methods([]string{"GET", "HEAD", "OPTIONS", "TRACE"})

type methods []string

func (vals methods) Contain(s string) bool {
	for _, v := range vals {
		if v == s {
			return true
		}
	}

	return false
}

// ValidSessionID checks that the sessionID is a valid uuid
func ValidSessionID(sessionID string) (ccc.UUID, bool) {
	sessionUUID, err := ccc.UUIDFromString(sessionID)
	if err != nil {
		return ccc.NilUUID, false
	}

	return sessionUUID, true
}
