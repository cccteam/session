// Package types defines common types and constants used across the session package.
package types

import (
	"context"
	"net/http"
	"time"

	"github.com/cccteam/ccc"
	"github.com/cccteam/logger"
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
	STSessionID STKey = "sessionid"

	// STTokenExpiration is the key used to store the cookie expiration in the Secure Token Cookie
	STTokenExpiration STKey = "expiration"

	// XSRFCookieLife is constant controlling XSRF Cookie expiration
	XSRFCookieLife = time.Hour

	// XSRFReWriteWindow controls rewriting xsrf cookie token if it expires within duration
	XSRFReWriteWindow = 30 * time.Minute

	// CTXSessionID is the key for storing SessionID in context
	CTXSessionID CTXKey = "sessionID"
)

type (
	// SCKey is a type for storing values in the session cookie
	SCKey string

	// STKey is a type for storing values in the secure token cookie
	STKey string

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

// SessionIDFromRequest returns the sessionID from the request
func SessionIDFromRequest(r *http.Request) ccc.UUID {
	return SessionIDFromCtx(r.Context())
}

// SessionIDFromCtx returns the sessionID from the request context
func SessionIDFromCtx(ctx context.Context) ccc.UUID {
	id, ok := ctx.Value(CTXSessionID).(ccc.UUID)
	if !ok {
		logger.FromCtx(ctx).Errorf("failed to find %s in request context", CTXSessionID)
	}

	return id
}

// ValidSessionID checks that the sessionID is a valid uuid
func ValidSessionID(sessionID string) (ccc.UUID, bool) {
	sessionUUID, err := ccc.UUIDFromString(sessionID)
	if err != nil {
		return ccc.NilUUID, false
	}

	return sessionUUID, true
}
