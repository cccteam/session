package types

import (
	"context"
	"net/http"
	"time"

	"github.com/cccteam/ccc"
	"github.com/cccteam/logger"
)

const (
	// Keys used within the Secure Cookie
	SCAuthCookieName SCKey = "auth"
	SCSessionID      SCKey = "sessionID"
	SCSameSiteStrict SCKey = "sameSiteStrict"

	STCookieName = "XSRF-TOKEN"
	STHeaderName = "X-XSRF-TOKEN"

	// Keys used in Secure Token Cookie
	STSessionID       STKey = "sessionid"
	STTokenExpiration STKey = "expiration"

	XSRFCookieLife = time.Hour

	// rewrite xsrf cookie token if it expires within duration
	XSRFReWriteWindow = 30 * time.Minute

	// Keys used within the request Context
	CTXSessionID CTXKey = "sessionID"
)

type (
	// SCKey is a type for storing values in the session cookie
	SCKey string

	STKey string

	// ctxKey is a type for storing values in the request context
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

func SessionIDFromRequest(r *http.Request) ccc.UUID {
	return SessionIDFromCtx(r.Context())
}

func SessionIDFromCtx(ctx context.Context) ccc.UUID {
	id, ok := ctx.Value(CTXSessionID).(ccc.UUID)
	if !ok {
		logger.Ctx(ctx).Errorf("failed to find %s in request context", CTXSessionID)
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
