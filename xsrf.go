package session

import (
	"net/http"
	"time"

	"github.com/cccteam/httpio"
)

type stKey string

func (c stKey) String() string {
	return string(c)
}

const (
	stCookieName = "XSRF-TOKEN"
	stHeaderName = "X-XSRF-TOKEN"
	// Keys used in Secure Token Cookie
	stSessionID       stKey = "sessionid"
	stTokenExpiration stKey = "expiration"

	xsrfCookieLife = time.Hour

	// rewrite xsrf cookie token if it expires within duration
	xsrfReWriteWindow = 30 * time.Minute
)

// safeMethods are Idempotent methods as defined by RFC7231 section 4.2.2.
var safeMethods = methods([]string{"GET", "HEAD", "OPTIONS", "TRACE"})

type methods []string

func (vals methods) contain(s string) bool {
	for _, v := range vals {
		if v == s {
			return true
		}
	}

	return false
}

// SetXSRFToken sets the XSRF Token
func (s *session) SetXSRFToken(next http.Handler) http.Handler {
	return s.handle(func(w http.ResponseWriter, r *http.Request) error {
		if s.setXSRFTokenCookie(w, r, sessionIDFromRequest(r), xsrfCookieLife) && !safeMethods.contain(r.Method) {
			// Cookie was not present and request requires XSRF Token, so
			// redirect request to try again now that the XSRF Token Cookie is set
			http.Redirect(w, r, r.RequestURI, http.StatusTemporaryRedirect)

			return nil
		}

		next.ServeHTTP(w, r)

		return nil
	})
}

// ValidateXSRFToken validates the XSRF Token
func (s *session) ValidateXSRFToken(next http.Handler) http.Handler {
	return s.handle(func(w http.ResponseWriter, r *http.Request) error {
		// Validate XSRFToken for non-safe
		if !safeMethods.contain(r.Method) && !s.hasValidXSRFToken(r) {
			// Token validation failed
			return httpio.NewEncoder(w).ClientMessage(r.Context(), httpio.NewForbiddenMessage("invalid XSRF token"))
		}

		next.ServeHTTP(w, r)

		return nil
	})
}
