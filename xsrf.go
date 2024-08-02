package session

import (
	"net/http"
	"time"

	"github.com/cccteam/httpio"
	"github.com/cccteam/logger"
	"github.com/go-playground/errors/v5"
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
func (s *Session) SetXSRFToken(next http.Handler) http.Handler {
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
func (s *Session) ValidateXSRFToken(next http.Handler) http.Handler {
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

// setXSRFTokenCookie sets the cookie if it does not exist and updates the cookie when it is close to expiration.
func (c *cookieClient) setXSRFTokenCookie(w http.ResponseWriter, r *http.Request, sessionID string, cookieExpiration time.Duration) (set bool) {
	cookieValue, found := c.readXSRFCookie(r)
	sessionMatch := sessionID == cookieValue[stSessionID]
	if found {
		exp, err := time.Parse(time.UnixDate, cookieValue[stTokenExpiration])
		if err != nil {
			logger.Req(r).Error("parsing expiration")
		} else if time.Now().Before(exp.Add(-xsrfReWriteWindow)) && sessionMatch {
			return false
		}
	}

	cookieValue = map[stKey]string{
		stSessionID:       sessionID,
		stTokenExpiration: time.Now().Add(cookieExpiration).Format(time.UnixDate),
	}

	if err := c.writeXSRFCookie(w, cookieExpiration, cookieValue); err != nil {
		logger.Req(r).Error("writeXSRFCookie()")

		return false
	}

	return true
}

func (c *cookieClient) hasValidXSRFToken(r *http.Request) bool {
	cookieValue, found := c.readXSRFCookie(r)
	if !found {
		return false
	}
	exp, err := time.Parse(time.UnixDate, cookieValue[stTokenExpiration])
	if err != nil {
		logger.Req(r).Error("parsing expiration")

		return false
	}
	if time.Now().After(exp) {
		return false
	}
	if sessionIDFromRequest(r) != cookieValue[stSessionID] {
		return false
	}
	hval, found := c.readXSRFHeader(r)
	if !found {
		return false
	}

	return hval[stSessionID] == cookieValue[stSessionID]
}

func (c *cookieClient) writeXSRFCookie(w http.ResponseWriter, cookieExpiration time.Duration, cookieValue map[stKey]string) error {
	encoded, err := c.secureCookie.Encode(stCookieName, cookieValue)
	if err != nil {
		return errors.Wrap(err, "securecookie.Encode()")
	}

	http.SetCookie(w, &http.Cookie{
		Name:    stCookieName,
		Expires: time.Now().Add(cookieExpiration),
		Value:   encoded,
		Path:    "/",
		Secure:  true,
	})

	return nil
}

func (c *cookieClient) readXSRFCookie(r *http.Request) (map[stKey]string, bool) {
	cookie, err := r.Cookie(stCookieName)
	if err != nil {
		return nil, false
	}

	cookieValue := make(map[stKey]string)
	err = c.secureCookie.Decode(stCookieName, cookie.Value, &cookieValue)
	if err != nil {
		logger.Req(r).Error("securecookie.Decode()")

		return nil, false
	}

	return cookieValue, true
}

func (c *cookieClient) readXSRFHeader(r *http.Request) (map[stKey]string, bool) {
	h := r.Header.Get(stHeaderName)
	cookieValue := make(map[stKey]string)
	err := c.secureCookie.Decode(stCookieName, h, &cookieValue)
	if err != nil {
		logger.Req(r).Error("securecookie.Decode()")

		return nil, false
	}

	return cookieValue, true
}
