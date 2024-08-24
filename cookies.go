package session

import (
	"net/http"
	"strconv"
	"time"

	"github.com/cccteam/ccc"
	"github.com/cccteam/logger"
	"github.com/go-playground/errors/v5"
	"github.com/gorilla/securecookie"
)

// scKey is a type for storing values in the session cookie
type scKey string

func (c scKey) String() string {
	return string(c)
}

const (
	// Keys used within the Secure Cookie
	scAuthCookieName scKey = "auth"
	scSessionID      scKey = "sessionID"
	scSameSiteStrict scKey = "sameSiteStrict"
)

// Interface included for testability
type cookieManager interface {
	newAuthCookie(w http.ResponseWriter, sameSiteStrict bool, sessionID ccc.UUID) (map[scKey]string, error)
	readAuthCookie(r *http.Request) (map[scKey]string, bool)
	writeAuthCookie(w http.ResponseWriter, sameSiteStrict bool, cval map[scKey]string) error
	setXSRFTokenCookie(w http.ResponseWriter, r *http.Request, sessionID ccc.UUID, cookieExpiration time.Duration) (set bool)
	hasValidXSRFToken(r *http.Request) bool
}

var _ cookieManager = &cookieClient{}

type cookieClient struct {
	secureCookie *securecookie.SecureCookie
}

func newCookieClient(secureCookie *securecookie.SecureCookie) *cookieClient {
	return &cookieClient{
		secureCookie: secureCookie,
	}
}

func (c *cookieClient) newAuthCookie(w http.ResponseWriter, sameSiteStrict bool, sessionID ccc.UUID) (map[scKey]string, error) {
	// Update cookie
	cval := map[scKey]string{
		scSessionID: sessionID.String(),
	}

	if err := c.writeAuthCookie(w, sameSiteStrict, cval); err != nil {
		return nil, errors.Wrap(err, "")
	}

	return cval, nil
}

func (c *cookieClient) readAuthCookie(r *http.Request) (map[scKey]string, bool) {
	cval := make(map[scKey]string)

	cookie, err := r.Cookie(scAuthCookieName.String())
	if err != nil {
		return cval, false
	}
	err = c.secureCookie.Decode(scAuthCookieName.String(), cookie.Value, &cval)
	if err != nil {
		logger.Req(r).Error(errors.Wrap(err, "secureCookie.Decode()"))

		return cval, false
	}

	return cval, true
}

func (c *cookieClient) writeAuthCookie(w http.ResponseWriter, sameSiteStrict bool, cval map[scKey]string) error {
	cval[scSameSiteStrict] = strconv.FormatBool(sameSiteStrict)
	encoded, err := c.secureCookie.Encode(scAuthCookieName.String(), cval)
	if err != nil {
		return errors.Wrap(err, "securecookie.Encode()")
	}

	sameSite := http.SameSiteStrictMode
	if !sameSiteStrict {
		sameSite = http.SameSiteNoneMode
	}

	http.SetCookie(w, &http.Cookie{
		Name:     scAuthCookieName.String(),
		Value:    encoded,
		Path:     "/",
		Secure:   true,
		HttpOnly: true,
		SameSite: sameSite,
	})

	return nil
}

// setXSRFTokenCookie sets the cookie if it does not exist and updates the cookie when it is close to expiration.
func (c *cookieClient) setXSRFTokenCookie(w http.ResponseWriter, r *http.Request, sessionID ccc.UUID, cookieExpiration time.Duration) (set bool) {
	cval, found := c.readXSRFCookie(r)
	sessionMatch := sessionID.String() == cval[stSessionID]
	if found {
		exp, err := time.Parse(time.UnixDate, cval[stTokenExpiration])
		if err != nil {
			logger.Req(r).Error("parsing expiration")
		} else if time.Now().Before(exp.Add(-xsrfReWriteWindow)) && sessionMatch {
			return false
		}
	}

	cval = map[stKey]string{
		stSessionID:       sessionID.String(),
		stTokenExpiration: time.Now().Add(cookieExpiration).Format(time.UnixDate),
	}

	if err := c.writeXSRFCookie(w, cookieExpiration, cval); err != nil {
		logger.Req(r).Error("writeXSRFCookie()")

		return false
	}

	return true
}

func (c *cookieClient) hasValidXSRFToken(r *http.Request) bool {
	cval, found := c.readXSRFCookie(r)
	if !found {
		return false
	}
	exp, err := time.Parse(time.UnixDate, cval[stTokenExpiration])
	if err != nil {
		logger.Req(r).Error("parsing expiration")

		return false
	}
	if time.Now().After(exp) {
		return false
	}
	if sessionIDFromRequest(r).String() != cval[stSessionID] {
		return false
	}
	hval, found := c.readXSRFHeader(r)
	if !found {
		return false
	}

	return hval[stSessionID] == cval[stSessionID]
}

func (c *cookieClient) writeXSRFCookie(w http.ResponseWriter, cookieExpiration time.Duration, cval map[stKey]string) error {
	encoded, err := c.secureCookie.Encode(stCookieName, cval)
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

	cval := make(map[stKey]string)
	err = c.secureCookie.Decode(stCookieName, cookie.Value, &cval)
	if err != nil {
		logger.Req(r).Error("securecookie.Decode()")

		return nil, false
	}

	return cval, true
}

func (c *cookieClient) readXSRFHeader(r *http.Request) (map[stKey]string, bool) {
	h := r.Header.Get(stHeaderName)
	cval := make(map[stKey]string)
	err := c.secureCookie.Decode(stCookieName, h, &cval)
	if err != nil {
		logger.Req(r).Error("securecookie.Decode()")

		return nil, false
	}

	return cval, true
}
