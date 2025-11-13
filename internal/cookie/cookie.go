package cookie

import (
	"net/http"
	"strconv"
	"time"

	"github.com/cccteam/ccc"
	"github.com/cccteam/logger"
	"github.com/cccteam/session/internal/types"
	"github.com/go-playground/errors/v5"
	"github.com/gorilla/securecookie"
)

var _ CookieManager = &CookieClient{}

type CookieClient struct {
	secureCookie *securecookie.SecureCookie
	cookieName   string
	domain       string
}

func NewCookieClient(secureCookie *securecookie.SecureCookie, options ...CookieOption) *CookieClient {
	cookie := &CookieClient{
		secureCookie: secureCookie,
		cookieName:   string(types.SCAuthCookieName),
	}
	for _, opt := range options {
		opt(cookie)
	}

	return cookie
}

func (c *CookieClient) NewAuthCookie(w http.ResponseWriter, sameSiteStrict bool, sessionID ccc.UUID) (map[types.SCKey]string, error) {
	// Update cookie
	cval := map[types.SCKey]string{
		types.SCSessionID: sessionID.String(),
	}

	if err := c.WriteAuthCookie(w, sameSiteStrict, cval); err != nil {
		return nil, errors.Wrap(err, "")
	}

	return cval, nil
}

func (c *CookieClient) ReadAuthCookie(r *http.Request) (map[types.SCKey]string, bool) {
	cval := make(map[types.SCKey]string)

	cookie, err := r.Cookie(c.cookieName)
	if err != nil {
		return cval, false
	}
	err = c.secureCookie.Decode(c.cookieName, cookie.Value, &cval)
	if err != nil {
		logger.Req(r).Error(errors.Wrap(err, "secureCookie.Decode()"))

		return cval, false
	}

	return cval, true
}

func (c *CookieClient) WriteAuthCookie(w http.ResponseWriter, sameSiteStrict bool, cval map[types.SCKey]string) error {
	cval[types.SCSameSiteStrict] = strconv.FormatBool(sameSiteStrict)
	encoded, err := c.secureCookie.Encode(c.cookieName, cval)
	if err != nil {
		return errors.Wrap(err, "securecookie.Encode()")
	}

	sameSite := http.SameSiteStrictMode
	if !sameSiteStrict {
		sameSite = http.SameSiteNoneMode
	}

	http.SetCookie(w, &http.Cookie{
		Name:     c.cookieName,
		Value:    encoded,
		Path:     "/",
		Domain:   c.domain,
		Secure:   secureCookie(),
		HttpOnly: true,
		SameSite: sameSite,
	})

	return nil
}

// SetXSRFTokenCookie sets the cookie if it does not exist and updates the cookie when it is close to expiration.
func (c *CookieClient) SetXSRFTokenCookie(w http.ResponseWriter, r *http.Request, sessionID ccc.UUID, cookieExpiration time.Duration) (set bool) {
	cval, found := c.ReadXSRFCookie(r)
	sessionMatch := sessionID.String() == cval[types.STSessionID]
	if found {
		exp, err := time.Parse(time.UnixDate, cval[types.STTokenExpiration])
		if err != nil {
			logger.Req(r).Error("parsing expiration")
		} else if time.Now().Before(exp.Add(-types.XSRFReWriteWindow)) && sessionMatch {
			return false
		}
	}

	cval = map[types.STKey]string{
		types.STSessionID:       sessionID.String(),
		types.STTokenExpiration: time.Now().Add(cookieExpiration).Format(time.UnixDate),
	}

	if err := c.WriteXSRFCookie(w, cookieExpiration, cval); err != nil {
		logger.Req(r).Error("WriteXSRFCookie()")

		return false
	}

	return true
}

func (c *CookieClient) HasValidXSRFToken(r *http.Request) bool {
	cval, found := c.ReadXSRFCookie(r)
	if !found {
		return false
	}
	exp, err := time.Parse(time.UnixDate, cval[types.STTokenExpiration])
	if err != nil {
		logger.Req(r).Error("parsing expiration")

		return false
	}
	if time.Now().After(exp) {
		return false
	}
	if types.SessionIDFromRequest(r).String() != cval[types.STSessionID] {
		return false
	}
	hval, found := c.ReadXSRFHeader(r)
	if !found {
		return false
	}

	return hval[types.STSessionID] == cval[types.STSessionID]
}

func (c *CookieClient) WriteXSRFCookie(w http.ResponseWriter, cookieExpiration time.Duration, cval map[types.STKey]string) error {
	encoded, err := c.secureCookie.Encode(types.STCookieName, cval)
	if err != nil {
		return errors.Wrap(err, "securecookie.Encode()")
	}

	http.SetCookie(w, &http.Cookie{
		Name:     types.STCookieName,
		Expires:  time.Now().Add(cookieExpiration),
		Value:    encoded,
		Path:     "/",
		Secure:   secureCookie(),
		SameSite: http.SameSiteStrictMode,
	})

	return nil
}

func (c *CookieClient) ReadXSRFCookie(r *http.Request) (map[types.STKey]string, bool) {
	cookie, err := r.Cookie(types.STCookieName)
	if err != nil {
		return nil, false
	}

	cval := make(map[types.STKey]string)
	err = c.secureCookie.Decode(types.STCookieName, cookie.Value, &cval)
	if err != nil {
		logger.Req(r).Error("securecookie.Decode()")

		return nil, false
	}

	return cval, true
}

func (c *CookieClient) ReadXSRFHeader(r *http.Request) (map[types.STKey]string, bool) {
	h := r.Header.Get(types.STHeaderName)
	cval := make(map[types.STKey]string)
	err := c.secureCookie.Decode(types.STCookieName, h, &cval)
	if err != nil {
		logger.Req(r).Errorf("securecookie.Decode(): %s", err)

		return nil, false
	}

	return cval, true
}
