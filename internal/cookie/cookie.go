// Package cookie implements all cookie handling for the session package
package cookie

import (
	"net/http"
	"strconv"
	"time"

	"github.com/cccteam/ccc"
	"github.com/cccteam/logger"
	"github.com/cccteam/session/internal/types"
	"github.com/cccteam/session/sessioninfo"
	"github.com/go-playground/errors/v5"
	"github.com/gorilla/securecookie"
)

var _ CookieHandler = &CookieClient{}

// CookieClient implements all cookie management for session package
type CookieClient struct {
	secureCookie *securecookie.SecureCookie
	CookieName   string
	STCookieName string
	STHeaderName string
	Domain       string
}

// NewCookieClient returns a new CookieClient
func NewCookieClient(secureCookie *securecookie.SecureCookie) *CookieClient {
	cookie := &CookieClient{
		secureCookie: secureCookie,
		CookieName:   string(types.SCAuthCookieName),
		STCookieName: types.STCookieName,
		STHeaderName: types.STHeaderName,
	}

	return cookie
}

// NewAuthCookie writes a new Auth Cookie for given sessionID
func (c *CookieClient) NewAuthCookie(w http.ResponseWriter, sameSiteStrict bool, sessionID ccc.UUID) (map[types.SCKey]string, error) {
	// Update cookie
	cval := map[types.SCKey]string{
		types.SCSessionID: sessionID.String(),
	}

	if err := c.WriteAuthCookie(w, sameSiteStrict, cval); err != nil {
		return nil, errors.Wrap(err, "CookieClient.WriteAuthCookie()")
	}

	return cval, nil
}

// ReadAuthCookie reads the Auth cookie from the request
func (c *CookieClient) ReadAuthCookie(r *http.Request) (map[types.SCKey]string, bool) {
	cval := make(map[types.SCKey]string)

	cookie, err := r.Cookie(c.CookieName)
	if err != nil {
		return cval, false
	}
	err = c.secureCookie.Decode(c.CookieName, cookie.Value, &cval)
	if err != nil {
		logger.FromReq(r).Error(errors.Wrap(err, "secureCookie.Decode()"))

		return cval, false
	}

	return cval, true
}

// WriteAuthCookie writes the Auth cookie to the response
func (c *CookieClient) WriteAuthCookie(w http.ResponseWriter, sameSiteStrict bool, cval map[types.SCKey]string) error {
	cval[types.SCSameSiteStrict] = strconv.FormatBool(sameSiteStrict)
	encoded, err := c.secureCookie.Encode(c.CookieName, cval)
	if err != nil {
		return errors.Wrap(err, "securecookie.Encode()")
	}

	sameSite := http.SameSiteStrictMode
	if !sameSiteStrict {
		sameSite = http.SameSiteNoneMode
	}

	http.SetCookie(w, &http.Cookie{
		Name:     c.CookieName,
		Value:    encoded,
		Path:     "/",
		Domain:   c.Domain,
		Secure:   secureCookie(),
		HttpOnly: true,
		SameSite: sameSite,
	})

	return nil
}

// RefreshXSRFTokenCookie updates the cookie when it is close to expiration, or sets it if it does not exist.
func (c *CookieClient) RefreshXSRFTokenCookie(w http.ResponseWriter, r *http.Request, sessionID ccc.UUID, cookieExpiration time.Duration) (set bool, err error) {
	cval, found := c.ReadXSRFCookie(r)
	sessionMatch := sessionID.String() == cval[types.STSessionID]
	if found {
		exp, err := time.Parse(time.UnixDate, cval[types.STTokenExpiration])
		if err != nil {
			logger.FromReq(r).Error(errors.Wrap(err, "failed to parse expiration"))
		} else if time.Now().Before(exp.Add(-types.XSRFReWriteWindow)) && sessionMatch {
			return false, nil
		}
	}

	if err := c.CreateXSRFTokenCookie(w, sessionID, cookieExpiration); err != nil {
		return false, errors.Wrap(err, "SetXSRFTokenCookie()")
	}

	return true, nil
}

// CreateXSRFTokenCookie sets a new cookie
func (c *CookieClient) CreateXSRFTokenCookie(w http.ResponseWriter, sessionID ccc.UUID, cookieExpiration time.Duration) error {
	cval := map[types.STKey]string{
		types.STSessionID:       sessionID.String(),
		types.STTokenExpiration: time.Now().Add(cookieExpiration).Format(time.UnixDate),
	}

	if err := c.WriteXSRFCookie(w, cookieExpiration, cval); err != nil {
		return errors.Wrap(err, "CookieClient.WriteXSRFCookie()")
	}

	return nil
}

// HasValidXSRFToken checks if the XSRF token is valid
func (c *CookieClient) HasValidXSRFToken(r *http.Request) bool {
	cval, found := c.ReadXSRFCookie(r)
	if !found {
		return false
	}
	exp, err := time.Parse(time.UnixDate, cval[types.STTokenExpiration])
	if err != nil {
		logger.FromReq(r).Error(errors.Wrap(err, "failed to parse expiration"))

		return false
	}
	if time.Now().After(exp) {
		return false
	}
	if sessioninfo.IDFromRequest(r).String() != cval[types.STSessionID] {
		return false
	}
	hval, found := c.ReadXSRFHeader(r)
	if !found {
		return false
	}

	return hval[types.STSessionID] == cval[types.STSessionID]
}

// WriteXSRFCookie writes the XSRF cookie to the response
func (c *CookieClient) WriteXSRFCookie(w http.ResponseWriter, cookieExpiration time.Duration, cval map[types.STKey]string) error {
	encoded, err := c.secureCookie.Encode(c.STCookieName, cval)
	if err != nil {
		return errors.Wrap(err, "securecookie.Encode()")
	}

	http.SetCookie(w, &http.Cookie{
		Name:     c.STCookieName,
		Expires:  time.Now().Add(cookieExpiration),
		Value:    encoded,
		Path:     "/",
		Secure:   secureCookie(),
		SameSite: http.SameSiteStrictMode,
	})

	return nil
}

// ReadXSRFCookie reads the XSRF cookie from the request
func (c *CookieClient) ReadXSRFCookie(r *http.Request) (map[types.STKey]string, bool) {
	cookie, err := r.Cookie(c.STCookieName)
	if err != nil {
		return nil, false
	}

	cval := make(map[types.STKey]string)
	if err := c.secureCookie.Decode(c.STCookieName, cookie.Value, &cval); err != nil {
		logger.FromReq(r).Error(errors.Wrap(err, "securecookie.Decode()"))

		return nil, false
	}

	return cval, true
}

// ReadXSRFHeader reads the XSRF header from the request
func (c *CookieClient) ReadXSRFHeader(r *http.Request) (map[types.STKey]string, bool) {
	h := r.Header.Get(c.STHeaderName)
	cval := make(map[types.STKey]string)
	err := c.secureCookie.Decode(c.STCookieName, h, &cval)
	if err != nil {
		logger.FromReq(r).Error(errors.Wrap(err, "securecookie.Decode()"))

		return nil, false
	}

	return cval, true
}
