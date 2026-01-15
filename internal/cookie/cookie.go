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

var _ Handler = &Client{}

// Client implements all cookie management for session package
type Client struct {
	masterKeyBase64 string
	secureCookie    *securecookie.SecureCookie
	*cookieOptions
}

// NewCookieClient returns a new CookieClient
func NewCookieClient(masterKeyBase64 string, opts ...Option) (*Client, error) {
	client := &Client{
		masterKeyBase64: masterKeyBase64,
		cookieOptions: &cookieOptions{
			CookieName:   string(types.SCAuthCookieName),
			STCookieName: types.STCookieName,
			STHeaderName: types.STHeaderName,
		},
	}

	for _, opt := range opts {
		opt(client.cookieOptions)
	}

	secureCookie, err := createSecureCookie(client.masterKeyBase64)
	if err != nil {
		return nil, errors.Wrap(err, "createPasetoKey()")
	}

	client.secureCookie = secureCookie

	return client, nil
}

// NewAuthCookie writes a new Auth Cookie for given sessionID
func (c *Client) NewAuthCookie(w http.ResponseWriter, sameSiteStrict bool, sessionID ccc.UUID) (map[types.SCKey]string, error) {
	cval := map[types.SCKey]string{
		types.SCSessionID: sessionID.String(),
	}

	if err := c.WriteAuthCookie(w, sameSiteStrict, cval); err != nil {
		return nil, errors.Wrap(err, "CookieClient.WriteAuthCookie()")
	}

	return cval, nil
}

// ReadAuthCookie reads the Auth cookie from the request
func (c *Client) ReadAuthCookie(r *http.Request) (params map[types.SCKey]string, found bool, err error) {
	cval := make(map[types.SCKey]string)

	cookie, err := r.Cookie(c.CookieName)
	if err != nil {
		if errors.Is(err, http.ErrNoCookie) {
			return cval, false, nil
		}

		return cval, false, errors.Wrap(err, "http.Request.Cookie()")
	}
	if err := c.secureCookie.Decode(c.CookieName, cookie.Value, &cval); err != nil {
		return cval, false, errors.Wrap(err, "securecookie.SecureCookie.Decode()")
	}

	return cval, true, nil
}

// WriteAuthCookie writes the Auth cookie to the response
func (c *Client) WriteAuthCookie(w http.ResponseWriter, sameSiteStrict bool, cval map[types.SCKey]string) error {
	cval[types.SCSameSiteStrict] = strconv.FormatBool(sameSiteStrict)
	encoded, err := c.secureCookie.Encode(c.CookieName, cval)
	if err != nil {
		return errors.Wrap(err, "securecookie.SecureCookie.Encode()")
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
func (c *Client) RefreshXSRFTokenCookie(w http.ResponseWriter, r *http.Request, sessionID ccc.UUID, cookieExpiration time.Duration) (set bool, err error) {
	cval, found, err := c.ReadXSRFCookie(r)
	if err != nil {
		return false, errors.Wrap(err, "CookieClient.ReadXSRFCookie()")
	}

	sessionMatch := sessionID.String() == cval[types.STSessionID]
	if found {
		exp, err := time.Parse(time.UnixDate, cval[types.STTokenExpiration])
		if err != nil {
			logger.FromReq(r).Error(errors.Wrap(err, "time.Parse(): failed to parse expiration"))
		} else if time.Now().Before(exp.Add(-types.XSRFReWriteWindow)) && sessionMatch {
			return false, nil
		}
	}

	if err := c.CreateXSRFTokenCookie(w, sessionID, cookieExpiration); err != nil {
		return false, errors.Wrap(err, "CookieClient.CreateXSRFTokenCookie()")
	}

	return true, nil
}

// CreateXSRFTokenCookie sets a new cookie
func (c *Client) CreateXSRFTokenCookie(w http.ResponseWriter, sessionID ccc.UUID, cookieExpiration time.Duration) error {
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
func (c *Client) HasValidXSRFToken(r *http.Request) (bool, error) {
	cval, found, err := c.ReadXSRFCookie(r)
	if err != nil {
		return false, errors.Wrap(err, "CookieClient.ReadXSRFCookie()")
	}
	if !found {
		return false, nil
	}
	exp, err := time.Parse(time.UnixDate, cval[types.STTokenExpiration])
	if err != nil {
		return false, errors.Wrap(err, "time.Parse(): failed to parse expiration")
	}
	if time.Now().After(exp) {
		return false, nil
	}
	if sessioninfo.IDFromRequest(r).String() != cval[types.STSessionID] {
		return false, nil
	}
	hval, found, err := c.ReadXSRFHeader(r)
	if err != nil {
		return false, errors.Wrap(err, "CookieClient.ReadXSRFHeader()")
	}
	if !found {
		return false, nil
	}

	return hval[types.STSessionID] == cval[types.STSessionID], nil
}

// WriteXSRFCookie writes the XSRF cookie to the response
func (c *Client) WriteXSRFCookie(w http.ResponseWriter, cookieExpiration time.Duration, cval map[types.STKey]string) error {
	encoded, err := c.secureCookie.Encode(c.STCookieName, cval)
	if err != nil {
		return errors.Wrap(err, "securecookie.SecureCookie.Encode()")
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
func (c *Client) ReadXSRFCookie(r *http.Request) (params map[types.STKey]string, found bool, err error) {
	cval := make(map[types.STKey]string)

	cookie, err := r.Cookie(c.STCookieName)
	if err != nil {
		if errors.Is(err, http.ErrNoCookie) {
			return cval, false, nil
		}

		return cval, false, errors.Wrap(err, "http.Request.Cookie()")
	}

	if err := c.secureCookie.Decode(c.STCookieName, cookie.Value, &cval); err != nil {
		return cval, false, errors.Wrap(err, "securecookie.SecureCookie.Decode()")
	}

	return cval, true, nil
}

// ReadXSRFHeader reads the XSRF header from the request
func (c *Client) ReadXSRFHeader(r *http.Request) (params map[types.STKey]string, found bool, err error) {
	h := r.Header.Get(c.STHeaderName)
	cval := make(map[types.STKey]string)

	if err := c.secureCookie.Decode(c.STCookieName, h, &cval); err != nil {
		return nil, false, errors.Wrap(err, "securecookie.SecureCookie.Decode()")
	}

	return cval, true, nil
}

// WriteOidcCookie writes the OIDC cookie to the response
func (c *Client) WriteOidcCookie(w http.ResponseWriter, cval map[types.STKey]string) error {
	encoded, err := c.secureCookie.Encode(types.STOIDCCookieName, cval)
	if err != nil {
		return errors.Wrap(err, "securecookie.SecureCookie.Encode()")
	}

	http.SetCookie(w, &http.Cookie{
		Name:    types.STOIDCCookieName,
		Expires: time.Now().Add(types.OIDCCookieExpiration),
		Value:   encoded,
		Path:    "/",
		Secure:  secureCookie(),
	})

	return nil
}

// ReadOidcCookie reads the OIDC cookie from the request
func (c *Client) ReadOidcCookie(r *http.Request) (params map[types.STKey]string, found bool, err error) {
	cookie, err := r.Cookie(types.STOIDCCookieName)
	if err != nil {
		return nil, false, errors.Wrap(err, "http.Request.Cookie()")
	}

	cval := make(map[types.STKey]string)
	if err := c.secureCookie.Decode(types.STOIDCCookieName, cookie.Value, &cval); err != nil {
		return nil, false, errors.Wrap(err, "securecookie.SecureCookie.Decode()")
	}

	return cval, true, nil
}

// DeleteOidcCookie deletes the OIDC cookie from the response
func (c *Client) DeleteOidcCookie(w http.ResponseWriter) {
	http.SetCookie(w, &http.Cookie{
		Name:    types.STOIDCCookieName,
		Expires: time.Unix(0, 0),
		Path:    "/",
		Secure:  secureCookie(),
	})
}
