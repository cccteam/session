// Package cookie implements all cookie handling for the session package
package cookie

import (
	"net/http"
	"strconv"
	"strings"

	"github.com/cccteam/ccc"
	"github.com/cccteam/logger"
	"github.com/cccteam/session/cookie"
	"github.com/cccteam/session/sessioninfo"
	"github.com/go-playground/errors/v5"
)

var _ Handler = &Client{}

// Client implements all cookie management for session package
type Client struct {
	cookie *cookie.Client
	*cookieOptions
}

// NewCookieClient returns a new CookieClient
func NewCookieClient(masterKeyBase64 string, opts ...Option) (*Client, error) {
	c, err := cookie.New(masterKeyBase64)
	if err != nil {
		return nil, errors.Wrap(err, "cookie.New()")
	}

	client := &Client{
		cookie: c,
		cookieOptions: &cookieOptions{
			CookieName:   AuthCookieName,
			STCookieName: XSRFCookieName,
			STHeaderName: XSRFHeaderName,
		},
	}

	for _, opt := range opts {
		opt(client.cookieOptions)
	}

	return client, nil
}

// NewAuthCookie writes a new Auth Cookie for given sessionID
func (c *Client) NewAuthCookie(w http.ResponseWriter, sameSiteStrict bool, sessionID ccc.UUID) *cookie.Values {
	cval := cookie.NewValues()
	cval.SetString(SessionID, sessionID.String())

	c.WriteAuthCookie(w, sameSiteStrict, cval)

	return cval
}

// ReadAuthCookie reads the Auth cookie from the request
func (c *Client) ReadAuthCookie(r *http.Request) (values *cookie.Values, found bool, err error) {
	cval, found, err := c.cookie.Read(r, c.CookieName)
	if err != nil {
		return cval, found, errors.Wrap(err, "CookieClient.Read()")
	}

	return cval, found, nil
}

// WriteAuthCookie writes the Auth cookie to the response
func (c *Client) WriteAuthCookie(w http.ResponseWriter, sameSiteStrict bool, values *cookie.Values) {
	sameSite := http.SameSiteStrictMode
	if !sameSiteStrict {
		sameSite = http.SameSiteNoneMode
	}

	values.SetString(SameSiteStrict, strconv.FormatBool(sameSiteStrict))

	c.cookie.WriteSessionCookie(w, c.CookieName, c.Domain, true, sameSite, values)
}

// RefreshXSRFTokenCookie updates the cookie when it is close to expiration, or sets it if it does not exist.
func (c *Client) RefreshXSRFTokenCookie(w http.ResponseWriter, r *http.Request, sessionID ccc.UUID) (set bool, err error) {
	cval, found, err := c.cookie.Read(r, c.STCookieName)
	if err != nil {
		return false, errors.Wrap(err, "CookieClient.ReadXSRFCookie()")
	}

	if found {
		cSessionID, err := cval.GetString(SessionID)
		if err == nil {
			if sessionID.String() == cSessionID {
				return false, nil
			}
		}
	}

	c.CreateXSRFTokenCookie(w, sessionID)

	return true, nil
}

// CreateXSRFTokenCookie sets a new cookie
func (c *Client) CreateXSRFTokenCookie(w http.ResponseWriter, sessionID ccc.UUID) {
	cval := cookie.NewValues()
	cval.SetString(SessionID, sessionID.String())

	c.cookie.WriteSessionCookie(w, c.STCookieName, c.Domain, false, http.SameSiteStrictMode, cval)
}

// HasValidXSRFToken checks if the XSRF token is valid
func (c *Client) HasValidXSRFToken(r *http.Request) (bool, error) {
	cval, found, err := c.cookie.Read(r, c.STCookieName)
	if err != nil {
		return false, errors.Wrap(err, "CookieClient.ReadXSRFCookie()")
	}
	if !found {
		return false, nil
	}
	cSessionID, _ := cval.GetString(SessionID)
	if sessioninfo.IDFromRequest(r).String() != cSessionID {
		return false, nil
	}

	hval, found := c.readXSRFHeader(r)
	if !found {
		return false, nil
	}
	hSessionID, _ := hval.GetString(SessionID)

	return hSessionID == cSessionID, nil
}

// readXSRFHeader reads the XSRF header from the request
func (c *Client) readXSRFHeader(r *http.Request) (values *cookie.Values, found bool) {
	h := r.Header.Get(c.STHeaderName)

	cval, err := c.cookie.Decrypt(c.STCookieName, h)
	if err != nil {
		if strings.Contains(err.Error(), "this token has expired") {
			return nil, false
		}
		logger.FromReq(r).Warnf("Invalid cookie or encryption key was rotated: %v", err)

		return nil, false
	}

	return cval, true
}

// WriteOidcCookie writes the OIDC cookie to the response
func (c *Client) WriteOidcCookie(w http.ResponseWriter, values *cookie.Values) {
	c.cookie.WritePersistentCookie(w, OIDCCookieName, c.Domain, false, http.SameSiteDefaultMode, OIDCCookieExpiration, values)
}

// ReadOidcCookie reads the OIDC cookie from the request
func (c *Client) ReadOidcCookie(r *http.Request) (values *cookie.Values, found bool, err error) {
	cval, found, err := c.cookie.Read(r, OIDCCookieName)
	if err != nil {
		return nil, found, errors.Wrap(err, "cookie.Client.Read()")
	}

	return cval, found, nil
}

// DeleteOidcCookie deletes the OIDC cookie from the response
func (c *Client) DeleteOidcCookie(w http.ResponseWriter) {
	c.cookie.Delete(w, OIDCCookieName)
}

// Cookie returns the underlying cookie.Client
func (c *Client) Cookie() *cookie.Client {
	return c.cookie
}
