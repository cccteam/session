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
			CookieName:     AuthCookieName,
			XSRFCookieName: XSRFCookieName,
			XSRFHeaderName: XSRFHeaderName,
		},
	}

	for _, opt := range opts {
		opt(client.cookieOptions)
	}

	return client, nil
}

// NewAuthCookie writes a new Auth Cookie for given sessionID
func (c *Client) NewAuthCookie(w http.ResponseWriter, sameSiteStrict bool, sessionID ccc.UUID) *cookie.Values {
	cval := cookie.NewValues().SetString(SessionID, sessionID.String())

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
	cval, found, err := c.cookie.Read(r, c.XSRFCookieName)
	if err != nil {
		return false, errors.Wrap(err, "cookie.Client.Read()")
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
	cval := cookie.NewValues().SetString(SessionID, sessionID.String())

	c.cookie.WriteSessionCookie(w, c.XSRFCookieName, c.Domain, false, http.SameSiteStrictMode, cval)
}

// HasValidXSRFToken checks if the XSRF token is valid
func (c *Client) HasValidXSRFToken(r *http.Request) (bool, error) {
	cval, found, err := c.cookie.Read(r, c.XSRFCookieName)
	if err != nil {
		return false, errors.Wrap(err, "cookie.Client.Read()")
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
	h := r.Header.Get(c.XSRFHeaderName)

	cval, err := c.cookie.Decrypt(c.XSRFCookieName, h)
	if err != nil {
		if strings.Contains(err.Error(), "this token has expired") {
			return nil, false
		}
		logger.FromReq(r).Warnf("Invalid cookie or encryption key was rotated: %v", err)

		return nil, false
	}

	return cval, true
}

// WriteStateCookie writes an OIDC login's state cookie under name (a registration's,
// StateCookieName), so logins with different providers in one browser never
// overwrite each other's state. It carries the state, PKCE verifier and return URL
// between the redirect to the identity provider and the callback. No script reads it
// and the server reads it once at the callback, so it is HttpOnly. SameSite stays the
// default: a strict setting would keep it from coming back with the provider's redirect.
func (c *Client) WriteStateCookie(w http.ResponseWriter, name string, values *cookie.Values) {
	c.cookie.WritePersistentCookie(w, name, c.Domain, true, http.SameSiteDefaultMode, OIDCCookieExpiration, values)
}

// ReadStateCookie reads the state cookie named name, or the legacy OIDCCookieName cookie
// when the browser has none. readName is the name of the cookie read, or "" when neither
// is present. Pass it to DeleteStateCookie.
func (c *Client) ReadStateCookie(r *http.Request, name string) (values *cookie.Values, readName string, err error) {
	for _, n := range []string{name, OIDCCookieName} {
		cval, found, err := c.cookie.Read(r, n)
		if err != nil {
			return nil, "", errors.Wrap(err, "cookie.Client.Read()")
		}
		if found {
			return cval, n, nil
		}
	}

	return nil, "", nil
}

// DeleteStateCookie deletes the state cookie named name. A state cookie is single-use.
func (c *Client) DeleteStateCookie(w http.ResponseWriter, name string) {
	c.cookie.Delete(w, name, c.Domain)
}

// StateCookieName is the name of the state cookie of the registration named
// registration: StateCookiePrefix followed by the name.
func StateCookieName(registration string) string {
	return StateCookiePrefix + registration
}

// RegistrationStateCookies is one registration's state cookie, as the core hands it to
// the method it registers: named for the registration (OIDC-<name>), so two
// registrations of one method, and logins with different providers in one browser,
// never read each other's state; and carrying the registration's name in its values,
// so a cookie another registration wrote, or the shared OIDC cookie of v0.12, reads as
// absent and the callback that finds it is refused. It implements signin.StateCookies.
type RegistrationStateCookies struct {
	client       *Client
	registration string
	name         string
}

// ForRegistration returns the state cookie of the registration named registration.
func (c *Client) ForRegistration(registration string) RegistrationStateCookies {
	return RegistrationStateCookies{client: c, registration: registration, name: StateCookieName(registration)}
}

// Name is the cookie's name, OIDC-<registration>.
func (s RegistrationStateCookies) Name() string {
	return s.name
}

// WriteStateCookie writes values, with the registration's name added, as the
// registration's state cookie.
func (s RegistrationStateCookies) WriteStateCookie(w http.ResponseWriter, values *cookie.Values) {
	s.client.WriteStateCookie(w, s.name, values.SetString(Registration, s.registration))
}

// ReadStateCookie reads the registration's state cookie. readName is its name, or ""
// when the browser carries none, or one that names another registration.
func (s RegistrationStateCookies) ReadStateCookie(r *http.Request) (values *cookie.Values, readName string, err error) {
	cval, found, err := s.client.cookie.Read(r, s.name)
	if err != nil {
		return nil, "", errors.Wrap(err, "cookie.Client.Read()")
	}
	if !found {
		return nil, "", nil
	}
	// A cookie without the key, the shared OIDC cookie of v0.12 among them, names no
	// registration and so is not this one's.
	registration, _ := cval.GetString(Registration)
	if registration != s.registration {
		return nil, "", nil
	}

	return cval, s.name, nil
}

// DeleteStateCookie deletes the state cookie named name, the name ReadStateCookie
// returned.
func (s RegistrationStateCookies) DeleteStateCookie(w http.ResponseWriter, name string) {
	s.client.DeleteStateCookie(w, name)
}

// LegacyStateCookies is the state cookie of a legacy session type (legacy.OIDCAzure):
// named for its provider as in v0.12 (OIDC-azure), with the shared OIDC cookie of
// earlier releases read when the provider's is absent, so a login started before an
// upgrade completes. It implements signin.StateCookies.
type LegacyStateCookies struct {
	client *Client
	name   string
}

// ForLegacy returns the legacy state cookie of provider (azure).
func (c *Client) ForLegacy(provider string) LegacyStateCookies {
	return LegacyStateCookies{client: c, name: StateCookieName(provider)}
}

// WriteStateCookie writes values as the provider's state cookie.
func (s LegacyStateCookies) WriteStateCookie(w http.ResponseWriter, values *cookie.Values) {
	s.client.WriteStateCookie(w, s.name, values)
}

// ReadStateCookie reads the provider's state cookie, or the shared OIDC cookie when the
// browser has none; readName is the name read, or "" when neither is present.
func (s LegacyStateCookies) ReadStateCookie(r *http.Request) (values *cookie.Values, readName string, err error) {
	return s.client.ReadStateCookie(r, s.name)
}

// DeleteStateCookie deletes the state cookie named name, the name ReadStateCookie
// returned.
func (s LegacyStateCookies) DeleteStateCookie(w http.ResponseWriter, name string) {
	s.client.DeleteStateCookie(w, name)
}

// Cookie returns the underlying cookie.Client
func (c *Client) Cookie() *cookie.Client {
	return c.cookie
}
