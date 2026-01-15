// Package cookie implements all cookie handling for the session package
package cookie

import (
	"encoding/json"
	"net/http"
	"strings"
	"time"

	"aidanwoods.dev/go-paseto"
	"github.com/cccteam/ccc"
	"github.com/cccteam/session/internal/types"
	"github.com/cccteam/session/sessioninfo"
	"github.com/go-playground/errors/v5"
)

var _ Handler = &Client{}

// Client implements all cookie management for session package
type Client struct {
	pasetoKey paseto.V4SymmetricKey
	*cookieOptions
}

// NewCookieClient returns a new CookieClient
func NewCookieClient(masterKeyBase64 string, opts ...Option) (*Client, error) {
	pasetoKey, err := createPasetoKey(masterKeyBase64)
	if err != nil {
		return nil, errors.Wrap(err, "createPasetoKey()")
	}

	client := &Client{
		pasetoKey: pasetoKey,
		cookieOptions: &cookieOptions{
			CookieName:   string(types.SCAuthCookieName),
			STCookieName: types.STCookieName,
			STHeaderName: types.STHeaderName,
		},
	}

	for _, opt := range opts {
		opt(client.cookieOptions)
	}

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
	cookie, err := r.Cookie(c.CookieName)
	if err != nil {
		if errors.Is(err, http.ErrNoCookie) {
			return nil, false, nil
		}

		return nil, false, errors.Wrap(err, "http.Request.Cookie()")
	}

	cval, err := c.decryptCookie(c.CookieName, cookie.Value)
	if err != nil {
		if strings.Contains(err.Error(), "this token has expired") {
			return nil, false, nil
		}

		return nil, false, errors.Wrap(err, "decryptCookie()")
	}

	return cval, true, nil
}

// WriteAuthCookie writes the Auth cookie to the response
func (c *Client) WriteAuthCookie(w http.ResponseWriter, sameSiteStrict bool, cval map[types.SCKey]string) error {
	sameSite := http.SameSiteStrictMode
	if !sameSiteStrict {
		sameSite = http.SameSiteNoneMode
	}

	http.SetCookie(w, &http.Cookie{
		Name:     c.CookieName,
		Expires:  time.Time{},
		Value:    c.encryptCookie(c.CookieName, time.Now().AddDate(10, 0, 0), cval),
		Path:     "/",
		Domain:   c.Domain,
		Secure:   secureCookie(),
		HttpOnly: true,
		SameSite: sameSite,
	})

	return nil
}

// RefreshXSRFTokenCookie updates the cookie when it is close to expiration, or sets it if it does not exist.
func (c *Client) RefreshXSRFTokenCookie(w http.ResponseWriter, r *http.Request, sessionID ccc.UUID) (set bool, err error) {
	cval, found, err := c.ReadXSRFCookie(r)
	if err != nil {
		return false, errors.Wrap(err, "CookieClient.ReadXSRFCookie()")
	}

	sessionMatch := sessionID.String() == cval[types.STSessionID]
	if found && sessionMatch {
		return false, nil
	}

	if err := c.CreateXSRFTokenCookie(w, sessionID); err != nil {
		return false, errors.Wrap(err, "CookieClient.CreateXSRFTokenCookie()")
	}

	return true, nil
}

// CreateXSRFTokenCookie sets a new cookie
func (c *Client) CreateXSRFTokenCookie(w http.ResponseWriter, sessionID ccc.UUID) error {
	cval := map[types.SCKey]string{
		types.STSessionID: sessionID.String(),
	}

	if err := c.WriteXSRFCookie(w, cval); err != nil {
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
func (c *Client) WriteXSRFCookie(w http.ResponseWriter, cval map[types.SCKey]string) error {
	http.SetCookie(w, &http.Cookie{
		Name:     c.STCookieName,
		Expires:  time.Time{},
		Value:    c.encryptCookie(c.STCookieName, time.Now().AddDate(10, 0, 0), cval),
		Path:     "/",
		Domain:   "",
		Secure:   secureCookie(),
		HttpOnly: false,
		SameSite: http.SameSiteStrictMode,
	})

	return nil
}

// ReadXSRFCookie reads the XSRF cookie from the request
func (c *Client) ReadXSRFCookie(r *http.Request) (params map[types.SCKey]string, found bool, err error) {
	cookie, err := r.Cookie(c.STCookieName)
	if err != nil {
		if errors.Is(err, http.ErrNoCookie) {
			return nil, false, nil
		}

		return nil, false, errors.Wrap(err, "http.Request.Cookie()")
	}

	cval, err := c.decryptCookie(c.STCookieName, cookie.Value)
	if err != nil {
		if strings.Contains(err.Error(), "this token has expired") {
			return nil, false, nil
		}

		return nil, false, errors.Wrap(err, "decryptCookie()")
	}

	return cval, true, nil
}

// ReadXSRFHeader reads the XSRF header from the request
func (c *Client) ReadXSRFHeader(r *http.Request) (params map[types.SCKey]string, found bool, err error) {
	h := r.Header.Get(c.STHeaderName)

	cval, err := c.decryptCookie(c.STCookieName, h)
	if err != nil {
		if strings.Contains(err.Error(), "this token has expired") {
			return nil, false, nil
		}

		return nil, false, errors.Wrap(err, "decryptCookie()")
	}

	return cval, true, nil
}

// WriteOidcCookie writes the OIDC cookie to the response
func (c *Client) WriteOidcCookie(w http.ResponseWriter, cval map[types.SCKey]string) error {
	http.SetCookie(w, &http.Cookie{
		Name:     types.STOIDCCookieName,
		Expires:  time.Now().Add(types.OIDCCookieExpiration),
		Value:    c.encryptCookie(types.STOIDCCookieName, time.Now().Add(types.OIDCCookieExpiration), cval),
		Path:     "/",
		Domain:   "",
		Secure:   secureCookie(),
		HttpOnly: false,
		SameSite: http.SameSiteDefaultMode,
	})

	return nil
}

// ReadOidcCookie reads the OIDC cookie from the request
func (c *Client) ReadOidcCookie(r *http.Request) (params map[types.SCKey]string, found bool, err error) {
	cookie, err := r.Cookie(types.STOIDCCookieName)
	if err != nil {
		return nil, false, errors.Wrap(err, "http.Request.Cookie()")
	}

	cval, err := c.decryptCookie(types.STOIDCCookieName, cookie.Value)
	if err != nil {
		if strings.Contains(err.Error(), "this token has expired") {
			return nil, false, nil
		}

		return nil, false, errors.Wrap(err, "securecookie.SecureCookie.Decode()")
	}

	return cval, true, nil
}

// DeleteOidcCookie deletes the OIDC cookie from the response
func (c *Client) DeleteOidcCookie(w http.ResponseWriter) {
	http.SetCookie(w, &http.Cookie{
		Name:     types.STOIDCCookieName,
		Expires:  time.Unix(0, 0),
		Value:    "",
		Path:     "/",
		Domain:   "",
		Secure:   secureCookie(),
		HttpOnly: false,
		SameSite: http.SameSiteDefaultMode,
	})
}

func (c *Client) encryptCookie(cookieName string, expiration time.Time, cval map[types.SCKey]string) string {
	token := paseto.NewToken()
	for k, v := range cval {
		token.SetString("custom:"+string(k), v)
	}

	token.SetExpiration(expiration)

	return token.V4Encrypt(c.pasetoKey, []byte(cookieName))
}

func (c *Client) decryptCookie(cookieName, cookieValue string) (map[types.SCKey]string, error) {
	cval := make(map[types.SCKey]string)

	token, err := paseto.NewParser().ParseV4Local(c.pasetoKey, cookieValue, []byte(cookieName))
	if err != nil {
		return cval, errors.Wrap(err, "paseto.ParseV4Local()")
	}

	var rawClaims map[string]interface{}
	if err := json.Unmarshal(token.ClaimsJSON(), &rawClaims); err != nil {
		return cval, errors.Wrap(err, "failed to unmarshal token claims")
	}

	for k, v := range rawClaims {
		if strVal, ok := v.(string); ok {
			if !strings.HasPrefix(k, "custom:") {
				continue
			}
			cval[types.SCKey(strings.TrimPrefix(k, "custom:"))] = strVal
		}
	}

	return cval, nil
}
