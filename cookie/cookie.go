// Package cookie provides cookie encryption using PASETO
package cookie

import (
	"net/http"
	"strings"
	"time"

	"aidanwoods.dev/go-paseto"
	"github.com/cccteam/logger"
	"github.com/go-playground/errors/v5"
)

// Client implements reading and writing encrypted cookies
type Client struct {
	pasetoKey paseto.V4SymmetricKey
}

// New returns a new Client
// keyBase64 must be a base64-encoded string of at least 32 random bytes,
// used to derived the symmetric key.
func New(keyBase64 string) (*Client, error) {
	pasetoKey, err := createPasetoKey(keyBase64)
	if err != nil {
		return nil, errors.Wrap(err, "createPasetoKey()")
	}

	client := &Client{
		pasetoKey: pasetoKey,
	}

	return client, nil
}

// Read reads the cookie from the request
func (c *Client) Read(r *http.Request, cookieName string) (values *Values, found bool, err error) {
	cookie, err := r.Cookie(cookieName)
	if err != nil {
		if errors.Is(err, http.ErrNoCookie) {
			return nil, false, nil
		}

		return nil, false, errors.Wrap(err, "http.Request.Cookie()")
	}

	cval, err := c.Decrypt(cookieName, cookie.Value)
	if err != nil {
		if strings.Contains(err.Error(), "this token has expired") {
			return cval, false, nil
		}
		logger.FromReq(r).Warnf("Invalid cookie or encryption key was rotated: %v", err)

		return cval, false, nil
	}

	return cval, true, nil
}

// WriteSessionCookie writes a session cookie to the response
func (c *Client) WriteSessionCookie(w http.ResponseWriter, cookieName, domain string, httpOnly bool, sameSite http.SameSite, values *Values) {
	http.SetCookie(w, &http.Cookie{
		Name:     cookieName,
		Expires:  time.Time{},
		Value:    c.Encrypt(cookieName, time.Now().AddDate(10, 0, 0), values),
		Path:     "/",
		Domain:   domain,
		Secure:   SecureCookie(),
		HttpOnly: httpOnly,
		SameSite: sameSite,
	})
}

// WritePersistentCookie writes a persistent cookie to the response
func (c *Client) WritePersistentCookie(w http.ResponseWriter, cookieName, domain string, httpOnly bool, sameSite http.SameSite, expiration time.Duration, values *Values) {
	expirationTime := time.Now().Add(expiration)
	http.SetCookie(w, &http.Cookie{
		Name:     cookieName,
		Expires:  expirationTime,
		Value:    c.Encrypt(cookieName, expirationTime, values),
		Path:     "/",
		Domain:   domain,
		Secure:   SecureCookie(),
		HttpOnly: httpOnly,
		SameSite: sameSite,
	})
}

// Delete deletes a cookie from the response
func (c *Client) Delete(w http.ResponseWriter, cookieName string) {
	http.SetCookie(w, &http.Cookie{
		Name:     cookieName,
		Expires:  time.Unix(0, 0),
		Value:    "",
		Path:     "/",
		Domain:   "",
		Secure:   SecureCookie(),
		HttpOnly: false,
		SameSite: http.SameSiteDefaultMode,
	})
}

// Encrypt encrypts a cookie and returns the value
func (c *Client) Encrypt(cookieName string, expiration time.Time, values *Values) string {
	values.token.SetExpiration(expiration)

	return values.token.V4Encrypt(c.pasetoKey, []byte(cookieName))
}

// Decrypt decrypts a cookie and returns the values
func (c *Client) Decrypt(cookieName, cookieValue string) (*Values, error) {
	token, err := paseto.NewParser().ParseV4Local(c.pasetoKey, cookieValue, []byte(cookieName))
	if err != nil {
		return nil, errors.Wrap(err, "paseto.ParseV4Local()")
	}

	return &Values{token: *token}, nil
}
