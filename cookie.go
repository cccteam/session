package session

import (
	"net/http"
	"strconv"
	"time"

	"github.com/cccteam/logger"
	"github.com/go-playground/errors/v5"
	"github.com/gofrs/uuid"
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
	newAuthCookie(w http.ResponseWriter, sameSiteStrict bool, idGen func() (uuid.UUID, error)) (map[scKey]string, error)
	readAuthCookie(r *http.Request) (map[scKey]string, bool)
	writeAuthCookie(w http.ResponseWriter, sameSiteStrict bool, cookieValue map[scKey]string) error
	setXSRFTokenCookie(w http.ResponseWriter, r *http.Request, sessionID string, cookieExpiration time.Duration) (set bool)
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

func (c *cookieClient) newAuthCookie(w http.ResponseWriter, sameSiteStrict bool, idGen func() (uuid.UUID, error)) (map[scKey]string, error) {
	id, err := idGen()
	if err != nil {
		return nil, errors.Wrap(err, "")
	}

	// Update cookie
	cookieValue := map[scKey]string{
		scSessionID: id.String(),
	}

	if err := c.writeAuthCookie(w, sameSiteStrict, cookieValue); err != nil {
		return nil, errors.Wrap(err, "")
	}

	return cookieValue, nil
}

func (c *cookieClient) readAuthCookie(r *http.Request) (map[scKey]string, bool) {
	cookieValue := make(map[scKey]string)

	cookie, err := r.Cookie(scAuthCookieName.String())
	if err != nil {
		return cookieValue, false
	}
	err = c.secureCookie.Decode(scAuthCookieName.String(), cookie.Value, &cookieValue)
	if err != nil {
		logger.Req(r).Error(errors.Wrap(err, "secureCookie.Decode()"))

		return cookieValue, false
	}

	return cookieValue, true
}

func (c *cookieClient) writeAuthCookie(w http.ResponseWriter, sameSiteStrict bool, cookieValue map[scKey]string) error {
	cookieValue[scSameSiteStrict] = strconv.FormatBool(sameSiteStrict)
	encoded, err := c.secureCookie.Encode(scAuthCookieName.String(), cookieValue)
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
