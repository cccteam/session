// oidc contains the app-specific methods related to auth via Open ID Connect (OIDC)
package oidc

import (
	"net/http"
	"time"

	"github.com/go-playground/errors/v5"
)

type stKey string

func (c stKey) String() string {
	return string(c)
}

const (
	stCookieName = "OIDC"
	// Keys used in Secure Token Cookie
	stState        stKey = "state"
	stPkceVerifier stKey = "pkceVerifier"
	stReturnURL    stKey = "returnURL"

	oidcCookieExpiration = 10 * time.Minute
)

func (o *OIDC) writeOidcCookie(w http.ResponseWriter, cval map[stKey]string) error {
	encoded, err := o.s.Encode(stCookieName, cval)
	if err != nil {
		return errors.Wrap(err, "securecookie.Encode()")
	}

	http.SetCookie(w, &http.Cookie{
		Name:    stCookieName,
		Expires: time.Now().Add(oidcCookieExpiration),
		Value:   encoded,
		Path:    "/",
		Secure:  o.secure,
	})

	return nil
}

func (o *OIDC) readOidcCookie(r *http.Request) (map[stKey]string, bool) {
	c, err := r.Cookie(stCookieName)
	if err != nil {
		return nil, false
	}

	cval := make(map[stKey]string)
	err = o.s.Decode(stCookieName, c.Value, &cval)
	if err != nil {
		return nil, false
	}

	return cval, true
}

func (o *OIDC) deleteOidcCookie(w http.ResponseWriter) {
	http.SetCookie(w, &http.Cookie{
		Name:    stCookieName,
		Expires: time.Unix(0, 0),
		Path:    "/",
		Secure:  o.secure,
	})
}
