//go:build skipAuth

package oidc

import (
	"context"
	"encoding/json"
	"net/http"
	"os"
	"strings"

	"github.com/go-playground/errors/v5"
	"github.com/gofrs/uuid"
	"github.com/gorilla/securecookie"
)

var _ Authenticator = &OIDC{}

const defaultLoginURL = "/login"

type OIDC struct {
	redirectURL string
	s           *securecookie.SecureCookie
	loginURL    string
}

func New(s *securecookie.SecureCookie, _, _, _, redirectURL string) *OIDC {
	return &OIDC{
		redirectURL: redirectURL,
		s:           s,
	}
}

func (o *OIDC) SetLoginURL(url string) {
	o.loginURL = url
}

func (o *OIDC) LoginURL() string {
	if o.loginURL == "" {
		return defaultLoginURL
	}

	return o.loginURL
}

func (o *OIDC) AuthCodeURL(_ context.Context, w http.ResponseWriter, returnURL string) (string, error) {
	cval := map[stKey]string{
		stReturnURL: returnURL, // URL to redirect to following successful authentication
	}
	if err := o.writeOidcCookie(w, cval); err != nil {
		return "", errors.Wrap(err, "writeOidcCookie()")
	}

	return o.redirectURL, nil
}

func (o *OIDC) Verify(_ context.Context, w http.ResponseWriter, r *http.Request, claims any) (returnURL, sid string, err error) {
	type claimsSimulated struct {
		PreferredUsername string   `json:"preferred_username"`
		Roles             []string `json:"roles"`
	}
	var c claimsSimulated
	c.PreferredUsername = os.Getenv("APP_USERNAME")
	c.Roles = strings.Split(os.Getenv("APP_ROLES"), ",")

	// Transfer the claims values to the input 'claims' variable
	cByte, err := json.Marshal(c)
	if err != nil {
		return "", "", errors.Wrap(err, "json.Marshal()")
	}
	if err := json.Unmarshal(cByte, claims); err != nil {
		return "", "", errors.Wrap(err, "json.Unmarshal()")
	}

	cval, ok := o.readOidcCookie(r)
	if !ok {
		return "", "", errors.New("No OIDC cookie")
	}
	o.deleteOidcCookie(w)

	returnURL = cval[stReturnURL]
	if strings.TrimSpace(returnURL) == "" {
		returnURL = "/"
	}

	oidcID, err := uuid.NewV4()
	if err != nil {
		return "", "", errors.Wrap(err, "uuid.NewV4()")
	}

	return returnURL, oidcID.String(), nil
}
