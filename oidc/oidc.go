//go:build !skipAuth

package oidc

import (
	"context"
	"net/http"
	"strings"
	"sync"

	"github.com/cccteam/httpio"
	"github.com/coreos/go-oidc/v3/oidc"
	"github.com/go-playground/errors/v5"
	"github.com/gofrs/uuid"
	"github.com/gorilla/securecookie"
	"golang.org/x/oauth2"
)

var _ Authenticator = &OIDC{}

const defaultLoginURL = "/login"

type OIDC struct {
	s            *securecookie.SecureCookie
	loginURL     string
	issuerURL    string
	clientID     string
	clientSecret string
	redirectURL  string

	mu sync.RWMutex
	provider
	config
}

// New returns a new OIDC Authenticator
func New(s *securecookie.SecureCookie, issuerURL, clientID, clientSecret, redirectURL string) *OIDC {
	return &OIDC{
		s:            s,
		issuerURL:    issuerURL,
		clientID:     clientID,
		clientSecret: clientSecret,
		redirectURL:  redirectURL,
	}
}

func (o *OIDC) init(ctx context.Context) error {
	o.mu.RLock()
	if o.provider != nil {
		o.mu.RUnlock()

		return nil
	}

	o.mu.RUnlock()
	o.mu.Lock()
	defer o.mu.Unlock()

	if o.provider != nil {
		return nil
	}

	provider, err := oidc.NewProvider(ctx, o.issuerURL)
	if err != nil {
		return errors.Wrap(err, "oidc.NewProvider()")
	}

	o.provider = provider
	o.config = &oAuth2{
		config: oauth2.Config{
			ClientID:     o.clientID,
			ClientSecret: o.clientSecret,
			RedirectURL:  o.redirectURL,
			Endpoint:     provider.Endpoint(),
			Scopes:       []string{oidc.ScopeOpenID, "profile"},
		},
	}

	return nil
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

// AuthCodeURL returns the URL to redirect to in order to initiate the OIDC authentication process
func (o *OIDC) AuthCodeURL(ctx context.Context, w http.ResponseWriter, returnURL string) (string, error) {
	if err := o.init(ctx); err != nil {
		return "", errors.Wrap(err, "init()")
	}

	// Using PKCE (Proof Key for Code Exchange) to protect against authorization code interception attacks
	pkceVerifier := oauth2.GenerateVerifier()

	// Use a random string as the state to protect against CSRF attacks
	state, err := uuid.NewV4()
	if err != nil {
		return "", errors.Wrap(err, "uuid.NewV4()")
	}

	cval := map[stKey]string{
		stState:        state.String(),
		stPkceVerifier: pkceVerifier,
		stReturnURL:    returnURL, // URL to redirect to following successful authentication
	}

	if err := o.writeOidcCookie(w, cval); err != nil {
		return "", errors.Wrap(err, "writeOidcCookie()")
	}

	return o.config.AuthCodeURL(state.String(), oauth2.S256ChallengeOption(pkceVerifier)), nil
}

// Verify performs the necessary verification and processing of the OIDC callback request.
// It populates 'claims' with the ID Token's claims and returns:
//   - the URL to redirect to following successful authentication
//   - the 'sid' value from the session_state query parameter
func (o *OIDC) Verify(ctx context.Context, w http.ResponseWriter, r *http.Request, claims any) (returnURL, sid string, err error) {
	if err := o.init(ctx); err != nil {
		return "", "", errors.Wrap(err, "init()")
	}

	cval, ok := o.readOidcCookie(r)
	if !ok {
		return "", "", httpio.NewForbiddenMessage("No OIDC cookie")
	}
	o.deleteOidcCookie(w)

	returnURL = cval[stReturnURL]
	if strings.TrimSpace(returnURL) == "" {
		returnURL = "/"
	}

	// Validate state parameter
	if r.URL.Query().Get("state") != cval[stState] {
		return "", "", httpio.NewForbiddenMessage("Invalid 'state' parameter value")
	}

	sid = r.URL.Query().Get("session_state")

	oauth2Token, err := o.config.Exchange(ctx, r.URL.Query().Get("code"), oauth2.VerifierOption(cval[stPkceVerifier]))
	if err != nil {
		return "", "", httpio.NewInternalServerErrorMessageWithError(err, "Failed to exchange token")
	}

	rawIDToken, ok := oauth2Token.Extra("id_token").(string)
	if !ok {
		return "", "", httpio.NewInternalServerErrorMessage("No id_token in token response")
	}

	verifier := o.provider.Verifier(&oidc.Config{ClientID: o.config.ClientID()})

	idToken, err := verifier.Verify(ctx, rawIDToken)
	if err != nil {
		return "", "", httpio.NewInternalServerErrorMessageWithError(err, "Failed to verify ID token")
	}

	// Extract the claims from the ID Token
	if err := idToken.Claims(&claims); err != nil {
		return "", "", httpio.NewInternalServerErrorMessageWithError(err, "Failed to parse ID token claims")
	}

	return returnURL, sid, nil
}
