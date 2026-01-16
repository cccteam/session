//go:build !skipAuth

// Package azureoidc implements a client for Azure OIDC Authorization Code Flow with PKCE (Proof Key for Code Exchange).
package azureoidc

import (
	"context"
	"net/http"
	"strings"

	"github.com/cccteam/httpio"
	"github.com/cccteam/session/internal/azureoidc/loader"
	"github.com/cccteam/session/internal/cookie"
	"github.com/go-playground/errors/v5"
	"github.com/gofrs/uuid"
	"golang.org/x/oauth2"
)

var _ Authenticator = &OIDC{}

// OIDC implements the Authenticator interface for OpenID Connect authentication.
type OIDC struct {
	cookieClient *cookie.Client
	loader.Loader
}

// New returns a new OIDC Authenticator
func New(cookieClient *cookie.Client, issuerURL, clientID, clientSecret, redirectURL string) *OIDC {
	return &OIDC{
		cookieClient: cookieClient,
		Loader:       loader.New(issuerURL, clientID, clientSecret, redirectURL),
	}
}

// AuthCodeURL returns the URL to redirect to in order to initiate the OIDC authentication process
func (o *OIDC) AuthCodeURL(ctx context.Context, w http.ResponseWriter, returnURL string) (string, error) {
	provider, err := o.Provider(ctx)
	if err != nil {
		return "", errors.Wrap(err, "loader.Loader.Provider()")
	}

	// Using PKCE (Proof Key for Code Exchange) to protect against authorization code interception attacks
	pkceVerifier := oauth2.GenerateVerifier()

	// Use a random string as the state to protect against CSRF attacks
	state, err := uuid.NewV4()
	if err != nil {
		return "", errors.Wrap(err, "uuid.NewV4()")
	}

	cval := cookie.NewValues().
		Set(cookie.OIDCState, state.String()).
		Set(cookie.OIDCPkceVerifier, pkceVerifier).
		Set(cookie.ReturnURL, returnURL)

	if err := o.cookieClient.WriteOidcCookie(w, cval); err != nil {
		return "", errors.Wrap(err, "OIDC.WriteOidcCookie()")
	}

	return provider.AuthCodeURL(state.String(), oauth2.S256ChallengeOption(pkceVerifier)), nil
}

// Verify performs the necessary verification and processing of the OIDC callback request.
// It populates 'claims' with the ID Token's claims and returns:
//   - the URL to redirect to following successful authentication
//   - the 'sid' value from the session_state query parameter
func (o *OIDC) Verify(ctx context.Context, w http.ResponseWriter, r *http.Request, claims any) (returnURL, sid string, err error) {
	provider, err := o.Provider(ctx)
	if err != nil {
		return "", "", errors.Wrap(err, "loader.Loader.Provider()")
	}

	cval, ok, err := o.cookieClient.ReadOidcCookie(r)
	if err != nil {
		return "", "", errors.Wrap(err, "cookie.Client.ReadOidcCookie()")
	}
	if !ok {
		return "", "", httpio.NewForbiddenMessage("No OIDC cookie")
	}
	o.cookieClient.DeleteOidcCookie(w)

	returnURL = cval.Get(cookie.ReturnURL)
	if strings.TrimSpace(returnURL) == "" {
		returnURL = "/"
	}

	// Validate state parameter
	if r.URL.Query().Get("state") != cval.Get(cookie.OIDCState) {
		return "", "", httpio.NewForbiddenMessage("Invalid 'state' parameter value")
	}

	sid = r.URL.Query().Get("session_state")

	oauth2Token, err := provider.Exchange(ctx, r.URL.Query().Get("code"), oauth2.VerifierOption(cval.Get(cookie.OIDCPkceVerifier)))
	if err != nil {
		return "", "", httpio.NewInternalServerErrorMessageWithError(err, "Failed to exchange token")
	}

	rawIDToken, ok := oauth2Token.Extra("id_token").(string)
	if !ok {
		return "", "", httpio.NewInternalServerErrorMessage("No id_token in token response")
	}

	idToken, err := provider.Verify(ctx, rawIDToken)
	if err != nil {
		return "", "", httpio.NewInternalServerErrorMessageWithError(err, "Failed to verify ID token")
	}

	// Extract the claims from the ID Token
	if err := idToken.Claims(&claims); err != nil {
		return "", "", httpio.NewInternalServerErrorMessageWithError(err, "Failed to parse ID token claims")
	}

	return returnURL, sid, nil
}
