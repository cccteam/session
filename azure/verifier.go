//go:build !skipAuth

// Package azure is the Microsoft Entra ID (Azure) sign-in method: the OpenID Connect
// authorization code flow with PKCE against the tenant, and its registration on an
// Auth session.
package azure

import (
	"context"
	"net/http"

	"github.com/cccteam/httpio"
	"github.com/cccteam/session/cookie"
	internalcookie "github.com/cccteam/session/internal/cookie"
	"github.com/cccteam/session/oidc"
	"github.com/cccteam/session/sessioninfo"
	"github.com/cccteam/session/signin"
	gooidc "github.com/coreos/go-oidc/v3/oidc"
	"github.com/go-playground/errors/v5"
	"github.com/gofrs/uuid"
	"golang.org/x/oauth2"
)

var _ Authenticator = &OIDC{}

// OIDC implements the Authenticator interface for OpenID Connect authentication.
type OIDC struct {
	cookies signin.StateCookies
	oidc.Loader
}

// NewOIDC returns a new OIDC Authenticator
func NewOIDC(cookies signin.StateCookies, issuerURL, clientID, clientSecret, redirectURL string) *OIDC {
	return &OIDC{
		cookies: cookies,
		Loader:  oidc.New(issuerURL, clientID, clientSecret, redirectURL, []string{gooidc.ScopeOpenID, "profile"}),
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
		SetString(internalcookie.OIDCState, state.String()).
		SetString(internalcookie.OIDCPkceVerifier, pkceVerifier).
		SetString(internalcookie.ReturnURL, returnURL)

	o.cookies.WriteStateCookie(w, internalcookie.AzureStateCookieName, cval)

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

	cval, cookieName, err := o.cookies.ReadStateCookie(r, internalcookie.AzureStateCookieName)
	if err != nil {
		return "", "", errors.Wrap(err, "cookie.Client.ReadStateCookie()")
	}
	if cookieName == "" {
		return "", "", sessioninfo.NewLoginRefusal(sessioninfo.RefusedNoOIDCCookie, httpio.NewForbiddenMessage("No OIDC cookie"))
	}
	o.cookies.DeleteStateCookie(w, cookieName)

	returnURL, _ = cval.GetString(internalcookie.ReturnURL)
	returnURL = internalcookie.SanitizeReturnURL(returnURL)

	state, err := cval.GetString(internalcookie.OIDCState)
	if err != nil {
		return "", "", sessioninfo.NewLoginRefusal(sessioninfo.RefusedInvalidState, httpio.NewForbiddenMessage("Invalid 'state' parameter value"))
	}
	// Validate state parameter
	if r.URL.Query().Get("state") != state {
		return "", "", sessioninfo.NewLoginRefusal(sessioninfo.RefusedInvalidState, httpio.NewForbiddenMessage("Invalid 'state' parameter value"))
	}

	verifier, err := cval.GetString(internalcookie.OIDCPkceVerifier)
	if err != nil {
		return "", "", sessioninfo.NewLoginRefusal(sessioninfo.RefusedInvalidPKCE, httpio.NewForbiddenMessage("Invalid 'pkceVerifier' parameter value"))
	}
	oauth2Token, err := provider.Exchange(ctx, r.URL.Query().Get("code"), oauth2.VerifierOption(verifier))
	if err != nil {
		return "", "", sessioninfo.NewLoginRefusal(sessioninfo.RefusedTokenExchange, httpio.NewInternalServerErrorMessageWithError(err, "Failed to exchange token"))
	}

	rawIDToken, ok := oauth2Token.Extra("id_token").(string)
	if !ok {
		return "", "", sessioninfo.NewLoginRefusal(sessioninfo.RefusedNoIDToken, httpio.NewInternalServerErrorMessage("No id_token in token response"))
	}

	idToken, err := provider.Verify(ctx, rawIDToken)
	if err != nil {
		return "", "", sessioninfo.NewLoginRefusal(sessioninfo.RefusedIDTokenVerification, httpio.NewInternalServerErrorMessageWithError(err, "Failed to verify ID token"))
	}

	// Extract the claims from the ID Token
	if err := idToken.Claims(&claims); err != nil {
		return "", "", sessioninfo.NewLoginRefusal(sessioninfo.RefusedClaimsParse, httpio.NewInternalServerErrorMessageWithError(err, "Failed to parse ID token claims"))
	}

	sid = r.URL.Query().Get("session_state")

	return returnURL, sid, nil
}
