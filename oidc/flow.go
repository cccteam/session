package oidc

import (
	"context"
	"net/http"

	"github.com/cccteam/httpio"
	"github.com/cccteam/session/cookie"
	internalcookie "github.com/cccteam/session/internal/cookie"
	"github.com/cccteam/session/sessioninfo"
	"github.com/cccteam/session/signin"
	gooidc "github.com/coreos/go-oidc/v3/oidc"
	"github.com/go-playground/errors/v5"
	"github.com/gofrs/uuid"
	"golang.org/x/oauth2"
)

// Flow is the authorization code flow with PKCE (Proof Key for Code Exchange) the
// OpenID Connect methods share. Begin writes the state, the PKCE verifier and the
// return URL to the method's own state cookie and hands back the provider's
// authorization URL; Complete binds the callback to that login, exchanges the code
// and verifies the ID token. The provider comes from the embedded Loader, which also
// carries the login URL refused sign-ins are sent to.
type Flow struct {
	Loader
	cookies    signin.StateCookies
	cookieName string
}

// NewFlow returns the flow over loader, keeping its state in the cookie named
// cookieName through cookies. Each method names its own cookie, so logins with
// different providers in one browser never read each other's state.
func NewFlow(cookies signin.StateCookies, cookieName string, loader Loader) *Flow {
	return &Flow{Loader: loader, cookies: cookies, cookieName: cookieName}
}

// Begin writes the state cookie and returns the provider's authorization URL. params
// are authorization parameters beside state and the PKCE challenge, such as Google's
// hd hint.
func (f *Flow) Begin(ctx context.Context, w http.ResponseWriter, returnURL string, params ...oauth2.AuthCodeOption) (string, error) {
	provider, err := f.Provider(ctx)
	if err != nil {
		return "", errors.Wrap(err, "oidc.Loader.Provider()")
	}

	// PKCE protects against authorization code interception; the random state binds
	// the callback to the login this browser started (CSRF).
	pkceVerifier := oauth2.GenerateVerifier()
	state, err := uuid.NewV4()
	if err != nil {
		return "", errors.Wrap(err, "uuid.NewV4()")
	}

	cval := cookie.NewValues().
		SetString(internalcookie.OIDCState, state.String()).
		SetString(internalcookie.OIDCPkceVerifier, pkceVerifier).
		SetString(internalcookie.ReturnURL, returnURL)
	f.cookies.WriteStateCookie(w, f.cookieName, cval)

	opts := append([]oauth2.AuthCodeOption{oauth2.S256ChallengeOption(pkceVerifier)}, params...)

	return provider.AuthCodeURL(state.String(), opts...), nil
}

// Completed is a completed round trip to the provider.
type Completed struct {
	// ReturnURL is the sanitized path in the application the browser goes to next.
	ReturnURL string
	// IDToken is the verified ID token.
	IDToken *gooidc.IDToken
	// Token is the token response of the code exchange: the access token and whatever
	// else the provider issued with it.
	Token *oauth2.Token
}

// Claims decodes the ID token's claims into the value into points to. A token whose
// claims do not decode is refused (claims_parse).
func (c *Completed) Claims(into any) error {
	if err := c.IDToken.Claims(into); err != nil {
		return sessioninfo.NewLoginRefusal(sessioninfo.RefusedClaimsParse, httpio.NewInternalServerErrorMessageWithError(err, "Failed to parse ID token claims"))
	}

	return nil
}

// Complete verifies the callback: the state cookie must be present and is deleted, so
// it is single use; its state must match the state parameter; the code is exchanged
// with the PKCE verifier; and the ID token's signature, issuer, audience and expiry are
// verified. Every refusal is a sessioninfo.LoginRefusal.
func (f *Flow) Complete(ctx context.Context, w http.ResponseWriter, r *http.Request) (*Completed, error) {
	provider, err := f.Provider(ctx)
	if err != nil {
		return nil, errors.Wrap(err, "oidc.Loader.Provider()")
	}

	cval, cookieName, err := f.cookies.ReadStateCookie(r, f.cookieName)
	if err != nil {
		return nil, errors.Wrap(err, "signin.StateCookies.ReadStateCookie()")
	}
	if cookieName == "" {
		return nil, sessioninfo.NewLoginRefusal(sessioninfo.RefusedNoOIDCCookie, httpio.NewForbiddenMessage("No OIDC cookie"))
	}
	f.cookies.DeleteStateCookie(w, cookieName)

	returnURL, _ := cval.GetString(internalcookie.ReturnURL)
	returnURL = internalcookie.SanitizeReturnURL(returnURL)

	state, err := cval.GetString(internalcookie.OIDCState)
	if err != nil || r.URL.Query().Get("state") != state {
		return nil, sessioninfo.NewLoginRefusal(sessioninfo.RefusedInvalidState, httpio.NewForbiddenMessage("Invalid 'state' parameter value"))
	}

	verifier, err := cval.GetString(internalcookie.OIDCPkceVerifier)
	if err != nil {
		return nil, sessioninfo.NewLoginRefusal(sessioninfo.RefusedInvalidPKCE, httpio.NewForbiddenMessage("Invalid 'pkceVerifier' parameter value"))
	}
	token, err := provider.Exchange(ctx, r.URL.Query().Get("code"), oauth2.VerifierOption(verifier))
	if err != nil {
		return nil, sessioninfo.NewLoginRefusal(sessioninfo.RefusedTokenExchange, httpio.NewInternalServerErrorMessageWithError(err, "Failed to exchange token"))
	}

	rawIDToken, ok := token.Extra("id_token").(string)
	if !ok {
		return nil, sessioninfo.NewLoginRefusal(sessioninfo.RefusedNoIDToken, httpio.NewInternalServerErrorMessage("No id_token in token response"))
	}
	idToken, err := provider.Verify(ctx, rawIDToken)
	if err != nil {
		return nil, sessioninfo.NewLoginRefusal(sessioninfo.RefusedIDTokenVerification, httpio.NewInternalServerErrorMessageWithError(err, "Failed to verify ID token"))
	}

	return &Completed{ReturnURL: returnURL, IDToken: idToken, Token: token}, nil
}
