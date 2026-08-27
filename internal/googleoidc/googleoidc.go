//go:build !skipAuth

// Package googleoidc implements a client for Google OIDC Authorization Code Flow with
// PKCE (Proof Key for Code Exchange), restricted to a single Google Workspace hosted
// domain.
package googleoidc

import (
	"context"
	"net/http"
	"strings"

	"github.com/cccteam/httpio"
	"github.com/cccteam/session/cookie"
	internalcookie "github.com/cccteam/session/internal/cookie"
	"github.com/cccteam/session/internal/oidcloader"
	"github.com/coreos/go-oidc/v3/oidc"
	"github.com/go-playground/errors/v5"
	"github.com/gofrs/uuid"
	"golang.org/x/oauth2"
)

// issuerURL is Google's OIDC issuer. It is fixed: Google operates a single issuer for
// all Workspace organizations (tenancy is expressed by the hd claim, not the issuer).
const issuerURL = "https://accounts.google.com"

var _ Authenticator = &OIDC{}

// OIDC implements the Authenticator interface for OpenID Connect authentication.
type OIDC struct {
	cookieClient *internalcookie.Client
	hostedDomain string
	oidcloader.Loader
}

// New returns a new OIDC Authenticator. hostedDomain is the Google Workspace domain the
// flow is restricted to: it is sent as the hd hint on the authorization request and
// enforced against the verified ID token's hd claim.
func New(cookieClient *internalcookie.Client, clientID, clientSecret, redirectURL, hostedDomain string) *OIDC {
	return newWithIssuer(cookieClient, issuerURL, clientID, clientSecret, redirectURL, hostedDomain)
}

// newWithIssuer exists so tests can point the authenticator at a fake IdP; production
// code always goes through New and Google's fixed issuer.
func newWithIssuer(cookieClient *internalcookie.Client, issuer, clientID, clientSecret, redirectURL, hostedDomain string) *OIDC {
	return &OIDC{
		cookieClient: cookieClient,
		hostedDomain: hostedDomain,
		Loader:       oidcloader.New(issuer, clientID, clientSecret, redirectURL, []string{oidc.ScopeOpenID, "email", "profile"}),
	}
}

// AuthCodeURL returns the URL to redirect to in order to initiate the OIDC authentication process
func (o *OIDC) AuthCodeURL(ctx context.Context, w http.ResponseWriter, returnURL string) (string, error) {
	provider, err := o.Provider(ctx)
	if err != nil {
		return "", errors.Wrap(err, "oidcloader.Loader.Provider()")
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

	o.cookieClient.WriteOidcCookie(w, cval)

	// The hd parameter pre-selects the Workspace domain's accounts in Google's account
	// chooser. It is a UX hint only — the trusted enforcement is the hd claim check in
	// Verify.
	return provider.AuthCodeURL(state.String(),
		oauth2.S256ChallengeOption(pkceVerifier),
		oauth2.SetAuthURLParam("hd", o.hostedDomain),
	), nil
}

// Verify performs the necessary verification and processing of the OIDC callback
// request. Beyond the standard checks (state, PKCE code exchange, ID-token signature /
// issuer / audience / expiry), it rejects tokens whose hd claim does not match the
// configured hosted domain (a consumer account carries no hd claim at all and fails
// closed) and tokens without a verified email.
// It populates 'claims' with the ID Token's claims and returns the URL to redirect to
// following successful authentication. Google issues no sid claim and supports no
// IdP-initiated logout, so no OIDC session ID is returned.
func (o *OIDC) Verify(ctx context.Context, w http.ResponseWriter, r *http.Request, claims any) (returnURL string, err error) {
	provider, err := o.Provider(ctx)
	if err != nil {
		return "", errors.Wrap(err, "oidcloader.Loader.Provider()")
	}

	cval, ok, err := o.cookieClient.ReadOidcCookie(r)
	if err != nil {
		return "", errors.Wrap(err, "cookie.Client.ReadOidcCookie()")
	}
	if !ok {
		return "", httpio.NewForbiddenMessage("No OIDC cookie")
	}
	o.cookieClient.DeleteOidcCookie(w)

	returnURL, _ = cval.GetString(internalcookie.ReturnURL)
	if strings.TrimSpace(returnURL) == "" {
		returnURL = "/"
	}

	state, err := cval.GetString(internalcookie.OIDCState)
	if err != nil {
		return "", httpio.NewForbiddenMessage("Invalid 'state' parameter value")
	}
	// Validate state parameter
	if r.URL.Query().Get("state") != state {
		return "", httpio.NewForbiddenMessage("Invalid 'state' parameter value")
	}

	verifier, err := cval.GetString(internalcookie.OIDCPkceVerifier)
	if err != nil {
		return "", httpio.NewForbiddenMessage("Invalid 'pkceVerifier' parameter value")
	}
	oauth2Token, err := provider.Exchange(ctx, r.URL.Query().Get("code"), oauth2.VerifierOption(verifier))
	if err != nil {
		return "", httpio.NewInternalServerErrorMessageWithError(err, "Failed to exchange token")
	}

	rawIDToken, ok := oauth2Token.Extra("id_token").(string)
	if !ok {
		return "", httpio.NewInternalServerErrorMessage("No id_token in token response")
	}

	idToken, err := provider.Verify(ctx, rawIDToken)
	if err != nil {
		return "", httpio.NewInternalServerErrorMessageWithError(err, "Failed to verify ID token")
	}

	// Enforce the hosted-domain restriction on the verified token. Unlike the hd
	// request parameter, the hd claim is inside the Google-signed token and can be
	// trusted; a consumer account has no hd claim and fails closed.
	var gClaims struct {
		Hd            string `json:"hd"`
		EmailVerified bool   `json:"email_verified"` //nolint:tagliatelle // Google's claim name
	}
	if err := idToken.Claims(&gClaims); err != nil {
		return "", httpio.NewInternalServerErrorMessageWithError(err, "Failed to parse ID token claims")
	}
	if !strings.EqualFold(gClaims.Hd, o.hostedDomain) {
		return "", httpio.NewForbiddenMessage("Account is not a member of the required Google Workspace domain")
	}
	if !gClaims.EmailVerified {
		return "", httpio.NewForbiddenMessage("Account email is not verified")
	}

	// Extract the claims from the ID Token
	if err := idToken.Claims(&claims); err != nil {
		return "", httpio.NewInternalServerErrorMessageWithError(err, "Failed to parse ID token claims")
	}

	return returnURL, nil
}
