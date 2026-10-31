// Package oidc is the OpenID Connect machinery the identity provider packages build
// on: the provider loader (discovery), the authorization code flow with PKCE and the
// state cookie, and the claims decoding.
package oidc

import (
	"context"
	"sync"
	"time"

	gooidc "github.com/coreos/go-oidc/v3/oidc"
	"github.com/go-playground/errors/v5"
	"golang.org/x/oauth2"
)

const defaultLoginURL = "/login"

type loader struct {
	loginURL     string
	issuerURL    string
	clientID     string
	clientSecret string
	redirectURL  string
	scopes       []string
	// sharedEndpoint marks a discovery document that names its issuer with a
	// placeholder, so the issuer is not checked against it: see NewSharedEndpoint.
	sharedEndpoint bool

	mu       sync.RWMutex
	provider *provider
}

// New creates a new OIDC loader for the provider at issuerURL, whose discovery
// document must name that issuer and whose tokens must carry it. scopes is the OAuth2
// scope set requested at authorization time; it must include the openid scope. An
// empty clientSecret is a public client, which authenticates the code exchange with
// its client ID alone.
func New(issuerURL, clientID, clientSecret, redirectURL string, scopes []string) Loader {
	return &loader{
		issuerURL:    issuerURL,
		clientID:     clientID,
		clientSecret: clientSecret,
		redirectURL:  redirectURL,
		scopes:       scopes,
	}
}

// NewSharedEndpoint creates a loader for a provider configuration read at
// discoveryURL whose document names its issuer with a placeholder, as the Microsoft
// identity platform's organizations, common and consumers endpoints do: the document
// is accepted as it is, and a token's issuer is not checked against it. The caller
// must check the token's issuer itself, against the tenant the token names, before
// trusting the token; the signature, audience and expiry are checked as always.
func NewSharedEndpoint(discoveryURL, clientID, clientSecret, redirectURL string, scopes []string) Loader {
	return &loader{
		issuerURL:      discoveryURL,
		clientID:       clientID,
		clientSecret:   clientSecret,
		redirectURL:    redirectURL,
		scopes:         scopes,
		sharedEndpoint: true,
	}
}

// Provider returns the OIDC provider.
func (l *loader) Provider(ctx context.Context) (Provider, error) {
	l.mu.RLock()
	if l.provider != nil {
		l.mu.RUnlock()

		return l.provider, nil
	}

	l.mu.RUnlock()
	l.mu.Lock()
	defer l.mu.Unlock()

	if l.provider != nil {
		return l.provider, nil
	}

	if err := l.newProvider(ctx); err != nil {
		return nil, errors.Wrap(err, "loader.newProvider()")
	}

	return l.provider, nil
}

// SetLoginURL sets the URL to redirect to when an error occurs during the OIDC authentication process
func (l *loader) SetLoginURL(url string) {
	l.loginURL = url
}

// LoginURL returns the URL to redirect to when an error occurs during the OIDC authentication process
func (l *loader) LoginURL() string {
	if l.loginURL == "" {
		return defaultLoginURL
	}

	return l.loginURL
}

func (l *loader) newProvider(ctx context.Context) error {
	expire, cancel := context.WithTimeoutCause(ctx, 5*time.Second, errors.New("gooidc.NewProvider() timeout"))
	defer cancel()

	if l.sharedEndpoint {
		// The document's issuer is a placeholder: discovery accepts it as read from
		// the endpoint, and Verify leaves the issuer check to the caller.
		expire = gooidc.InsecureIssuerURLContext(expire, l.issuerURL)
	}
	newProvider, err := gooidc.NewProvider(expire, l.issuerURL)
	if err != nil {
		return errors.Wrap(err, "gooidc.NewProvider()")
	}

	endpoint := newProvider.Endpoint()
	if l.clientSecret == "" {
		// A public client has no secret to send: the code exchange carries the client ID
		// in the request body alone, never an authorization header with an empty password.
		endpoint.AuthStyle = oauth2.AuthStyleInParams
	}

	l.provider = &provider{
		provider:        newProvider,
		skipIssuerCheck: l.sharedEndpoint,
		config: oauth2.Config{
			ClientID:     l.clientID,
			ClientSecret: l.clientSecret,
			RedirectURL:  l.redirectURL,
			Endpoint:     endpoint,
			Scopes:       l.scopes,
		},
	}

	return nil
}
