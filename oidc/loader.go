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

	mu       sync.RWMutex
	provider *provider
}

// New creates a new OIDC loader. scopes is the OAuth2 scope set requested at
// authorization time; it must include the openid scope.
func New(issuerURL, clientID, clientSecret, redirectURL string, scopes []string) Loader {
	return &loader{
		issuerURL:    issuerURL,
		clientID:     clientID,
		clientSecret: clientSecret,
		redirectURL:  redirectURL,
		scopes:       scopes,
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

	newProvider, err := gooidc.NewProvider(expire, l.issuerURL)
	if err != nil {
		return errors.Wrap(err, "gooidc.NewProvider()")
	}

	l.provider = &provider{
		provider: newProvider,
		config: oauth2.Config{
			ClientID:     l.clientID,
			ClientSecret: l.clientSecret,
			RedirectURL:  l.redirectURL,
			Endpoint:     newProvider.Endpoint(),
			Scopes:       l.scopes,
		},
	}

	return nil
}
