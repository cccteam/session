// Package loader contains interfaces for safely accessing an OIDC Provider.
package loader

import (
	"context"
	"sync"
	"time"

	"github.com/coreos/go-oidc/v3/oidc"
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

	mu       sync.RWMutex
	provider *provider
}

// New creates a new OIDC loader.
func New(issuerURL, clientID, clientSecret, redirectURL string) Loader {
	return &loader{
		issuerURL:    issuerURL,
		clientID:     clientID,
		clientSecret: clientSecret,
		redirectURL:  redirectURL,
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
		return nil, errors.Wrap(err, "newProvider()")
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
	expire, cancel := context.WithTimeoutCause(ctx, 5*time.Second, errors.New("oidc.NewProvider() timeout"))
	defer cancel()

	newProvider, err := oidc.NewProvider(expire, l.issuerURL)
	if err != nil {
		return errors.Wrap(err, "oidc.NewProvider()")
	}

	l.provider = &provider{
		provider: newProvider,
		config: oauth2.Config{
			ClientID:     l.clientID,
			ClientSecret: l.clientSecret,
			RedirectURL:  l.redirectURL,
			Endpoint:     newProvider.Endpoint(),
			Scopes:       []string{oidc.ScopeOpenID, "profile"},
		},
	}

	return nil
}
