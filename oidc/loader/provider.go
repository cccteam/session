// provider contains interfaces for safely accessing an OIDC Provider
package loader

import (
	"context"
	"sync"

	"github.com/coreos/go-oidc/v3/oidc"
	"github.com/go-playground/errors/v5"
	"golang.org/x/oauth2"
)

const defaultLoginURL = "/login"

type provider struct {
	loginURL     string
	issuerURL    string
	clientID     string
	clientSecret string
	redirectURL  string

	mu       sync.RWMutex
	provider *OIDCConfig
}

func New(issuerURL, clientID, clientSecret, redirectURL string) Loader {
	return &provider{
		issuerURL:    issuerURL,
		clientID:     clientID,
		clientSecret: clientSecret,
		redirectURL:  redirectURL,
	}
}

func (p *provider) Provider(ctx context.Context) (Provider, error) {
	p.mu.RLock()
	if p.provider != nil {
		p.mu.RUnlock()

		return p.provider, nil
	}

	p.mu.RUnlock()
	p.mu.Lock()
	defer p.mu.Unlock()

	if p.provider != nil {
		return p.provider, nil
	}

	if err := p.newProvider(ctx); err != nil {
		return nil, errors.Wrap(err, "newProvider()")
	}

	return p.provider, nil
}

func (p *provider) SetLoginURL(url string) {
	p.loginURL = url
}

func (p *provider) LoginURL() string {
	if p.loginURL == "" {
		return defaultLoginURL
	}

	return p.loginURL
}

func (p *provider) newProvider(ctx context.Context) error {
	newProvider, err := oidc.NewProvider(ctx, p.issuerURL)
	if err != nil {
		return errors.Wrap(err, "oidc.NewProvider()")
	}

	p.provider = &OIDCConfig{
		provider: newProvider,
		config: oauth2.Config{
			ClientID:     p.clientID,
			ClientSecret: p.clientSecret,
			RedirectURL:  p.redirectURL,
			Endpoint:     newProvider.Endpoint(),
			Scopes:       []string{oidc.ScopeOpenID, "profile"},
		},
	}

	return nil
}
