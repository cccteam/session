// provider contains interfaces for safely accessing an OIDC Provider
package provider

import (
	"context"
	"sync"

	"github.com/coreos/go-oidc/v3/oidc"
	"github.com/go-playground/errors/v5"
	"golang.org/x/oauth2"
)

const defaultLoginURL = "/login"

type Provider struct {
	loginURL     string
	issuerURL    string
	clientID     string
	clientSecret string
	redirectURL  string

	provider *oidcConfig

	mu sync.RWMutex
}

func New(issuerURL, clientID, clientSecret, redirectURL string) *Provider {
	return &Provider{
		issuerURL:    issuerURL,
		clientID:     clientID,
		clientSecret: clientSecret,
		redirectURL:  redirectURL,
	}
}

func (p *Provider) OidcProvider(ctx context.Context) (oidcProvider, error) {
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

	err := p.newOidcProvider(ctx)
	if err != nil {
		return nil, errors.Wrap(err, "newOidcProvider()")
	}

	return p.provider, nil
}

func (p *Provider) SetLoginURL(url string) {
	p.loginURL = url
}

func (p *Provider) LoginURL() string {
	if p.loginURL == "" {
		return defaultLoginURL
	}

	return p.loginURL
}

func (p *Provider) newOidcProvider(ctx context.Context) error {
	newProvider, err := oidc.NewProvider(ctx, p.issuerURL)
	if err != nil {
		return errors.Wrap(err, "oidc.NewProvider()")
	}

	p.provider = &oidcConfig{
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
