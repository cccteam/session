package loader

import (
	"context"

	"github.com/coreos/go-oidc/v3/oidc"
	"github.com/go-playground/errors/v5"
	"golang.org/x/oauth2"
)

var _ Provider = &provider{}

type provider struct {
	provider *oidc.Provider
	config   oauth2.Config
}

func (o *provider) AuthCodeURL(state string, opts ...oauth2.AuthCodeOption) string {
	return o.config.AuthCodeURL(state, opts...)
}

func (o *provider) Exchange(ctx context.Context, code string, opts ...oauth2.AuthCodeOption) (*oauth2.Token, error) {
	t, err := o.config.Exchange(ctx, code, opts...)
	if err != nil {
		return nil, errors.Wrap(err, "oauth2.Config.Exchange()")
	}

	return t, nil
}

func (o *provider) Verifier() *oidc.IDTokenVerifier {
	return o.provider.Verifier(&oidc.Config{ClientID: o.config.ClientID})
}
