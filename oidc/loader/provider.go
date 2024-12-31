package loader

import (
	"context"
	"time"

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
	expire, cancel := context.WithTimeoutCause(ctx, 5*time.Second, errors.New("oauth2.Config.Exchange() timeout"))
	defer cancel()

	t, err := o.config.Exchange(expire, code, opts...)
	if err != nil {
		return nil, errors.Wrap(err, "oauth2.Config.Exchange()")
	}

	return t, nil
}

func (o *provider) Verify(ctx context.Context, rawIDToken string) (*oidc.IDToken, error) {
	expire, cancel := context.WithTimeoutCause(ctx, 5*time.Second, errors.New("oidc.IDTokenVerifier.Verify() timeout"))
	defer cancel()

	token, err := o.provider.Verifier(&oidc.Config{ClientID: o.config.ClientID}).Verify(expire, rawIDToken)
	if err != nil {
		return nil, errors.Wrap(err, "oidc.IDTokenVerifier.Verify()")
	}

	return token, nil
}
