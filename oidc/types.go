package oidc

import (
	"context"

	"github.com/go-playground/errors/v5"
	"golang.org/x/oauth2"
)

var _ config = &oAuth2{}

type oAuth2 struct {
	config oauth2.Config
}

func (o *oAuth2) AuthCodeURL(state string, opts ...oauth2.AuthCodeOption) string {
	return o.config.AuthCodeURL(state, opts...)
}

func (o *oAuth2) Exchange(ctx context.Context, code string, opts ...oauth2.AuthCodeOption) (*oauth2.Token, error) {
	t, err := o.config.Exchange(ctx, code, opts...)
	if err != nil {
		return nil, errors.Wrap(err, "oauth2.Config.Exchange()")
	}

	return t, nil
}

func (o *oAuth2) ClientID() string {
	return o.config.ClientID
}
