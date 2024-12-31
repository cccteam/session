package loader

import (
	"context"

	"github.com/coreos/go-oidc/v3/oidc"
	"golang.org/x/oauth2"
)

type Loader interface {
	Provider(ctx context.Context) (Provider, error)
	LoginURL() string
	SetLoginURL(string)
}

type Provider interface {
	AuthCodeURL(state string, opts ...oauth2.AuthCodeOption) string
	Exchange(ctx context.Context, code string, opts ...oauth2.AuthCodeOption) (*oauth2.Token, error)
	Verify(ctx context.Context, rawIDToken string) (*oidc.IDToken, error)
}
