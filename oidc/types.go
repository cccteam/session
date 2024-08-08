package oidc

import (
	"context"
	"net/http"

	"github.com/coreos/go-oidc/v3/oidc"
	"github.com/go-playground/errors/v5"
	"golang.org/x/oauth2"
)

type Authenticator interface {
	// AuthCodeURL returns the URL to redirect to in order to initiate the OIDC authentication process
	AuthCodeURL(w http.ResponseWriter, returnURL string) (string, error)

	// Verify performs the necessary verification and processing of the OIDC callback request.
	// It populates 'claims' with the ID Token's claims and returns:
	//		- the URL to redirect to following successful authentication
	//		- the 'sid' value from the session_state query parameter
	Verify(ctx context.Context, w http.ResponseWriter, r *http.Request, claims any) (returnURL, oidcSID string, err error)
}

// Defined for testability
type provider interface {
	Verifier(config *oidc.Config) *oidc.IDTokenVerifier
	Endpoint() oauth2.Endpoint
}

// Defined for testability
type config interface {
	AuthCodeURL(state string, opts ...oauth2.AuthCodeOption) string
	Exchange(ctx context.Context, code string, opts ...oauth2.AuthCodeOption) (*oauth2.Token, error)
	ClientID() string
}

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
