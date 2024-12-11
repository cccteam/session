package oidc

import (
	"context"
	"net/http"

	"github.com/coreos/go-oidc/v3/oidc"
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

	// LoginURL returns the URL to redirect to when an error occurs during the OIDC authentication process
	LoginURL() string
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
