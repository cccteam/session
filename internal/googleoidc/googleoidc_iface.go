package googleoidc

import (
	"context"
	"net/http"
)

// Authenticator defines the interface for authenticating users via OpenID Connect.
type Authenticator interface {
	// AuthCodeURL returns the URL to redirect to in order to initiate the OIDC authentication process
	AuthCodeURL(ctx context.Context, w http.ResponseWriter, returnURL string) (string, error)

	// Verify performs the necessary verification and processing of the OIDC callback
	// request, including the hosted-domain (hd claim) and verified-email checks.
	// It populates 'claims' with the ID Token's claims and returns the URL to redirect
	// to following successful authentication. Google issues no sid claim, so no OIDC
	// session ID is returned.
	Verify(ctx context.Context, w http.ResponseWriter, r *http.Request, claims any) (returnURL string, err error)

	// LoginURL returns the URL to redirect to when an error occurs during the OIDC authentication process
	LoginURL() string
}
