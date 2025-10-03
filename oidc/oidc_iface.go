package oidc

import (
	"context"
	"net/http"
)

// Authenticator defines the interface for authenticating users via OpenID Connect.
type Authenticator interface {
	// AuthCodeURL returns the URL to redirect to in order to initiate the OIDC authentication process
	AuthCodeURL(ctx context.Context, w http.ResponseWriter, returnURL string) (string, error)

	// Verify performs the necessary verification and processing of the OIDC callback request.
	// It populates 'claims' with the ID Token's claims and returns:
	//		- the URL to redirect to following successful authentication
	//		- the 'sid' value from the session_state query parameter
	Verify(ctx context.Context, w http.ResponseWriter, r *http.Request, claims any) (returnURL, oidcSID string, err error)

	// LoginURL returns the URL to redirect to when an error occurs during the OIDC authentication process
	LoginURL() string
}
