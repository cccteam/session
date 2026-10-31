package oidc

import (
	"context"
	"net/http"

	"github.com/cccteam/session/signin"
)

// Authenticator is what the generic method runs its round trip through: the verifier
// over the provider's discovered configuration in production, a fake in tests.
type Authenticator interface {
	// AuthCodeURL writes the state cookie and returns the provider's authorization URL
	// to redirect to. options carry the login page's hints: the login hint and whether
	// the provider shows its account chooser (prompt=select_account).
	AuthCodeURL(ctx context.Context, w http.ResponseWriter, returnURL string, options signin.LoginOptions) (string, error)

	// Verify completes the callback: it binds it to the login the state cookie
	// recorded, exchanges the code and verifies the ID token's signature, issuer,
	// audience and expiry. It populates claims with the ID token's claims and returns
	// the sanitized path the browser goes to next.
	Verify(ctx context.Context, w http.ResponseWriter, r *http.Request, claims any) (returnURL string, err error)

	// LoginURL is where refused and pending sign-ins are sent.
	LoginURL() string
}
