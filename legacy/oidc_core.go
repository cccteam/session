package legacy

import (
	"context"
	"net/http"

	"github.com/cccteam/ccc/tracer"
	"github.com/cccteam/session/internal/basesession"
	internalcookie "github.com/cccteam/session/internal/cookie"
	"github.com/cccteam/session/internal/sessioncore"
	"github.com/go-playground/errors/v5"
)

// oidcLoginStarter is the part of an OIDC authenticator that oidcLogin and oidcCallback
// use.
type oidcLoginStarter interface {
	// AuthCodeURL writes the provider's state cookie and returns the authorization URL.
	AuthCodeURL(ctx context.Context, w http.ResponseWriter, returnURL string) (string, error)
	// LoginURL is where a refused login is sent, with ?code=.
	LoginURL() string
}

// oidcLogin is the login handler every OIDC provider shares. It redirects the browser
// to the provider, or back to the login page with a refusal code. authenticatorName
// names the authenticator in wrapped errors.
func oidcLogin(base *basesession.BaseSession, authn oidcLoginStarter, authenticatorName string) http.HandlerFunc {
	return base.Handle(func(w http.ResponseWriter, r *http.Request) error {
		ctx, span := tracer.Start(r.Context())
		defer span.End()

		returnURL := r.URL.Query().Get("returnUrl")
		authCodeURL, err := authn.AuthCodeURL(ctx, w, returnURL)
		if err != nil {
			sessioncore.RedirectRefusedLogin(w, r, authn.LoginURL(), err)

			return errors.Wrap(err, authenticatorName+".Authenticator.AuthCodeURL()")
		}

		// The target is the provider's authorization URL. The caller's returnUrl only
		// rides in the state cookie and is sanitized on the callback.
		// nosemgrep: go.lang.security.injection.open-redirect.open-redirect
		http.Redirect(w, r, authCodeURL, http.StatusFound)

		return nil
	})
}

// oidcCallback is the callback handler every OIDC provider shares. complete does the
// provider's work and returns where the browser goes next. Any error from complete
// sends the browser to the login page with the error's refusal code. No step redirects
// on its own.
func oidcCallback(
	base *basesession.BaseSession, authn oidcLoginStarter, complete func(ctx context.Context, w http.ResponseWriter, r *http.Request) (returnURL string, err error),
) http.HandlerFunc {
	return base.Handle(func(w http.ResponseWriter, r *http.Request) error {
		ctx, span := tracer.Start(r.Context())
		defer span.End()

		returnURL, err := complete(ctx, w, r)
		if err != nil {
			sessioncore.RedirectRefusedLogin(w, r, authn.LoginURL(), err)

			return err
		}

		// The verifier already sanitized returnURL. It is sanitized again so the
		// Location header is exactly a value SanitizeReturnURL keeps.
		internalcookie.RedirectToReturnURL(w, returnURL, http.StatusFound)

		return nil
	})
}
