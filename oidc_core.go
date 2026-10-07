package session

import (
	"context"
	"encoding/json"
	"net/http"

	"github.com/cccteam/ccc/accesstypes"
	"github.com/cccteam/ccc/tracer"
	"github.com/cccteam/httpio"
	"github.com/cccteam/session/internal/basesession"
	"github.com/cccteam/session/sessioninfo"
	"github.com/go-playground/errors/v5"
)

// oidcLoginStarter is the part of an OIDC provider's authenticator the shared login and
// callback shells use. Every provider's authenticator implements it.
type oidcLoginStarter interface {
	// AuthCodeURL writes the provider's state cookie and returns the authorization URL.
	AuthCodeURL(ctx context.Context, w http.ResponseWriter, returnURL string) (string, error)
	// LoginURL is where a refused login is sent, with ?code=.
	LoginURL() string
}

// oidcLogin is the login handler every OIDC provider shares: it redirects the browser to
// the provider's authorization URL, or back to the login page with a refusal code.
// authenticatorName names the authenticator in wrapped errors.
func oidcLogin(base *basesession.BaseSession, authn oidcLoginStarter, authenticatorName string) http.HandlerFunc {
	return base.Handle(func(w http.ResponseWriter, r *http.Request) error {
		ctx, span := tracer.Start(r.Context())
		defer span.End()

		returnURL := r.URL.Query().Get("returnUrl")
		authCodeURL, err := authn.AuthCodeURL(ctx, w, returnURL)
		if err != nil {
			redirectRefusedLogin(w, r, authn.LoginURL(), err)

			return errors.Wrap(err, authenticatorName+".Authenticator.AuthCodeURL()")
		}

		http.Redirect(w, r, authCodeURL, http.StatusFound)

		return nil
	})
}

// oidcCallback is the shell every OIDC provider's callback shares. complete does the
// provider's work (verify, decode, synchronize roles, establish the session) and
// returns the URL to send the browser to. Any error it returns, from any step, sends the
// browser to the login page with the error's refusal code and goes to the log; no step
// redirects on its own.
func oidcCallback(
	base *basesession.BaseSession, authn oidcLoginStarter, complete func(ctx context.Context, w http.ResponseWriter, r *http.Request) (returnURL string, err error),
) http.HandlerFunc {
	return base.Handle(func(w http.ResponseWriter, r *http.Request) error {
		ctx, span := tracer.Start(r.Context())
		defer span.End()

		returnURL, err := complete(ctx, w, r)
		if err != nil {
			redirectRefusedLogin(w, r, authn.LoginURL(), err)

			return err
		}

		http.Redirect(w, r, returnURL, http.StatusFound)

		return nil
	})
}

// decodeClaims decodes the fields a callback needs from the full verified claims
// payload.
func decodeClaims[C any](rawClaims json.RawMessage) (*C, error) {
	claims := new(C)
	if err := json.Unmarshal(rawClaims, claims); err != nil {
		return nil, errors.Wrap(err, "json.Unmarshal()")
	}

	return claims, nil
}

// requireRoles reconciles username's roles to roleNames and refuses the login, with
// RefusedNoRoles, when no recognized role results.
func (r *roleSyncConfig) requireRoles(ctx context.Context, username accesstypes.User, roleNames []string) error {
	hasRole, err := r.reconcile(ctx, username, roleNames)
	if err != nil {
		return errors.Wrap(err, "roleSyncConfig.reconcile()")
	}
	if !hasRole {
		return sessioninfo.NewLoginRefusal(sessioninfo.RefusedNoRoles, httpio.NewUnauthorizedMessage("Unauthorized: user has no roles"))
	}

	return nil
}
