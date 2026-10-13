package session

import (
	"net/http"
	"net/url"

	"github.com/cccteam/ccc/tracer"
	"github.com/cccteam/httpio"
	internalcookie "github.com/cccteam/session/internal/cookie"
	"github.com/cccteam/session/internal/sessioncore"
	"github.com/cccteam/session/sessioninfo"
	"github.com/cccteam/session/signin"
	"github.com/go-playground/errors/v5"
)

// externalLogin redirects the browser to the provider. A returnUrl that
// internalcookie.SanitizeReturnURL would change is refused with 400 rather than
// carried, so a crafted login link can't become an open redirect.
func (a *Auth[S, U, Tx]) externalLogin(m *signin.Method) http.HandlerFunc {
	return a.baseSession.Handle(func(w http.ResponseWriter, r *http.Request) error {
		ctx, span := tracer.Start(r.Context())
		defer span.End()

		returnURL := r.URL.Query().Get("returnUrl")
		if returnURL != "" && internalcookie.SanitizeReturnURL(returnURL) != returnURL {
			return httpio.NewEncoder(w).ClientMessage(ctx, httpio.NewBadRequestMessage("returnUrl must be a path in this application"))
		}

		providerURL, err := m.Begin(ctx, w, r, returnURL)
		if err != nil {
			if httpio.HasBadRequest(err) {
				return httpio.NewEncoder(w).ClientMessage(ctx, err)
			}
			sessioncore.RedirectRefusedLogin(w, r, m.LoginURL(), err)

			return errors.Wrap(err, string(m.Name)+": start the sign-in")
		}

		// The target is the provider's authorization URL, built from server-side
		// configuration; the caller's returnUrl only rides in the state cookie.
		// nosemgrep: go.lang.security.injection.open-redirect.open-redirect
		http.Redirect(w, r, providerURL, http.StatusFound)

		return nil
	})
}

// externalCallback completes the provider round trip. See the README's "The redirect
// and response contract" for where it redirects.
func (a *Auth[S, U, Tx]) externalCallback(m *signin.Method) http.HandlerFunc {
	return a.baseSession.Handle(func(w http.ResponseWriter, r *http.Request) error {
		ctx, span := tracer.Start(r.Context())
		defer span.End()

		v, err := m.Complete(ctx, w, r)
		if err != nil {
			sessioncore.RedirectRefusedLogin(w, r, m.LoginURL(), err)

			return errors.Wrap(err, string(m.Name)+": complete the sign-in")
		}

		outcome, err := a.signIn(ctx, w, &signInAttempt{
			identity:  v.Identity,
			reason:    sessioninfo.ReasonLogin,
			returnURL: v.ReturnURL,
			roleNames: v.RoleNames,
			sameSite:  sessioncore.SameSiteNone,
		})
		if err != nil {
			sessioncore.RedirectRefusedLogin(w, r, m.LoginURL(), err)

			return err
		}
		if outcome.pending != nil {
			target, handled, err := a.onPending(ctx, w, r, outcome.pending)
			switch {
			case handled:
				return err
			case err != nil:
				sessioncore.RedirectRefusedLogin(w, r, m.LoginURL(), err)

				return err
			case target == "":
				target = pendingRedirectURL(m.LoginURL(), outcome.pending.Reason, v.ReturnURL)
			}
			// The target is the configured login URL or the PendingHook's choice. It is
			// written as is, never cleaned.
			internalcookie.WriteRedirect(w, target, http.StatusFound)

			return nil
		}

		// The method already sanitized returnURL. It is sanitized again so the
		// Location header is exactly a value SanitizeReturnURL keeps.
		internalcookie.RedirectToReturnURL(w, v.ReturnURL, http.StatusFound)

		return nil
	})
}

// pendingRedirectURL returns where an external sign-in that became a pending identity
// sends the browser: the login URL with pending=<reason>, plus the sanitized returnUrl
// when it is not the root.
func pendingRedirectURL(loginURL string, reason sessioninfo.PendingReason, returnURL string) string {
	returnURL = internalcookie.SanitizeReturnURL(returnURL)
	u, err := url.Parse(loginURL)
	if err != nil {
		// An unparsable login URL still gets the reason, as a refusal gets its code.
		u = &url.URL{Path: loginURL}
	}
	q := u.Query()
	q.Set("pending", string(reason))
	if returnURL != "/" {
		q.Set("returnUrl", returnURL)
	}
	u.RawQuery = q.Encode()

	return u.String()
}
