package session

import (
	"context"
	"encoding/json"
	"net/http"
	"net/url"

	"github.com/cccteam/ccc/accesstypes"
	"github.com/cccteam/ccc/tracer"
	"github.com/cccteam/httpio"
	"github.com/cccteam/session/internal/azureoidc"
	internalcookie "github.com/cccteam/session/internal/cookie"
	"github.com/cccteam/session/internal/googleoidc"
	"github.com/cccteam/session/internal/workossso"
	"github.com/cccteam/session/sessioninfo"
	"github.com/go-playground/errors/v5"
)

// externalMethod is a redirect-based sign-in method of an Auth session.
type externalMethod struct {
	method sessioninfo.AuthMethod
	// loginURL is where refused and pending sign-ins are sent.
	loginURL func() string
	// start writes the provider's state cookie and returns the provider URL.
	start func(ctx context.Context, w http.ResponseWriter, r *http.Request, returnURL string) (string, error)
	// verify completes the round trip into a verified sign-in.
	verify func(ctx context.Context, w http.ResponseWriter, r *http.Request) (*verifiedSignIn, error)
	// syncRoles reconciles the user's roles to the role names the provider asserted.
	// It refuses with no_roles when no recognized role results. It is nil when the
	// method synchronizes no roles.
	syncRoles func(ctx context.Context, username string, roleNames []string) error
}

// verifiedSignIn is the result of a method's callback.
type verifiedSignIn struct {
	identity *sessioninfo.Identity
	// returnURL is the sanitized local path the browser goes to afterwards.
	returnURL string
	// roleNames are the role names the provider asserted. They are nil when the method
	// synchronizes no roles.
	roleNames []string
}

func applyLoginOptions(authn loginURLSetter, options []OIDCOption) {
	for _, o := range options {
		o(authn)
	}
}

// azureMethod is the Azure (Entra ID) method. The identity is (tid, oid). When roleSync
// is set, the token's roles claim is reconciled.
func azureMethod(authn azureoidc.Authenticator, roleSync *roleSyncConfig) *externalMethod {
	type claims struct {
		Tid   string   `json:"tid"`
		Oid   string   `json:"oid"`
		Email string   `json:"email"`
		Roles []string `json:"roles"`
		Amr   []string `json:"amr"`
	}

	m := &externalMethod{
		method:   sessioninfo.MethodAzure,
		loginURL: authn.LoginURL,
		start: func(ctx context.Context, w http.ResponseWriter, _ *http.Request, returnURL string) (string, error) {
			return authn.AuthCodeURL(ctx, w, returnURL)
		},
		verify: func(ctx context.Context, w http.ResponseWriter, r *http.Request) (*verifiedSignIn, error) {
			// Auth sessions do not record the provider's session ID (sid) yet.
			var rawClaims json.RawMessage
			returnURL, _, err := authn.Verify(ctx, w, r, &rawClaims)
			if err != nil {
				return nil, errors.Wrap(err, "azureoidc.Authenticator.Verify()")
			}
			c, err := decodeClaims[claims](rawClaims)
			if err != nil {
				return nil, sessioninfo.NewLoginRefusal(sessioninfo.RefusedClaimsParse, httpio.NewUnauthorizedMessageWithError(err, "Failed to parse ID token claims"))
			}
			if c.Tid == "" || c.Oid == "" {
				return nil, sessioninfo.NewLoginRefusal(sessioninfo.RefusedClaimsParse, httpio.NewUnauthorizedMessage("ID token carries no tid and oid"))
			}

			v := &verifiedSignIn{
				identity: &sessioninfo.Identity{
					Method: sessioninfo.MethodAzure, Connection: c.Tid, Subject: c.Oid, Email: c.Email, Claims: rawClaims, IDPAMR: c.Amr,
				},
				returnURL: returnURL,
			}
			if roleSync != nil {
				v.roleNames = nonNil(c.Roles)
			}

			return v, nil
		},
	}
	if roleSync != nil {
		m.syncRoles = func(ctx context.Context, username string, roleNames []string) error {
			return roleSync.requireRoles(ctx, accesstypes.User(username), roleNames)
		}
	}

	return m
}

// googleMethod is the Google Workspace method. The identity is sub. The authenticator
// checks the hosted domain and the verified email. When roleSync is set, the callback
// maps the person's directory groups to role names using the access token, which is
// used once and never stored.
func googleMethod(authn googleoidc.Authenticator, roleSync *googleRoleSyncConfig) *externalMethod {
	type claims struct {
		Sub           string   `json:"sub"`
		Email         string   `json:"email"`
		EmailVerified bool     `json:"email_verified"`
		Amr           []string `json:"amr"`
	}

	m := &externalMethod{
		method:   sessioninfo.MethodGoogle,
		loginURL: authn.LoginURL,
		start: func(ctx context.Context, w http.ResponseWriter, _ *http.Request, returnURL string) (string, error) {
			return authn.AuthCodeURL(ctx, w, returnURL)
		},
		verify: func(ctx context.Context, w http.ResponseWriter, r *http.Request) (*verifiedSignIn, error) {
			var rawClaims json.RawMessage
			returnURL, accessToken, err := authn.Verify(ctx, w, r, &rawClaims)
			if err != nil {
				return nil, errors.Wrap(err, "googleoidc.Authenticator.Verify()")
			}
			c, err := decodeClaims[claims](rawClaims)
			if err != nil {
				return nil, sessioninfo.NewLoginRefusal(sessioninfo.RefusedClaimsParse, httpio.NewUnauthorizedMessageWithError(err, "Failed to parse ID token claims"))
			}
			if c.Email == "" {
				return nil, sessioninfo.NewLoginRefusal(sessioninfo.RefusedNoEmailClaim, httpio.NewUnauthorizedMessage("Unauthorized: token carries no email claim"))
			}
			if c.Sub == "" {
				return nil, sessioninfo.NewLoginRefusal(sessioninfo.RefusedClaimsParse, httpio.NewUnauthorizedMessage("ID token carries no sub"))
			}

			v := &verifiedSignIn{
				identity: &sessioninfo.Identity{
					Method: sessioninfo.MethodGoogle, Subject: c.Sub, Email: c.Email, EmailVerified: c.EmailVerified, Claims: rawClaims, IDPAMR: c.Amr,
				},
				returnURL: returnURL,
			}
			if roleSync != nil {
				roleNames, err := roleSync.roleNames(ctx, c.Email, accessToken)
				if err != nil {
					return nil, errors.Wrap(err, "googleRoleSyncConfig.roleNames()")
				}
				v.roleNames = nonNil(roleNames)
			}

			return v, nil
		},
	}
	if roleSync != nil {
		m.syncRoles = func(ctx context.Context, username string, roleNames []string) error {
			return roleSync.requireRoles(ctx, accesstypes.User(username), roleNames)
		}
	}

	return m
}

// workOSMethod is the WorkOS SSO method. The identity is (connection_id, idp_id), and
// the full profile is its claims. WorkOS only relays the upstream IdP's email, so
// EmailVerified is false and the user resolver decides what the email is worth.
// Roles are never synchronized.
func workOSMethod(authn workossso.Authenticator) *externalMethod {
	return &externalMethod{
		method:   sessioninfo.MethodWorkOS,
		loginURL: authn.LoginURL,
		start: func(ctx context.Context, w http.ResponseWriter, r *http.Request, returnURL string) (string, error) {
			return authn.AuthorizationURL(ctx, w, r.URL.Query().Get("organization"), returnURL)
		},
		verify: func(ctx context.Context, w http.ResponseWriter, r *http.Request) (*verifiedSignIn, error) {
			returnURL, profile, rawProfile, err := authn.Verify(ctx, w, r)
			if err != nil {
				return nil, errors.Wrap(err, "workossso.Authenticator.Verify()")
			}

			return &verifiedSignIn{
				identity: &sessioninfo.Identity{
					Method: sessioninfo.MethodWorkOS, Connection: profile.ConnectionID, Subject: profile.IDPID, Email: profile.Email, Claims: rawProfile,
				},
				returnURL: returnURL,
			}, nil
		},
	}
}

// nonNil returns names, or an empty list for nil. A role-synchronizing method always
// carries a list, so "no roles asserted" stays distinct from "no role sync".
func nonNil(names []string) []string {
	if names == nil {
		return []string{}
	}

	return names
}

// externalLogin redirects the browser to the provider. A returnUrl that
// internalcookie.SanitizeReturnURL would change is refused with 400 rather than
// carried, so a crafted login link can't become an open redirect.
func (a *Auth[S, U]) externalLogin(m *externalMethod) http.HandlerFunc {
	return a.baseSession.Handle(func(w http.ResponseWriter, r *http.Request) error {
		ctx, span := tracer.Start(r.Context())
		defer span.End()

		returnURL := r.URL.Query().Get("returnUrl")
		if returnURL != "" && internalcookie.SanitizeReturnURL(returnURL) != returnURL {
			return httpio.NewEncoder(w).ClientMessage(ctx, httpio.NewBadRequestMessage("returnUrl must be a path in this application"))
		}

		providerURL, err := m.start(ctx, w, r, returnURL)
		if err != nil {
			if httpio.HasBadRequest(err) {
				return httpio.NewEncoder(w).ClientMessage(ctx, err)
			}
			redirectRefusedLogin(w, r, m.loginURL(), err)

			return errors.Wrap(err, string(m.method)+": start the sign-in")
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
func (a *Auth[S, U]) externalCallback(m *externalMethod) http.HandlerFunc {
	return a.baseSession.Handle(func(w http.ResponseWriter, r *http.Request) error {
		ctx, span := tracer.Start(r.Context())
		defer span.End()

		v, err := m.verify(ctx, w, r)
		if err != nil {
			redirectRefusedLogin(w, r, m.loginURL(), err)

			return err
		}

		outcome, err := a.signIn(ctx, w, &signInAttempt{
			identity:  v.identity,
			reason:    sessioninfo.ReasonLogin,
			returnURL: v.returnURL,
			roleNames: v.roleNames,
			sameSite:  sameSiteNone,
		})
		if err != nil {
			redirectRefusedLogin(w, r, m.loginURL(), err)

			return err
		}
		if outcome.pending != nil {
			target, handled, err := a.onPending(ctx, w, r, outcome.pending)
			switch {
			case handled:
				return err
			case err != nil:
				redirectRefusedLogin(w, r, m.loginURL(), err)

				return err
			case target == "":
				target = pendingRedirectURL(m.loginURL(), outcome.pending.Reason, v.returnURL)
			}
			// The target is the configured login URL or the PendingHook's choice. It is
			// written as is, never cleaned.
			internalcookie.WriteRedirect(w, target, http.StatusFound)

			return nil
		}

		// The authenticator already sanitized returnURL. It is sanitized again so the
		// Location header is exactly a value SanitizeReturnURL keeps.
		internalcookie.RedirectToReturnURL(w, v.returnURL, http.StatusFound)

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
