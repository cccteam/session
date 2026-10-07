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
	"github.com/cccteam/session/internal/cloudidentity"
	internalcookie "github.com/cccteam/session/internal/cookie"
	"github.com/cccteam/session/internal/googleoidc"
	"github.com/cccteam/session/internal/workossso"
	"github.com/cccteam/session/sessioninfo"
	"github.com/go-playground/errors/v5"
)

// externalMethod is a redirect-based sign-in method of an Auth session: how it starts
// the provider round trip, how it turns the callback into a verified identity, and how
// it reconciles roles once the account is known.
type externalMethod struct {
	method sessioninfo.AuthMethod
	// loginURL is where refused and pending sign-ins are sent.
	loginURL func() string
	// start writes the provider's state cookie and returns the provider URL.
	start func(ctx context.Context, w http.ResponseWriter, r *http.Request, returnURL string) (string, error)
	// verify completes the round trip into a verified sign-in.
	verify func(ctx context.Context, w http.ResponseWriter, r *http.Request) (*verifiedSignIn, error)
	// syncRoles reconciles the account username's roles to the role names the provider
	// asserted, refusing (no_roles) when no recognized role results. Nil when the method
	// synchronizes no roles.
	syncRoles func(ctx context.Context, username string, roleNames []string) error
	// frontChannelLogout says whether the provider has provider-initiated logout.
	frontChannelLogout bool
}

// verifiedSignIn is what a method's callback verified: the identity, where the browser
// goes afterwards (a sanitized local path), and the role names the provider asserted
// for role synchronization (nil when the method synchronizes no roles).
type verifiedSignIn struct {
	identity  *sessioninfo.Identity
	returnURL string
	roleNames []string
}

// newExternalMethod builds the external method cfg describes over the session's cookie
// client, which writes the method's state cookie.
func newExternalMethod(cookieClient *internalcookie.Client, cfg *signInMethodConfig) (*externalMethod, error) {
	switch cfg.method {
	case sessioninfo.MethodAzure:
		roleSync, err := azureRoleSync(cfg.azure.roleSync)
		if err != nil {
			return nil, err
		}
		authn := azureoidc.New(cookieClient, cfg.azure.issuerURL, cfg.azure.clientID, cfg.azure.clientSecret, cfg.azure.redirectURL)
		applyLoginOptions(authn, cfg.oidcOptions)

		return azureMethod(authn, roleSync), nil
	case sessioninfo.MethodGoogle:
		roleSync, err := googleRoleSync(cfg.google.roleSync, cfg.google.hostedDomain)
		if err != nil {
			return nil, err
		}
		// With role sync on, the sign-in also asks for the groups scope, so the access
		// token Verify hands back can read the person's own groups.
		var scopes []string
		if roleSync != nil {
			scopes = []string{cloudidentity.Scope}
		}
		authn := googleoidc.New(cookieClient, cfg.google.clientID, cfg.google.clientSecret, cfg.google.redirectURL, cfg.google.hostedDomain, scopes...)
		applyLoginOptions(authn, cfg.oidcOptions)

		return googleMethod(authn, roleSync), nil
	case sessioninfo.MethodWorkOS:
		authn := workossso.New(cookieClient, cfg.workos.apiKey, cfg.workos.clientID, cfg.workos.redirectURL)
		if cfg.workos.settings.baseURL != "" {
			authn.SetBaseURL(cfg.workos.settings.baseURL)
		}
		applyLoginOptions(authn, cfg.oidcOptions)

		return workOSMethod(authn), nil
	default:
		return nil, errors.Newf("unknown sign-in method %q", cfg.method)
	}
}

func applyLoginOptions(authn loginURLSetter, options []OIDCOption) {
	for _, o := range options {
		o(authn)
	}
}

// azureMethod is the Azure (Entra ID) method over authn. The identity is (tid, oid);
// roleSync, when set, reconciles the token's roles claim.
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
					Method: sessioninfo.MethodAzure, Connection: c.Tid, Subject: c.Oid, Email: c.Email, Claims: rawClaims, IdPAMR: c.Amr,
				},
				returnURL: returnURL,
			}
			if roleSync != nil {
				v.roleNames = nonNil(c.Roles)
			}

			return v, nil
		},
		frontChannelLogout: true,
	}
	if roleSync != nil {
		m.syncRoles = func(ctx context.Context, username string, roleNames []string) error {
			return roleSync.requireRoles(ctx, accesstypes.User(username), roleNames)
		}
	}

	return m
}

// googleMethod is the Google Workspace method over authn. The identity is sub; the
// hosted-domain and verified-email checks are the authenticator's. roleSync, when set,
// maps the person's directory groups to role names at the callback, with the access
// token that is used once and never stored.
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
					Method: sessioninfo.MethodGoogle, Subject: c.Sub, Email: c.Email, EmailVerified: c.EmailVerified, Claims: rawClaims, IdPAMR: c.Amr,
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

// workOSMethod is the WorkOS SSO method over authn. The identity is (connection_id,
// idp_id); the full profile is the identity's claims. WorkOS asserts emails on the
// upstream IdP's word, so EmailVerified is false and the account resolver decides what
// an email is worth. Roles are never synchronized.
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
					Method: sessioninfo.MethodWorkOS, Connection: profile.ConnectionID, Subject: profile.IdpID, Email: profile.Email, Claims: rawProfile,
				},
				returnURL: returnURL,
			}, nil
		},
	}
}

// nonNil is names, or an empty list for nil: a role-synchronizing method always
// carries a list, so "no roles asserted" and "the method synchronizes no roles" stay
// apart.
func nonNil(names []string) []string {
	if names == nil {
		return []string{}
	}

	return names
}

// externalHandlers returns the handlers of the configured external method.
func (a *Auth[S, U]) externalHandlers(method sessioninfo.AuthMethod) *ExternalHandlers {
	m, ok := a.external[method]
	if !ok {
		panic("session: the " + string(method) + " sign-in method is not configured: pass it to NewAuth")
	}

	return &ExternalHandlers{login: a.externalLogin(m), callback: a.externalCallback(m), frontChannelLogout: a.frontChannelLogout(m)}
}

// externalLogin redirects the browser to the provider. The returnUrl query parameter
// must be a path in this application: anything else (an absolute URL, //host, /\host)
// is refused with 400 rather than carried, so a crafted login link can't become an open
// redirect.
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
		http.Redirect(w, r, providerURL, http.StatusFound)

		return nil
	})
}

// externalCallback completes the provider round trip and redirects per the contract on
// ExternalHandlers.Callback.
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
			// The target is the login URL from server-side configuration, or the
			// application's own choice in its PendingHook.
			http.Redirect(w, r, target, http.StatusFound) //nolint:gosec // G710: not a caller-controlled redirect, see above

			return nil
		}

		// returnURL was sanitized to a local path by the authenticator.
		http.Redirect(w, r, v.returnURL, http.StatusFound)

		return nil
	})
}

// frontChannelLogout answers provider-initiated logout. Auth sessions do not record the
// provider's session ID yet, so Azure's answers 501; the other providers have none.
func (a *Auth[S, U]) frontChannelLogout(m *externalMethod) http.HandlerFunc {
	return a.baseSession.Handle(func(w http.ResponseWriter, r *http.Request) error {
		if !m.frontChannelLogout {
			return httpio.NewEncoder(w).ClientMessage(r.Context(), httpio.NewNotFoundMessagef("%s has no front-channel logout", m.method))
		}

		return httpio.NewEncoder(w).ClientMessage(r.Context(), httpio.NewNotImplementedMessage("front-channel logout is not supported by Auth sessions yet"))
	})
}

// pendingRedirectURL is where an external sign-in that became a pending identity sends
// the browser: the login URL with pending=<reason> and, when the sign-in carried one
// other than the root, returnUrl=<path>. The login page routes on pending to its
// confirmation or MFA step and reads the pending identity from Pending().Status().
func pendingRedirectURL(loginURL string, reason sessioninfo.PendingReason, returnURL string) string {
	u, err := url.Parse(loginURL)
	if err != nil {
		// The login URL is the application's configuration; one that does not parse
		// still gets the reason, appended as the refusal redirect would append a code.
		u = &url.URL{Path: loginURL}
	}
	q := u.Query()
	q.Set("pending", string(reason))
	if returnURL != "" && returnURL != "/" {
		q.Set("returnUrl", returnURL)
	}
	u.RawQuery = q.Encode()

	return u.String()
}
