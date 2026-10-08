package session

// CONTRACT (multi-method sessions, v0.13.0): the exported types, constructors and
// method signatures in this file are the agreed contract. See the "Auth sessions
// (multiple sign-in methods)" section of the README.

import (
	"context"
	"net/http"
	"time"

	"github.com/cccteam/ccc"
	"github.com/cccteam/ccc/securehash"
	"github.com/cccteam/ccc/tracer"
	"github.com/cccteam/httpio"
	"github.com/cccteam/session/cookie"
	"github.com/cccteam/session/internal/basesession"
	internalcookie "github.com/cccteam/session/internal/cookie"
	"github.com/cccteam/session/sessioninfo"
	"github.com/cccteam/session/sessionstorage"
	"github.com/go-playground/errors/v5"
)

var _ basesession.Handlers = &Auth[NoCustomData, NoCustomData]{}

// AuthOption configures an Auth session.
type AuthOption interface {
	isAuthOption()
}

func (CookieOption) isAuthOption()      {}
func (BaseSessionOption) isAuthOption() {}

// authSettings holds Auth-only settings.
type authSettings struct {
	identityLinked IdentityLinkedHook
	pendingHook    PendingHook
	pendingTimeout time.Duration
	pendingCookie  string
}

type authOption func(*authSettings)

func (authOption) isAuthOption() {}

// The defaults of the pending-identity settings.
const (
	defaultPendingTimeout    = 10 * time.Minute
	defaultPendingCookieName = "auth-pending"
)

// IdentityLinkedHook is called after an external identity is linked to an account, so
// the application can notify the user.
type IdentityLinkedHook = func(ctx context.Context, userID ccc.UUID, identity *sessioninfo.Identity) error

// WithIdentityLinked sets the hook called after every identity link: a link made by a
// pending identity's password confirmation, and a link the account resolver made during
// a sign-in (LinkIdentity or ProvisionAccount). The resolver's link is committed before
// the sign-in policy decides, so it is reported even when the policy then denies the
// sign-in or holds it for MFA. An error from the hook is logged; the link and the
// sign-in stand.
func WithIdentityLinked(hook IdentityLinkedHook) AuthOption {
	return authOption(func(s *authSettings) { s.identityLinked = hook })
}

// PendingHook is called when a sign-in handler has just held a sign-in as a pending
// identity, so the application can act on it: send its MFA code to the account, record
// the attempt, choose where the browser goes. pending is the stored identity (the
// account it waits on in UserID and Username, the asserted email in Identity.Email).
//
// The hook may write the response itself (a redirect, a JSON body); the handler then
// writes nothing more. Otherwise it returns where the browser goes: the external
// Callback() redirects there, and the JSON handlers answer it as "redirectUrl"; an empty
// URL keeps the default (<LoginURL>?pending=<reason>[&returnUrl=<path>], or no
// "redirectUrl"). The URL is the application's own, never built from request input.
//
// An error discards the pending identity and fails the sign-in: Callback() redirects to
// <LoginURL>?code=internal_error, a JSON handler answers the error. The hook runs after
// the pending identity is stored and its cookie set, and changes nothing about it: the
// session ID is regenerated only when the pending identity completes, and its timeout
// and encrypted cookie stand.
type PendingHook = func(ctx context.Context, w http.ResponseWriter, r *http.Request, pending *sessioninfo.PendingIdentity) (redirectURL string, err error)

// WithPendingHook sets the hook the sign-in handlers call after they hold a sign-in as a
// pending identity: PasswordMethod.Login(), every external method's Callback(), and
// Pending().ConfirmWithPassword() when the policy then requires MFA. The AuthAPI methods
// never call it: they return a *sessionstorage.PendingSignInError to their caller.
func WithPendingHook(hook PendingHook) AuthOption {
	return authOption(func(s *authSettings) { s.pendingHook = hook })
}

// WithPendingTimeout sets how long a pending identity waits for confirmation or MFA.
// (default: 10m)
func WithPendingTimeout(d time.Duration) AuthOption {
	return authOption(func(s *authSettings) { s.pendingTimeout = d })
}

// WithPendingCookieName sets the cookie name of the pending-identity stepping-stone
// session. (default: "auth-pending")
func WithPendingCookieName(name string) AuthOption {
	return authOption(func(s *authSettings) { s.pendingCookie = name })
}

// Auth is one session type that any registered sign-in method can establish. It owns
// accounts, sessions, cookies, XSRF, custom session and user data, impersonation, and
// the middleware, the same for every method.
//
// Sign-in methods are registered on it after NewAuth, before it serves its first
// request: PasswordSignIn, AzureSignIn, GoogleSignIn and WorkOSSignIn each return the
// method's own handlers, from which its routes are wired.
//
// Every session belongs to an account (SessionUsers) by UserId, and ValidateSession
// loads that account on every request, refusing a disabled one. A sign-in either
// establishes a session (with a new session ID), becomes a pending identity that waits
// for a password confirmation or the application's MFA step, or is refused with a
// sessioninfo.LoginRefusalCode. See the "Auth sessions (multiple sign-in methods)"
// section of the README for the routes and the redirect contract.
type Auth[SessionData, UserData any] struct {
	baseSession *basesession.BaseSession
	storage     sessionstorage.AccountStore
	settings    authSettings

	// cookies is the session's cookie client, which also writes the external methods'
	// state cookies.
	cookies *internalcookie.Client
	// pendingCookies writes the pending-identity cookie.
	pendingCookies *internalcookie.Client
	// methods are the registered sign-in methods. Read them through registered().
	methods signInMethods
}

// NewAuth creates an Auth session for the given storage. Register its sign-in methods
// on it before it serves a request (PasswordSignIn, AzureSignIn, GoogleSignIn,
// WorkOSSignIn). The storage's custom session and user data configurations must be
// built for SessionData and UserData; the OIDC-only storage features (the OIDC user
// anchor, the custom user data login hook) are refused. An external method needs
// storage with an identities configuration, which its registration checks.
// cookieKey: a Base64-encoded string representing at least 32 bytes of
// cryptographically secure random data.
func NewAuth[SessionData, UserData any](storage sessionstorage.AccountStore, cookieKey string, options ...AuthOption) (*Auth[SessionData, UserData], error) {
	if storage == nil {
		return nil, errors.New("storage is required: pass sessionstorage.NewSpannerAccounts or NewPostgresAccounts")
	}
	if err := verifyCustomDataTypes[SessionData, UserData](storage); err != nil {
		return nil, err
	}
	if storage.UserDataLoginHookConfigured() {
		return nil, errors.New("the custom user data login hook is OIDC-only: provision custom user data in the account resolver (Resolution.OnProvisioned) or per call on CreateSessionUser")
	}
	if storage.OIDCUsersEnabled() {
		return nil, errors.New("the OIDC user anchor (WithOIDCUsers) is OIDC-only: Auth accounts are SessionUsers records, and external identities link to them")
	}

	settings := authSettings{pendingTimeout: defaultPendingTimeout, pendingCookie: defaultPendingCookieName}
	var cookieOpts []internalcookie.Option
	for _, opt := range options {
		switch o := opt.(type) {
		case authOption:
			o(&settings)
		case CookieOption:
			cookieOpts = append(cookieOpts, internalcookie.Option(o))
		}
	}
	if settings.pendingTimeout <= 0 {
		return nil, errors.New("the pending timeout must be positive")
	}

	baseSession, cookieClient, err := newBaseSession(storage, cookieKey, options)
	if err != nil {
		return nil, err
	}
	if settings.pendingCookie == "" || settings.pendingCookie == cookieClient.CookieName {
		return nil, errors.Newf("the pending cookie name %q must be set and differ from the session cookie name", settings.pendingCookie)
	}
	pendingCookies, err := internalcookie.NewCookieClient(cookieKey, append(cookieOpts, internalcookie.WithCookieName(settings.pendingCookie))...)
	if err != nil {
		return nil, errors.Wrap(err, "cookie.NewCookieClient()")
	}

	return &Auth[SessionData, UserData]{
		baseSession:    baseSession,
		storage:        storage,
		settings:       settings,
		cookies:        cookieClient,
		pendingCookies: pendingCookies,
		methods: signInMethods{
			registered:  make(map[sessioninfo.AuthMethod]bool),
			hasher:      securehash.New(securehash.Argon2()),
			autoUpgrade: true,
			external:    make(map[sessioninfo.AuthMethod]*externalMethod),
		},
	}, nil
}

// Authenticated reports whether the session is authenticated: {"authenticated",
// "username", "impersonation"}. A session whose account is missing or disabled is
// reported as not authenticated.
func (a *Auth[S, U]) Authenticated() http.HandlerFunc {
	type response struct {
		Authenticated bool                               `json:"authenticated"`
		Username      string                             `json:"username"`
		Impersonation *basesession.ImpersonationResponse `json:"impersonation,omitempty"`
	}

	return a.serving(a.baseSession.Handle(func(w http.ResponseWriter, r *http.Request) error {
		ctx, span := tracer.Start(r.Context())
		defer span.End()

		ctx, err := a.validate(ctx)
		if err != nil {
			if httpio.HasUnauthorized(err) {
				return httpio.NewEncoder(w).Ok(response{})
			}

			return httpio.NewEncoder(w).ClientMessage(ctx, err)
		}

		imp, _ := sessioninfo.ImpersonationFromCtx(ctx)

		return httpio.NewEncoder(w).Ok(response{
			Authenticated: true,
			Username:      sessioninfo.FromCtx(ctx).Username,
			Impersonation: basesession.NewImpersonationResponse(imp),
		})
	}))
}

// Logout destroys the current session.
func (a *Auth[S, U]) Logout() http.HandlerFunc {
	return a.serving(a.baseSession.Logout())
}

// StartSession restores or initializes the session, and makes the browser's pending
// identity, if any, available to the Pending handlers and the AuthAPI pending methods.
func (a *Auth[S, U]) StartSession(next http.Handler) http.Handler {
	return a.serving(a.baseSession.StartSession(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		next.ServeHTTP(w, r.WithContext(a.withPendingCookie(r)))
	})))
}

// ValidateSession validates the session and loads the account by UserId: a session
// with no account, or whose account is missing or disabled, is refused with 401. The
// account is available through sessioninfo.UserFromCtx. A foreign actor's role-principal
// impersonation has no account and carries only its username.
func (a *Auth[S, U]) ValidateSession(next http.Handler) http.Handler {
	return a.serving(a.baseSession.Handle(func(w http.ResponseWriter, r *http.Request) error {
		ctx, span := tracer.Start(r.Context())
		defer span.End()

		ctx, err := a.validate(ctx)
		if err != nil {
			return httpio.NewEncoder(w).ClientMessage(ctx, err)
		}

		next.ServeHTTP(w, r.WithContext(ctx))

		return nil
	}))
}

// SetXSRFToken sets the XSRF token.
func (a *Auth[S, U]) SetXSRFToken(next http.Handler) http.Handler {
	return a.serving(a.baseSession.SetXSRFToken(next))
}

// ValidateXSRFToken validates the XSRF token.
func (a *Auth[S, U]) ValidateXSRFToken(next http.Handler) http.Handler {
	return a.serving(a.baseSession.ValidateXSRFToken(next))
}

// EnforceReadOnlyMask refuses writes from read-only impersonated sessions.
func (a *Auth[S, U]) EnforceReadOnlyMask(next http.Handler) http.Handler {
	return a.serving(a.baseSession.EnforceReadOnlyMask(next))
}

// EndImpersonation ends the current impersonated session.
func (a *Auth[S, U]) EndImpersonation() http.HandlerFunc {
	return a.serving(a.baseSession.EndImpersonation())
}

// PendingHandlers are the HTTP handlers for pending identities.
type PendingHandlers struct {
	status              http.HandlerFunc
	confirmWithPassword http.HandlerFunc
	cancel              http.HandlerFunc
}

// Status returns {"reason", "email", "expiresAt", "returnUrl"} for the current pending
// identity: 404 when there is none, 401 with {"message", "code": "pending_expired"}
// when it has expired.
func (h *PendingHandlers) Status() http.HandlerFunc { return h.status }

// ConfirmWithPassword accepts {"password"}, links the pending identity to its account
// on success, and starts the session. It answers {"mfaIsRequired": bool}: true when the
// sign-in policy requires MFA after the link, in which case the pending identity
// remains, now with reason "mfa" (the PendingHook runs for it, and "redirectUrl" carries
// the URL it chose), and the application completes it with AuthAPI.CompletePending. A
// wrong password is 401 and leaves the pending identity.
func (h *PendingHandlers) ConfirmWithPassword() http.HandlerFunc { return h.confirmWithPassword }

// Cancel discards the pending identity.
func (h *PendingHandlers) Cancel() http.HandlerFunc { return h.cancel }

// Pending returns the pending-identity handlers.
func (a *Auth[S, U]) Pending() *PendingHandlers {
	return &PendingHandlers{
		status:              a.serving(a.pendingStatus()),
		confirmWithPassword: a.serving(a.pendingConfirm()),
		cancel:              a.serving(a.pendingCancel()),
	}
}

// API provides programmatic access to the Auth session.
func (a *Auth[S, U]) API() *AuthAPI[S, U] { return &AuthAPI[S, U]{auth: a} }

// AuthAPI provides programmatic access to an Auth session.
type AuthAPI[SessionData, UserData any] struct {
	auth *Auth[SessionData, UserData]
}

// Cookie returns the underlying cookie client.
func (p *AuthAPI[S, U]) Cookie() *cookie.Client { return p.auth.shared().cookie() }
