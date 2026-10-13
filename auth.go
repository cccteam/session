package session

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
	"github.com/cccteam/session/internal/sessioncore"
	"github.com/cccteam/session/sessioninfo"
	"github.com/cccteam/session/sessionstorage"
	"github.com/cccteam/session/signin"
	"github.com/go-playground/errors/v5"
)

var _ basesession.Handlers = &Auth[NoCustomData, NoCustomData, struct{}]{}

// authSettings holds Auth-only settings.
type authSettings struct {
	identityLinked IdentityLinkedHook
	pendingHook    PendingHook
	pendingTimeout time.Duration
	pendingCookie  string
}

// authOption is an Auth settings option.
type authOption struct {
	sessioncore.AuthOptionMarker
	apply func(*authSettings)
}

// Default pending-identity settings.
const (
	defaultPendingTimeout    = 10 * time.Minute
	defaultPendingCookieName = "auth-pending"
)

// IdentityLinkedHook is called after an external identity is linked to a user,
// for example to notify the user.
type IdentityLinkedHook = func(ctx context.Context, userID ccc.UUID, identity *sessioninfo.Identity) error

// WithIdentityLinked sets the hook called after every identity link, whether made by a
// pending identity's password confirmation or by the user resolver during a sign-in
// (LinkIdentity or ProvisionUser). A resolver's link is committed before the sign-in
// policy runs, so it is reported even when the policy then denies the sign-in or holds
// it for MFA. An error from the hook is logged. The link and the sign-in stand.
func WithIdentityLinked(hook IdentityLinkedHook) AuthOption {
	return authOption{apply: func(s *authSettings) { s.identityLinked = hook }}
}

// PendingHook is called after a sign-in handler holds a sign-in as a pending identity,
// for example to send an MFA code or choose the next page. It runs after the pending
// identity is stored and its cookie set, and cannot change either.
//
// The hook may write the response itself, and the handler then writes nothing more.
// Otherwise it returns where the browser goes: Callback() redirects there and the JSON
// handlers return it as "redirectUrl". An empty URL keeps the default. The URL must be
// the application's own, never built from request input.
//
// An error discards the pending identity and fails the sign-in. See the README's "The
// redirect and response contract".
type PendingHook = func(ctx context.Context, w http.ResponseWriter, r *http.Request, pending *sessioninfo.PendingIdentity) (redirectURL string, err error)

// WithPendingHook sets the hook called when PasswordMethod.Login(), an external
// method's Callback() or Pending().ConfirmWithPassword() holds a sign-in as a pending
// identity. The AuthAPI methods never call it. They return a
// *signin.PendingSignInError instead.
func WithPendingHook(hook PendingHook) AuthOption {
	return authOption{apply: func(s *authSettings) { s.pendingHook = hook }}
}

// WithPendingTimeout sets how long a pending identity waits for confirmation or MFA.
// (default: 10m)
func WithPendingTimeout(d time.Duration) AuthOption {
	return authOption{apply: func(s *authSettings) { s.pendingTimeout = d }}
}

// WithPendingCookieName sets the name of the pending cookie, which carries the opaque
// token of the browser's pending sign-in. (default: "auth-pending")
func WithPendingCookieName(name string) AuthOption {
	return authOption{apply: func(s *authSettings) { s.pendingCookie = name }}
}

// Auth is one session type that any registered sign-in method can establish. Auth,
// sessions, cookies, XSRF, custom data, impersonation and the middleware work the same
// for every method.
//
// Register sign-in methods with PasswordSignIn, azure.SignIn, google.SignIn and
// workos.SignIn after NewAuth and before serving the first request. Each returns the
// method's handlers.
//
// Every session belongs to a user (SessionUsers). A sign-in either establishes a
// session under a new session ID, becomes a pending identity that waits for a password
// confirmation or the application's MFA step, or is refused with a
// sessioninfo.LoginRefusalCode. See the README's "Auth sessions (multiple sign-in
// methods)" for the routes and the redirect contract.
//
// Tx is the storage's transaction type (pgx.Tx, *spanner.ReadWriteTransaction), taken
// from the storage NewAuth is given. The sign-in policy and every external method's user
// resolver receive it, so a hook written for the other backend does not compile.
type Auth[SessionData, UserData, Tx any] struct {
	baseSession *basesession.BaseSession
	storage     sessionstorage.AuthStore[Tx]
	settings    authSettings
	// policy decides every sign-in once its user is known.
	policy signin.Policy[Tx]

	// cookies is the session cookie client. It also writes the external methods' state
	// cookies.
	cookies *internalcookie.Client
	// pendingCookies writes the pending-identity cookie.
	pendingCookies *internalcookie.Client
	// methods are the registered sign-in methods. Read them through registered.
	methods signInMethods[Tx]
}

// NewAuth creates an Auth session for the given storage. The storage's custom session
// and user data configurations must be built for SessionData and UserData. The
// OIDC-only storage features (the OIDC user anchor and the custom user data login hook)
// are refused. Tx is inferred from the storage: an application writes
// NewAuth[SessionData, UserData](store, cookieKey, policy).
//
// policy decides every sign-in once its user is known: signin.AllowAll, or the
// application's rule; it is required. Each external method's user resolver is given to
// that method's registration.
// cookieKey: A Base64-encoded string representing at least 32 bytes
// of cryptographically secure random data.
func NewAuth[SessionData, UserData, Tx any](
	storage sessionstorage.AuthStore[Tx], cookieKey string, policy signin.Policy[Tx], options ...AuthOption,
) (*Auth[SessionData, UserData, Tx], error) {
	if storage == nil {
		return nil, errors.New("storage is required: pass sessionstorage.NewSpannerAuth or NewPostgresAuth")
	}
	if policy == nil {
		return nil, errors.New("a sign-in policy is required: pass signin.AllowAll to allow every sign-in, or the application's rule")
	}
	if err := sessioncore.VerifyCustomDataTypes[SessionData, UserData](storage); err != nil {
		return nil, err
	}
	if storage.UserDataLoginHookConfigured() {
		return nil, errors.New("the custom user data login hook is OIDC-only: provision custom user data in the user resolver (signin.Provision's onProvisioned) or per call on CreateSessionUser")
	}
	if storage.OIDCUsersEnabled() {
		return nil, errors.New("the OIDC user anchor (WithOIDCUsers) is OIDC-only: Auth users are SessionUsers records, and external identities link to them")
	}

	settings := authSettings{pendingTimeout: defaultPendingTimeout, pendingCookie: defaultPendingCookieName}
	var cookieOpts []internalcookie.Option
	for _, opt := range options {
		switch o := opt.(type) {
		case authOption:
			o.apply(&settings)
		case CookieOption:
			cookieOpts = append(cookieOpts, internalcookie.Option(o))
		}
	}
	if settings.pendingTimeout <= 0 {
		return nil, errors.New("the pending timeout must be positive")
	}

	baseSession, cookieClient, err := sessioncore.NewBaseSession(storage, cookieKey, options)
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

	return &Auth[SessionData, UserData, Tx]{
		baseSession:    baseSession,
		storage:        storage,
		settings:       settings,
		policy:         policy,
		cookies:        cookieClient,
		pendingCookies: pendingCookies,
		methods: signInMethods[Tx]{
			registered:  make(map[string]bool),
			hasher:      securehash.New(securehash.Argon2()),
			autoUpgrade: true,
			external:    make(map[string]*externalMethod[Tx]),
		},
	}, nil
}

// Authenticated answers {"authenticated", "username", "impersonation"}. A session whose
// user is missing or disabled is reported as not authenticated.
func (a *Auth[S, U, Tx]) Authenticated() http.HandlerFunc {
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
func (a *Auth[S, U, Tx]) Logout() http.HandlerFunc {
	return a.serving(a.baseSession.Logout())
}

// StartSession restores or initializes the session. It also makes the browser's
// pending identity, if any, available to the Pending handlers and the AuthAPI pending
// methods.
func (a *Auth[S, U, Tx]) StartSession(next http.Handler) http.Handler {
	return a.serving(a.baseSession.StartSession(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		next.ServeHTTP(w, r.WithContext(a.withPendingCookie(r)))
	})))
}

// ValidateSession validates the session and loads its user by UserId. A session
// with no user, or whose user is missing or disabled, is refused with 401. The
// user is available through sessioninfo.UserFromCtx. A foreign actor's
// role-principal impersonation has no user and carries only its username.
func (a *Auth[S, U, Tx]) ValidateSession(next http.Handler) http.Handler {
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
func (a *Auth[S, U, Tx]) SetXSRFToken(next http.Handler) http.Handler {
	return a.serving(a.baseSession.SetXSRFToken(next))
}

// ValidateXSRFToken validates the XSRF token.
func (a *Auth[S, U, Tx]) ValidateXSRFToken(next http.Handler) http.Handler {
	return a.serving(a.baseSession.ValidateXSRFToken(next))
}

// EnforceReadOnlyMask refuses writes from read-only impersonated sessions.
func (a *Auth[S, U, Tx]) EnforceReadOnlyMask(next http.Handler) http.Handler {
	return a.serving(a.baseSession.EnforceReadOnlyMask(next))
}

// EndImpersonation ends the current impersonated session.
func (a *Auth[S, U, Tx]) EndImpersonation() http.HandlerFunc {
	return a.serving(a.baseSession.EndImpersonation())
}

// PendingHandlers are the HTTP handlers for pending identities.
type PendingHandlers struct {
	status              http.HandlerFunc
	confirmWithPassword http.HandlerFunc
	cancel              http.HandlerFunc
}

// Status returns {"reason", "email", "expiresAt", "returnUrl"} for the current pending
// identity. It answers 404 when there is none, and 401 with {"message", "code":
// "pending_expired"} when it has expired.
func (h *PendingHandlers) Status() http.HandlerFunc { return h.status }

// ConfirmWithPassword accepts {"password"}. On success it links the pending identity to
// its user and starts the session. It answers {"mfaIsRequired": bool}. When the
// sign-in policy requires MFA after the link, the pending identity remains with reason
// "mfa", the PendingHook runs, and the application completes it with
// AuthAPI.CompletePending. A wrong password is 401 and leaves the pending identity.
func (h *PendingHandlers) ConfirmWithPassword() http.HandlerFunc { return h.confirmWithPassword }

// Cancel discards the pending identity.
func (h *PendingHandlers) Cancel() http.HandlerFunc { return h.cancel }

// Pending returns the pending-identity handlers.
func (a *Auth[S, U, Tx]) Pending() *PendingHandlers {
	return &PendingHandlers{
		status:              a.serving(a.pendingStatus()),
		confirmWithPassword: a.serving(a.pendingConfirm()),
		cancel:              a.serving(a.pendingCancel()),
	}
}

// API provides programmatic access to the Auth session.
func (a *Auth[S, U, Tx]) API() *AuthAPI[S, U, Tx] { return &AuthAPI[S, U, Tx]{auth: a} }

// AuthAPI provides programmatic access to an Auth session.
type AuthAPI[SessionData, UserData, Tx any] struct {
	auth *Auth[SessionData, UserData, Tx]
}

// Cookie returns the underlying cookie client.
func (p *AuthAPI[S, U, Tx]) Cookie() *cookie.Client { return p.auth.shared().Cookie() }
