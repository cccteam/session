package session

// CONTRACT (multi-method sessions, v0.13.0): the exported types, constructors and
// method signatures in this file are the agreed contract. Bodies are stubs until the
// implementation lands; see docs/multi-method-auth.md.

import (
	"context"
	"net/http"
	"time"

	"github.com/cccteam/ccc"
	"github.com/cccteam/session/cookie"
	"github.com/cccteam/session/internal/basesession"
	"github.com/cccteam/session/sessioninfo"
	"github.com/cccteam/session/sessionstorage"
	"github.com/go-playground/errors/v5"
)

var errAuthNotImplemented = errors.New("session: not implemented (multi-method sessions contract stub)")

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
	pendingTimeout time.Duration
	pendingCookie  string
}

type authOption func(*authSettings)

func (authOption) isAuthOption() {}

// IdentityLinkedHook is called after an external identity is linked to an account, so
// the application can notify the user.
type IdentityLinkedHook = func(ctx context.Context, userID ccc.UUID, identity *sessioninfo.Identity) error

// WithIdentityLinked sets the hook called after every identity link.
func WithIdentityLinked(hook IdentityLinkedHook) AuthOption {
	return authOption(func(s *authSettings) { s.identityLinked = hook })
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

// SignInMethod is a way to prove identity that an Auth session accepts. Build one with
// PasswordSignIn, AzureSignIn, GoogleSignIn or WorkOSSignIn.
type SignInMethod interface {
	signInMethod() *signInMethodConfig
}

type signInMethodConfig struct {
	method sessioninfo.AuthMethod
}

func (c *signInMethodConfig) signInMethod() *signInMethodConfig { return c }

// PasswordSignIn enables username and password sign-in.
func PasswordSignIn(options ...PasswordOption) SignInMethod {
	return &signInMethodConfig{method: sessioninfo.MethodPassword}
}

// AzureSignIn enables Microsoft Entra ID (Azure) OIDC sign-in. The identity key is
// (tid, oid).
func AzureSignIn(roleSync RoleSyncConfig, issuerURL, clientID, clientSecret, redirectURL string, options ...OIDCOption) SignInMethod {
	return &signInMethodConfig{method: sessioninfo.MethodAzure}
}

// GoogleSignIn enables Google Workspace OIDC sign-in. The identity key is sub.
func GoogleSignIn(roleSync GoogleRoleSyncConfig, clientID, clientSecret, redirectURL, hostedDomain string, options ...OIDCOption) SignInMethod {
	return &signInMethodConfig{method: sessioninfo.MethodGoogle}
}

// WorkOSSignInOption configures WorkOSSignIn.
type WorkOSSignInOption interface {
	isWorkOSSignInOption()
}

func (OIDCOption) isWorkOSSignInOption() {}

type workOSSignInOption func(*workOSSettings)

func (workOSSignInOption) isWorkOSSignInOption() {}

type workOSSettings struct {
	baseURL string
}

// WithWorkOSBaseURL sets the WorkOS API base URL. (default: https://api.workos.com)
func WithWorkOSBaseURL(baseURL string) WorkOSSignInOption {
	return workOSSignInOption(func(s *workOSSettings) { s.baseURL = baseURL })
}

// WorkOSSignIn enables WorkOS SSO sign-in. The login handler reads the
// "organization" query parameter. The identity key is (connection_id, idp_id). Roles
// are never synchronized from WorkOS.
func WorkOSSignIn(apiKey, clientID, redirectURL string, options ...WorkOSSignInOption) SignInMethod {
	return &signInMethodConfig{method: sessioninfo.MethodWorkOS}
}

// Auth is one session type that any configured sign-in method can establish. It owns
// accounts, sessions, cookies, XSRF, custom session and user data, impersonation, and
// the middleware, the same for every method.
type Auth[SessionData, UserData any] struct {
	baseSession *basesession.BaseSession
	storage     sessionstorage.AccountStore
	methods     []SignInMethod
	settings    authSettings
}

// NewAuth creates an Auth session for the given storage and sign-in methods. Storage
// with any external method must carry an identities configuration.
func NewAuth[SessionData, UserData any](storage sessionstorage.AccountStore, cookieKey string, methods []SignInMethod, options ...AuthOption) (*Auth[SessionData, UserData], error) {
	return nil, errAuthNotImplemented
}

func notImplementedHandler() http.HandlerFunc {
	return func(w http.ResponseWriter, _ *http.Request) {
		http.Error(w, errAuthNotImplemented.Error(), http.StatusNotImplemented)
	}
}

func notImplementedMiddleware(_ http.Handler) http.Handler { return notImplementedHandler() }

// Authenticated reports whether the session is authenticated.
func (a *Auth[S, U]) Authenticated() http.HandlerFunc { return notImplementedHandler() }

// Logout destroys the current session.
func (a *Auth[S, U]) Logout() http.HandlerFunc { return notImplementedHandler() }

// StartSession restores or initializes the session.
func (a *Auth[S, U]) StartSession(next http.Handler) http.Handler {
	return notImplementedMiddleware(next)
}

// ValidateSession validates the session and loads the account by UserId.
func (a *Auth[S, U]) ValidateSession(next http.Handler) http.Handler {
	return notImplementedMiddleware(next)
}

// SetXSRFToken sets the XSRF token.
func (a *Auth[S, U]) SetXSRFToken(next http.Handler) http.Handler {
	return notImplementedMiddleware(next)
}

// ValidateXSRFToken validates the XSRF token.
func (a *Auth[S, U]) ValidateXSRFToken(next http.Handler) http.Handler {
	return notImplementedMiddleware(next)
}

// EnforceReadOnlyMask refuses writes from read-only impersonated sessions.
func (a *Auth[S, U]) EnforceReadOnlyMask(next http.Handler) http.Handler {
	return notImplementedMiddleware(next)
}

// EndImpersonation ends the current impersonated session.
func (a *Auth[S, U]) EndImpersonation() http.HandlerFunc { return notImplementedHandler() }

// PasswordHandlers are the HTTP handlers of the password method.
type PasswordHandlers struct{}

// Login accepts {"username", "password"}; on success it applies the sign-in policy and
// either starts the session or creates a pending identity (MFA).
func (h *PasswordHandlers) Login() http.HandlerFunc { return notImplementedHandler() }

// ChangeUserPassword changes the signed-in account's password.
func (h *PasswordHandlers) ChangeUserPassword() http.HandlerFunc { return notImplementedHandler() }

// Password returns the password method's handlers. It panics if the method is not
// configured.
func (a *Auth[S, U]) Password() *PasswordHandlers { return &PasswordHandlers{} }

// ExternalHandlers are the HTTP handlers of an external (redirect-based) method.
type ExternalHandlers struct{}

// Login redirects to the provider. For WorkOS it requires ?organization=; all methods
// accept ?returnUrl=.
func (h *ExternalHandlers) Login() http.HandlerFunc { return notImplementedHandler() }

// Callback completes the provider round trip, resolves the identity, applies the
// sign-in policy, and starts the session, creates a pending identity, or redirects to
// the login URL with ?code=<LoginRefusalCode>.
func (h *ExternalHandlers) Callback() http.HandlerFunc { return notImplementedHandler() }

// FrontChannelLogout handles provider-initiated logout (Azure only).
func (h *ExternalHandlers) FrontChannelLogout() http.HandlerFunc { return notImplementedHandler() }

// Azure returns the Azure method's handlers.
func (a *Auth[S, U]) Azure() *ExternalHandlers { return &ExternalHandlers{} }

// Google returns the Google method's handlers.
func (a *Auth[S, U]) Google() *ExternalHandlers { return &ExternalHandlers{} }

// WorkOS returns the WorkOS method's handlers.
func (a *Auth[S, U]) WorkOS() *ExternalHandlers { return &ExternalHandlers{} }

// PendingHandlers are the HTTP handlers for pending identities.
type PendingHandlers struct{}

// Status returns {"reason", "email", "expiresAt"} for the current pending identity.
func (h *PendingHandlers) Status() http.HandlerFunc { return notImplementedHandler() }

// ConfirmWithPassword accepts {"password"}, links the pending identity to its account
// on success, and starts the session.
func (h *PendingHandlers) ConfirmWithPassword() http.HandlerFunc { return notImplementedHandler() }

// Cancel discards the pending identity.
func (h *PendingHandlers) Cancel() http.HandlerFunc { return notImplementedHandler() }

// Pending returns the pending-identity handlers.
func (a *Auth[S, U]) Pending() *PendingHandlers { return &PendingHandlers{} }

// API provides programmatic access to the Auth session.
func (a *Auth[S, U]) API() *AuthAPI[S, U] { return &AuthAPI[S, U]{auth: a} }

// AuthAPI provides programmatic access to an Auth session.
type AuthAPI[SessionData, UserData any] struct {
	auth *Auth[SessionData, UserData]
}

// ValidateSession validates the session cookie and stores session data in the context.
func (p *AuthAPI[S, U]) ValidateSession(ctx context.Context) (context.Context, error) {
	return ctx, errAuthNotImplemented
}

// Cookie returns the underlying cookie client.
func (p *AuthAPI[S, U]) Cookie() *cookie.Client { return nil }

// ValidateCredentials checks a username and password and returns the account ID. A
// password-less account always fails validation.
func (p *AuthAPI[S, U]) ValidateCredentials(ctx context.Context, username, password string) (ccc.UUID, error) {
	return ccc.NilUUID, errAuthNotImplemented
}

// StartAuthenticatedSession starts a session for an existing account after the
// application has authenticated it itself, recording events; the sign-in policy is not
// consulted. It regenerates the session ID.
func (p *AuthAPI[S, U]) StartAuthenticatedSession(ctx context.Context, w http.ResponseWriter, userID ccc.UUID, events []sessioninfo.AuthEvent, customData ...*S) (ccc.UUID, error) {
	return ccc.NilUUID, errAuthNotImplemented
}

// Logout destroys the current session.
func (p *AuthAPI[S, U]) Logout(ctx context.Context) error { return errAuthNotImplemented }

// PendingIdentity returns the pending identity of the current request, or a NotFound
// error.
func (p *AuthAPI[S, U]) PendingIdentity(ctx context.Context) (*sessioninfo.PendingIdentity, error) {
	return nil, errAuthNotImplemented
}

// CompletePending finishes a pending identity after the application's MFA step:
// records the step-up events, links the identity if needed, starts the session, and
// regenerates the session ID.
func (p *AuthAPI[S, U]) CompletePending(ctx context.Context, w http.ResponseWriter, stepUp ...sessioninfo.AuthEvent) (ccc.UUID, error) {
	return ccc.NilUUID, errAuthNotImplemented
}

// ConfirmPendingWithPassword checks the password of the pending identity's account,
// links the identity, calls the IdentityLinked hook, and starts the session.
func (p *AuthAPI[S, U]) ConfirmPendingWithPassword(ctx context.Context, w http.ResponseWriter, password string) (ccc.UUID, error) {
	return ccc.NilUUID, errAuthNotImplemented
}

// CreateSessionUser creates an account. A nil req.Password creates a password-less
// account.
func (p *AuthAPI[S, U]) CreateSessionUser(ctx context.Context, req *CreateUserRequest, customData ...*U) (ccc.UUID, error) {
	return ccc.NilUUID, errAuthNotImplemented
}

// ChangeSessionUserUsername changes an account's username.
func (p *AuthAPI[S, U]) ChangeSessionUserUsername(ctx context.Context, userID ccc.UUID, username string) error {
	return errAuthNotImplemented
}

// ChangeSessionUserPassword changes an account's password and regenerates its session.
func (p *AuthAPI[S, U]) ChangeSessionUserPassword(ctx context.Context, w http.ResponseWriter, userID ccc.UUID, req *ChangeSessionUserPasswordRequest) error {
	return errAuthNotImplemented
}

// SetSessionUserPassword sets an account's password without the old one (enrollment,
// reset), destroying its sessions.
func (p *AuthAPI[S, U]) SetSessionUserPassword(ctx context.Context, userID ccc.UUID, password string) error {
	return errAuthNotImplemented
}

// DeactivateSessionUser disables an account and destroys its sessions.
func (p *AuthAPI[S, U]) DeactivateSessionUser(ctx context.Context, userID ccc.UUID) error {
	return errAuthNotImplemented
}

// ActivateSessionUser enables an account.
func (p *AuthAPI[S, U]) ActivateSessionUser(ctx context.Context, userID ccc.UUID) error {
	return errAuthNotImplemented
}

// DeleteSessionUser deletes an account, its identities and sessions.
func (p *AuthAPI[S, U]) DeleteSessionUser(ctx context.Context, userID ccc.UUID) error {
	return errAuthNotImplemented
}

// DestroyUserSessions expires every session of an account.
func (p *AuthAPI[S, U]) DestroyUserSessions(ctx context.Context, userID ccc.UUID) error {
	return errAuthNotImplemented
}

// Identities lists an account's linked external identities.
func (p *AuthAPI[S, U]) Identities(ctx context.Context, userID ccc.UUID) ([]*sessionstorage.SessionIdentity, error) {
	return nil, errAuthNotImplemented
}

// UnlinkIdentity removes an identity link.
func (p *AuthAPI[S, U]) UnlinkIdentity(ctx context.Context, identityID ccc.UUID) error {
	return errAuthNotImplemented
}

// UpdateCustomSessionData updates the custom session data of an active session.
func (p *AuthAPI[S, U]) UpdateCustomSessionData(ctx context.Context, sessionID ccc.UUID, mutate func(data *S) error) error {
	return errAuthNotImplemented
}

// CustomData returns the current session's custom data.
func (p *AuthAPI[S, U]) CustomData(ctx context.Context) (S, error) {
	var zero S

	return zero, errAuthNotImplemented
}

// CustomUserData returns an account's custom user data.
func (p *AuthAPI[S, U]) CustomUserData(ctx context.Context, userID ccc.UUID) (U, error) {
	var zero U

	return zero, errAuthNotImplemented
}

// UpdateCustomUserData updates an account's custom user data.
func (p *AuthAPI[S, U]) UpdateCustomUserData(ctx context.Context, userID ccc.UUID, mutate func(data *U) error) error {
	return errAuthNotImplemented
}

// StartImpersonatedSession starts an impersonated session (same semantics as the
// legacy types).
func (p *AuthAPI[S, U]) StartImpersonatedSession(ctx context.Context, w http.ResponseWriter, req *ImpersonationRequest, customData ...*S) (ccc.UUID, error) {
	return ccc.NilUUID, errAuthNotImplemented
}

// DestroyImpersonatedSessions expires every impersonated session started by actor.
func (p *AuthAPI[S, U]) DestroyImpersonatedSessions(ctx context.Context, actor string) error {
	return errAuthNotImplemented
}

// ActiveImpersonations lists active impersonations matching q.
func (p *AuthAPI[S, U]) ActiveImpersonations(ctx context.Context, q *ImpersonationQuery) ([]*sessioninfo.Impersonation, error) {
	return nil, errAuthNotImplemented
}

// DestroyImpersonatedSession expires one impersonated session.
func (p *AuthAPI[S, U]) DestroyImpersonatedSession(ctx context.Context, sessionID ccc.UUID) error {
	return errAuthNotImplemented
}

// EndImpersonation ends the current impersonated session, restoring the actor's
// session when possible.
func (p *AuthAPI[S, U]) EndImpersonation(ctx context.Context, w http.ResponseWriter) (restored bool, err error) {
	return false, errAuthNotImplemented
}
