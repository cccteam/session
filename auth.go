package session

import (
	"context"
	"net/http"
	"slices"
	"time"

	"github.com/cccteam/ccc"
	"github.com/cccteam/ccc/tracer"
	"github.com/cccteam/httpio"
	"github.com/cccteam/session/cookie"
	"github.com/cccteam/session/internal/basesession"
	internalcookie "github.com/cccteam/session/internal/cookie"
	"github.com/cccteam/session/internal/sessioncore"
	"github.com/cccteam/session/internal/signinflow"
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
	// identitiesTable, pendingSignInsTable, signInAttemptsTable and mailLinksTable
	// name the group's tables; nil keeps the store's defaults.
	identitiesTable     *string
	pendingSignInsTable *string
	signInAttemptsTable *string
	mailLinksTable      *string
	// mail is how the Auth sends mail, nil when it sends none.
	mail *mailSettings
	// invitationCookie names the cookie that carries an opened invitation into the
	// sign-in.
	invitationCookie string
	// tokens are the settings of the machine outlets' tokens and the device flow.
	tokens tokenSettings
	// tokensTable and deviceCodesTable name the group's tables; nil keeps the store's
	// defaults.
	tokensTable      *string
	deviceCodesTable *string
	// factors are the settings of the second factor the library runs: the email
	// code and the trusted devices.
	factors factorSettings
	// factorCodesTable and trustedDevicesTable name the group's tables; nil keeps
	// the store's defaults.
	factorCodesTable    *string
	trustedDevicesTable *string
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

// defaultInvitationCookieName names the cookie that carries an opened invitation.
const defaultInvitationCookieName = "auth-invitation"

// IdentityLinkedHook is called after an external identity is linked to a user,
// for example to notify the user.
type IdentityLinkedHook = func(ctx context.Context, userID ccc.UUID, identity *sessioninfo.Identity) error

// WithIdentityLinked sets the hook called after every identity link, whether made by a
// pending identity's password confirmation or by the account rules during a sign-in
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

// WithIdentitiesTableName sets the name of the group's identities table, beside
// WithSessionTableName and WithUserTableName. (default: SessionIdentities)
func WithIdentitiesTableName(name string) AuthOption {
	return authOption{apply: func(s *authSettings) { s.identitiesTable = &name }}
}

// WithPendingSignInsTableName sets the name of the group's pending sign-ins table.
// (default: SessionPendingSignIns)
func WithPendingSignInsTableName(name string) AuthOption {
	return authOption{apply: func(s *authSettings) { s.pendingSignInsTable = &name }}
}

// WithSignInAttemptsTableName sets the name of the group's sign-in attempts table.
// (default: SessionSignInAttempts)
func WithSignInAttemptsTableName(name string) AuthOption {
	return authOption{apply: func(s *authSettings) { s.signInAttemptsTable = &name }}
}

// WithMailLinksTableName sets the name of the group's mail links table. (default:
// SessionMailLinks)
func WithMailLinksTableName(name string) AuthOption {
	return authOption{apply: func(s *authSettings) { s.mailLinksTable = &name }}
}

// WithInvitationCookieName sets the name of the cookie that carries an invitation the
// browser opened into the sign-in. (default: auth-invitation)
func WithInvitationCookieName(name string) AuthOption {
	return authOption{apply: func(s *authSettings) { s.invitationCookie = name }}
}

// WithFactorCodesTableName sets the name of the group's factor codes table. (default:
// SessionFactorCodes)
func WithFactorCodesTableName(name string) AuthOption {
	return authOption{apply: func(s *authSettings) { s.factorCodesTable = &name }}
}

// WithTrustedDevicesTableName sets the name of the group's trusted devices table.
// (default: SessionTrustedDevices)
func WithTrustedDevicesTableName(name string) AuthOption {
	return authOption{apply: func(s *authSettings) { s.trustedDevicesTable = &name }}
}

// SignedIn is a session a sign-in established, as the SignedInHook receives it.
type SignedIn struct {
	// SessionID is the new session's ID.
	SessionID ccc.UUID
	// UserID and Username are the user the session belongs to.
	UserID   ccc.UUID
	Username string
	// Reason is how the session came about: ReasonLogin for a password or external
	// sign-in, ReasonExternalAuth for one the application started
	// (StartAuthenticatedSession), ReasonStepUp for an MFA completion,
	// ReasonIdentityLinked for a password confirmation.
	Reason sessioninfo.NewSessionReason
	// Events are the auth events the session recorded, the sign-in's method first.
	Events []sessioninfo.AuthEvent
}

// SignedInHook is called once for every session a sign-in establishes, after the
// transaction that inserted it has committed: a password or external sign-in, a
// confirmation, an MFA completion, a session the application started. It is never
// called for a refused sign-in or one held as a pending identity. An error is logged
// and the session stands.
type SignedInHook = func(ctx context.Context, signedIn *SignedIn) error

// nameTables applies the Auth's own table-name options to the store, whose setters
// validate each name (dbtype.ValidateTableName); a refusal is reported under the
// option's name. The base options (session and user tables) go the same way through
// sessioncore.NewBaseSession.
func nameTables[Tx any](storage sessionstorage.AuthStore[Tx], settings *authSettings) error {
	for _, table := range []struct {
		option string
		name   *string
		set    func(string) error
	}{
		{option: "WithIdentitiesTableName", name: settings.identitiesTable, set: storage.SetIdentitiesTableName},
		{option: "WithPendingSignInsTableName", name: settings.pendingSignInsTable, set: storage.SetPendingSignInsTableName},
		{option: "WithSignInAttemptsTableName", name: settings.signInAttemptsTable, set: storage.SetSignInAttemptsTableName},
		{option: "WithMailLinksTableName", name: settings.mailLinksTable, set: storage.SetMailLinksTableName},
		{option: "WithTokensTableName", name: settings.tokensTable, set: storage.SetTokensTableName},
		{option: "WithDeviceCodesTableName", name: settings.deviceCodesTable, set: storage.SetDeviceCodesTableName},
		{option: "WithFactorCodesTableName", name: settings.factorCodesTable, set: storage.SetFactorCodesTableName},
		{option: "WithTrustedDevicesTableName", name: settings.trustedDevicesTable, set: storage.SetTrustedDevicesTableName},
	} {
		if table.name == nil {
			continue
		}
		if err := table.set(*table.name); err != nil {
			return errors.Wrapf(err, "%s()", table.option)
		}
	}

	return nil
}

// Auth is one session type that any registered sign-in method can establish. Auth,
// sessions, cookies, XSRF, custom data, impersonation and the middleware work the same
// for every method.
//
// Register sign-in methods with PasswordSignIn, azure.SignIn and google.SignIn after
// NewAuth and before serving the first request (workos.SignIn once WorkOS returns to
// the public API in v0.13.1). Each returns the method's handlers.
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
	// policy is the application's sign-in rule, nil when it set none: the library's
	// own checks then decide. Set by SetSignInPolicy before the Auth is in use.
	policy signin.Policy[Tx]
	// signedIn is the application's after-sign-in hook, nil when it set none. Set by
	// SetSignedInHook before the Auth is in use.
	signedIn SignedInHook

	// cookies is the session cookie client. It also writes the external methods' state
	// cookies.
	cookies *internalcookie.Client
	// pendingCookies writes the pending-identity cookie.
	pendingCookies *internalcookie.Client
	// invitationCookies writes and reads the invitation cookie.
	invitationCookies *internalcookie.Client
	// trustedCookies writes and reads the trusted device cookie.
	trustedCookies *internalcookie.Client
	// acceptInvitation is the application's invitation acceptor, nil for none.
	acceptInvitation signinflow.InvitationAcceptor
	userRenamed      UserRenamedHook
	// directories reads the tenants' declarations of a directory for a stranger's
	// first sign-in, directoryRoles is the role store the person's memberships are
	// read from, and directorySeated seats the person they admit; all nil for none.
	// Set by SetDirectoryAdmission before the Auth is in use.
	directories     signin.DirectoryReader[Tx]
	directoryRoles  signin.UserRoleManager
	directorySeated signinflow.DirectorySeater
	// methods are the registered sign-in methods. Read them through registered.
	methods signInMethods[Tx]
}

// NewAuth creates an Auth session for the given storage. The storage's custom session
// and user data configurations must be built for SessionData and UserData. The
// OIDC-only storage features (the OIDC user anchor and the custom user data login hook)
// are refused. Tx is inferred from the storage: an application writes
// NewAuth[SessionData, UserData](store, cookieKey, options...).
//
// A sign-in is decided by the library's own checks: the user exists and is enabled,
// the identity is linked or resolved, roles reconcile. An application with rules of
// its own sets a sign-in policy with SetSignInPolicy. Each external method's first
// sign-in rule is given to that method's registration.
// cookieKey: A Base64-encoded string representing at least 32 bytes
// of cryptographically secure random data.
func NewAuth[SessionData, UserData, Tx any](
	storage sessionstorage.AuthStore[Tx], cookieKey string, options ...AuthOption,
) (*Auth[SessionData, UserData, Tx], error) {
	if storage == nil {
		return nil, errors.New("storage is required: pass sessionstorage.NewSpannerAuth or NewPostgresAuth")
	}
	if err := sessioncore.VerifyCustomDataTypes[SessionData, UserData](storage); err != nil {
		return nil, err
	}
	if storage.UserDataLoginHookConfigured() {
		return nil, errors.New("the custom user data login hook is OIDC-only: provision custom user data in a custom account rule (signin.Provision's onProvisioned) or per call on CreateSessionUser")
	}
	if storage.OIDCUsersEnabled() {
		return nil, errors.New("the OIDC user anchor (WithOIDCUsers) is OIDC-only: Auth users are SessionUsers records, and external identities link to them")
	}

	settings := authSettings{
		pendingTimeout: defaultPendingTimeout, pendingCookie: defaultPendingCookieName, invitationCookie: defaultInvitationCookieName, tokens: defaultTokenSettings(),
		factors: defaultFactorSettings,
	}
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
	if settings.mail != nil {
		if err := settings.mail.validate(); err != nil {
			return nil, err
		}
	}
	if err := settings.tokens.validate(); err != nil {
		return nil, err
	}
	if err := settings.factors.validate(); err != nil {
		return nil, err
	}
	if err := nameTables(storage, &settings); err != nil {
		return nil, err
	}

	baseSession, cookieClient, err := sessioncore.NewBaseSession(storage, cookieKey, options)
	if err != nil {
		return nil, err
	}
	cookies, err := newAuthCookies(cookieKey, cookieClient.CookieName, cookieOpts, &settings)
	if err != nil {
		return nil, err
	}

	a := &Auth[SessionData, UserData, Tx]{
		baseSession:       baseSession,
		storage:           storage,
		settings:          settings,
		cookies:           cookieClient,
		pendingCookies:    cookies.pending,
		invitationCookies: cookies.invitation,
		trustedCookies:    cookies.trusted,
	}
	a.methods.init(storage)

	return a, nil
}

// authCookies are the cookie clients of the Auth's own cookies, beside the session's.
type authCookies struct {
	pending, invitation, trusted *internalcookie.Client
}

// newAuthCookies builds the clients of the pending, invitation and trusted device
// cookies under the session's cookie key and options, refusing a name that is empty
// or that another of the four cookies has.
func newAuthCookies(cookieKey, sessionCookie string, opts []internalcookie.Option, settings *authSettings) (*authCookies, error) {
	names := []struct {
		what, name string
	}{
		{what: "pending", name: settings.pendingCookie},
		{what: "invitation", name: settings.invitationCookie},
		{what: "trusted device", name: settings.factors.trustedCookie},
	}
	taken := map[string]bool{sessionCookie: true}
	clients := make([]*internalcookie.Client, 0, len(names))
	for _, n := range names {
		if n.name == "" || taken[n.name] {
			return nil, errors.Newf("the %s cookie name %q must be set and differ from the session cookie name and the Auth's other cookie names", n.what, n.name)
		}
		taken[n.name] = true
		client, err := internalcookie.NewCookieClient(cookieKey, append(slices.Clone(opts), internalcookie.WithCookieName(n.name))...)
		if err != nil {
			return nil, errors.Wrap(err, "cookie.NewCookieClient()")
		}
		clients = append(clients, client)
	}

	return &authCookies{pending: clients[0], invitation: clients[1], trusted: clients[2]}, nil
}

// SetSignInPolicy sets the application's sign-in rule: asked once a sign-in's user is
// known and before any session exists, for every sign-in method and for a session the
// application starts for a user it authenticated itself (AuthAPI.StartAuthenticatedSession),
// with signin.Allow, signin.Deny or signin.RequireMFA. Without a policy the library's
// own checks decide. Set it after NewAuth and before serving the first request; a nil
// policy, a second policy, or a policy set once the Auth is in use is a wiring
// mistake and panics, as a misregistered sign-in method does.
func (a *Auth[SessionData, UserData, Tx]) SetSignInPolicy(policy signin.Policy[Tx]) {
	if policy == nil {
		panic("session: SetSignInPolicy was given nil: pass the application's rule, or set no policy and the library's checks decide")
	}
	a.methods.mu.Lock()
	defer a.methods.mu.Unlock()

	if a.methods.inUse.Load() {
		panic("session: the sign-in policy was set after the Auth served a request: set it before serving")
	}
	if a.policy != nil {
		panic("session: the sign-in policy was set twice: one Auth has one rule")
	}
	a.policy = policy
}

// SetSignedInHook sets the application's after-sign-in hook, called once for every
// session a sign-in establishes, whatever the method, after the transaction that
// inserted it has committed, with the user and the sign-in's events; never for a
// refusal or a sign-in held for confirmation or MFA. An error from the hook is logged
// and the session stands. Set it after NewAuth and before serving the first request; a
// nil hook, a second hook, or a hook set once the Auth is in use is a wiring mistake
// and panics, as SetSignInPolicy does.
func (a *Auth[SessionData, UserData, Tx]) SetSignedInHook(hook SignedInHook) {
	if hook == nil {
		panic("session: SetSignedInHook was given nil: pass the application's hook, or set none")
	}
	a.methods.mu.Lock()
	defer a.methods.mu.Unlock()

	if a.methods.inUse.Load() {
		panic("session: the after-sign-in hook was set after the Auth served a request: set it before serving")
	}
	if a.signedIn != nil {
		panic("session: the after-sign-in hook was set twice: one Auth has one hook")
	}
	a.signedIn = hook
}

// UserRenamedHook is told that a user's username changed by the library's own doing:
// under a password method declared UsernameIsEmail, the person who verifies a new
// address is renamed to it, live sessions included, as a rename does. An application
// that keys anything by the username, role memberships above all, moves it from the old
// name to the new here. The hook runs after the rename is written and outside any
// transaction; an error is logged and answered to the person as the verification
// having failed, with the address verified and the username changed, so the hook is
// written to be safe to run again (adding under the new name before removing under
// the old).
type UserRenamedHook = func(ctx context.Context, userID ccc.UUID, from, to string) error

// SetUserRenamed sets the hook a rename the library performs is reported to. An
// application whose password method declares UsernameIsEmail and that keys memberships
// by username needs one. Set it after NewAuth and before serving the first request; a
// nil hook, a second hook, or a hook set once the Auth is in use panics.
func (a *Auth[SessionData, UserData, Tx]) SetUserRenamed(hook UserRenamedHook) {
	if hook == nil {
		panic("session: SetUserRenamed was given nil: pass the application's hook, or set none")
	}
	a.methods.mu.Lock()
	defer a.methods.mu.Unlock()

	if a.methods.inUse.Load() {
		panic("session: the rename hook was set after the Auth served a request: set it before serving")
	}
	if a.userRenamed != nil {
		panic("session: the rename hook was set twice: one Auth has one hook")
	}
	a.userRenamed = hook
}

// InvitationAcceptedHook is the application's half of an invitation's acceptance: it
// grants what the invitation names, its roles in its tenant, to the user who accepted
// it, once the transaction that consumed the invitation has committed and before the
// sign-in policy decides, so the policy sees the membership. It runs for every
// acceptance: the one a sign-in or a sign-up performs with the invitation the browser
// carries, and Invitation().Accept() for a person already signed in. The user is named
// by id and by username, the key an application's memberships are held under, and is
// committed when the hook runs. The hook runs outside any transaction, once: an
// application's memberships live in a store of their own, written through its own
// client, which no transaction of the session store can carry (and which the Spanner
// emulator, allowing one read-write transaction at a time, would deadlock inside one).
// A hook that fails ends the sign-in with its error and leaves the invitation
// consumed: the person's next attempt at the link finds it dead, and an administrator
// invites again.
type InvitationAcceptedHook = func(ctx context.Context, userID ccc.UUID, username string, inv *sessioninfo.Invitation) error

// SetInvitationAccepted sets the application's invitation acceptor, the hook that
// grants what an invitation names when it is accepted. An Auth that sends invitations
// (AuthAPI.Invite) needs one, or an acceptance grants nothing. Set it after NewAuth
// and before serving the first request; a nil hook, a second hook, or a hook set once
// the Auth is in use is a wiring mistake and panics, as SetSignInPolicy does.
func (a *Auth[SessionData, UserData, Tx]) SetInvitationAccepted(hook InvitationAcceptedHook) {
	if hook == nil {
		panic("session: SetInvitationAccepted was given nil: pass the application's hook, or set none")
	}
	a.methods.mu.Lock()
	defer a.methods.mu.Unlock()

	if a.methods.inUse.Load() {
		panic("session: the invitation hook was set after the Auth served a request: set it before serving")
	}
	if a.acceptInvitation != nil {
		panic("session: the invitation hook was set twice: one Auth has one hook")
	}
	a.acceptInvitation = hook
}

// Authenticated answers {"authenticated", "username", "passwordChangeRequired",
// "email", "emailVerified", "emailHint", "impersonation"}. A session whose user is
// missing or disabled is reported as not authenticated. passwordChangeRequired is set
// while the user must change a password an operator set (see "Users and the forced
// password change" in the README): the session read is answered under the mark, so the
// login page can show the change form. email is the user's address when they hold one,
// with emailVerified saying whether they have proven it; emailHint, present when the
// user holds no address, is the address a directory asserted at a sign-in, offered as
// a prefill for the add-address step and trusted for nothing.
func (a *Auth[S, U, Tx]) Authenticated() http.HandlerFunc {
	type response struct {
		Authenticated          bool                               `json:"authenticated"`
		Username               string                             `json:"username"`
		PasswordChangeRequired bool                               `json:"passwordChangeRequired"`
		Email                  *string                            `json:"email,omitempty"`
		EmailVerified          bool                               `json:"emailVerified"`
		EmailHint              string                             `json:"emailHint,omitempty"`
		Impersonation          *basesession.ImpersonationResponse `json:"impersonation,omitempty"`
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
		user := sessioninfo.UserFromCtx(ctx)

		return httpio.NewEncoder(w).Ok(response{
			Authenticated:          true,
			Username:               sessioninfo.FromCtx(ctx).Username,
			PasswordChangeRequired: user.PasswordChangeRequired,
			Email:                  user.Email,
			EmailVerified:          user.EmailVerified(),
			EmailHint:              a.emailHint(ctx, user),
			Impersonation:          basesession.NewImpersonationResponse(imp),
		})
	}))
}

// Logout destroys the current session.
func (a *Auth[S, U, Tx]) Logout() http.HandlerFunc {
	return a.serving(a.baseSession.Logout())
}

// StartSession restores or initializes the session. It also makes the browser's
// pending identity, if any, available to the Pending handlers and the AuthAPI pending
// methods, and the invitation and the trusted device the browser carries to the
// sign-in.
func (a *Auth[S, U, Tx]) StartSession(next http.Handler) http.Handler {
	return a.serving(a.baseSession.StartSession(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ctx := a.withTrustedDeviceCookie(a.withInvitationCookie(a.withPendingCookie(r), r), r)
		next.ServeHTTP(w, r.WithContext(ctx))
	})))
}

// ValidateSession validates the session and loads its user by UserId. A session
// with no user, or whose user is missing or disabled, is refused with 401. The
// user is available through sessioninfo.UserFromCtx. A foreign actor's
// role-principal impersonation has no user and carries only its username. A user who
// must change a password an operator set is refused with 403 and {"message", "code":
// "password_change_required"} until the change: route the password change, the
// session read and the logout outside this middleware, since they validate on their
// own and are what the user reaches meanwhile. An impersonated session is not held to
// the mark.
func (a *Auth[S, U, Tx]) ValidateSession(next http.Handler) http.Handler {
	return a.serving(a.baseSession.Handle(func(w http.ResponseWriter, r *http.Request) error {
		ctx, span := tracer.Start(r.Context())
		defer span.End()

		ctx, err := a.validateRequest(ctx)
		if err != nil {
			// The password change mark is a coded refusal; anything else is the usual
			// client message.
			var refusal *sessioninfo.LoginRefusal
			if errors.As(err, &refusal) {
				return writeSignInError(ctx, w, err)
			}

			return httpio.NewEncoder(w).ClientMessage(ctx, err)
		}

		next.ServeHTTP(w, r.WithContext(ctx))

		return nil
	}))
}

// DirectorySeatedHook is the application's half of a directory's default seat: it
// seats the user a first sign-in provisioned, named by id and by username (the key an
// application's memberships are held under), with seats, the default seats of the
// directories the tenants declared for the identity's connection, once the
// resolution that created the user has committed and before the sign-in policy
// decides, so the policy sees the memberships. It runs outside any transaction, once,
// for the reason InvitationAcceptedHook does. A hook that fails ends the sign-in with
// its error; the user stays, holding nothing, and the person's next sign-in finds
// them pre-created and links.
type DirectorySeatedHook = func(ctx context.Context, userID ccc.UUID, username string, seats []signin.DirectorySeat) error

// SetDirectoryAdmission sets what a tenanted application gives a first sign-in
// through a directory by a person no user was created for: reader, which reads
// every tenant's declaration of the directory the identity came through
// (signin.DirectoryReader); roles, the role store the person's memberships are read
// from (signin.UserRoleManager, the access library's user manager the tenant policy
// reads too); and hook, which seats the person with the default seats the
// declarations name. With them the standard account rules ask the tenants first: a
// directory some tenant declares belongs to that tenant, and its declaration decides
// before the registration's own rule. A person who already holds a membership under
// the sign-in name in a declaring tenant, or as the application's staff, is that
// tenant's person and is admitted; a default seat admits a stranger with it; and a
// declaration naming none refuses a stranger by invitation only (invitation_only,
// unless the sign-in carries an invitation), with no account created. A directory no
// tenant declares falls to the registration's rule as without them. Set the three
// after NewAuth and before serving the first request; a nil reader, roles or hook, a
// second call, or a call once the Auth is in use is a wiring mistake and panics, as
// SetSignInPolicy does.
func (a *Auth[SessionData, UserData, Tx]) SetDirectoryAdmission(reader signin.DirectoryReader[Tx], roles signin.UserRoleManager, hook DirectorySeatedHook) {
	if reader == nil {
		panic("session: SetDirectoryAdmission was given no reader: pass the application's reader of the tenants' directory declarations")
	}
	if roles == nil {
		panic("session: SetDirectoryAdmission was given no role store: pass the access library's user manager")
	}
	if hook == nil {
		panic("session: SetDirectoryAdmission was given no hook: pass the application's hook that seats the person")
	}
	a.methods.mu.Lock()
	defer a.methods.mu.Unlock()

	if a.methods.inUse.Load() {
		panic("session: the directory admission was set after the Auth served a request: set it before serving")
	}
	if a.directories != nil {
		panic("session: the directory admission was set twice: one Auth has one")
	}
	a.directories, a.directoryRoles, a.directorySeated = reader, roles, hook
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
	sendCode            http.HandlerFunc
	verifyCode          http.HandlerFunc
	enrollEmail         http.HandlerFunc
	requireMail         func(group string)
}

// Status returns {"reason", "email", "expiresAt", "returnUrl"[, "factors"]} for the
// current pending identity, and for one that waits for MFA and may take the library's
// email code, the code's state under "emailCode": the masked address the code goes to
// ("codeEmail"), whether one is standing ("codeSent", "codeExpiresAt") and whether
// the user must first give an address ("enrollEmail"); see "The second factor" in the
// README. It answers 404 when there is none, and 401 with {"message", "code":
// "pending_expired"} when it has expired.
func (h *PendingHandlers) Status() http.HandlerFunc { return h.status }

// SendCode mails the pending identity's user a one-time code for the second factor,
// to the address the user holds, and answers {"codeEmail", "codeSent",
// "codeExpiresAt"}: the masked address and when the code stops being accepted. A code
// already standing is replaced. It answers 409 when the pending identity does not
// wait for MFA, when the sign-in policy does not accept the email code, or when the
// user holds no address (the page then asks for one and posts it to EnrollEmail());
// an address sent three codes within fifteen minutes is refused with
// too_many_attempts and the wait. Route it behind StartSession and
// ValidateXSRFToken; it panics at wiring on an Auth without mail.
func (h *PendingHandlers) SendCode() http.HandlerFunc {
	h.requireMail("Pending().SendCode()")

	return h.sendCode
}

// VerifyCode accepts {"code", "rememberDevice"} and completes the pending identity
// when code is the one sent: the session starts under a new ID, recording the
// sign-in's events and an email-code event, and the address the code went to is
// written on the user verified when it was not. With rememberDevice the browser is
// remembered as a trusted device of the user for the trusted device period, so its
// next sign-ins skip the factor. It answers as the password login does:
// {"mfaIsRequired": false}, or the policy's next wait. A wrong code is 401 with
// {"code": "invalid_code"} and the code stands with one fewer attempt; a code entered
// while none stands, because none was sent or the one sent expired, was used or took
// its last attempt, is 401 with {"code": "code_expired"}, and the page asks for a new
// one. Route it as SendCode.
func (h *PendingHandlers) VerifyCode() http.HandlerFunc {
	h.requireMail("Pending().VerifyCode()")

	return h.verifyCode
}

// EnrollEmail accepts {"email"} from a pending identity whose user holds no address,
// and mails that address the code as SendCode does; the address is written on the
// user, verified, when the code is entered. It answers as SendCode does, and 409 when
// the user already holds an address: the code goes there, and an administrator
// changes it. An address another account holds is answered as sent and told so by
// mail to that address, as the add-address step does, so the screen reveals nothing.
// Route it as SendCode.
func (h *PendingHandlers) EnrollEmail() http.HandlerFunc {
	h.requireMail("Pending().EnrollEmail()")

	return h.enrollEmail
}

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
		sendCode:            a.serving(a.pendingSendCode()),
		verifyCode:          a.serving(a.pendingVerifyCode()),
		enrollEmail:         a.serving(a.pendingEnrollEmail()),
		requireMail:         a.requireMail,
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
