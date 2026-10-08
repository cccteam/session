package session

// CONTRACT (multi-method sessions, v0.13.0): the exported registration functions,
// method types and their handlers in this file are the agreed contract. See the "Auth
// sessions (multiple sign-in methods)" section of the README.

import (
	"fmt"
	"net/http"
	"sync"
	"sync/atomic"

	"github.com/cccteam/ccc/securehash"
	"github.com/cccteam/httpio"
	"github.com/cccteam/session/internal/azureoidc"
	"github.com/cccteam/session/internal/cloudidentity"
	internalcookie "github.com/cccteam/session/internal/cookie"
	"github.com/cccteam/session/internal/googleoidc"
	"github.com/cccteam/session/internal/workossso"
	"github.com/cccteam/session/sessioninfo"
	"github.com/cccteam/session/sessionstorage"
	"github.com/go-playground/errors/v5"
)

// A sign-in method is registered on an Auth, and its registration returns the method's
// own handlers, from which its routes are wired: a method that is not registered has no
// handlers to wire, and a handler exists only on the method it belongs to
// (FrontChannelLogout only on *AzureMethod).
//
// Registration is refused, with a panic, in one place (Auth.register): registering a
// method twice on one Auth, registering after the Auth is in use (it has served a
// request, or read its methods for a password check or hash), and registering an
// external method on storage without an identities configuration. These are wiring
// mistakes, refused at startup the way http.ServeMux refuses a duplicate pattern.

// signInRegistry is the Auth a sign-in method is registered on. *Auth implements it, so
// the registration functions take an Auth of any SessionData and UserData and return
// method types that are not generic: a method's handlers close over the Auth, and its
// type needs nothing else from it.
type signInRegistry interface {
	register(reg *signInRegistration) methodHandlers
}

var _ signInRegistry = (*Auth[NoCustomData, NoCustomData])(nil)

// signInRegistration is what a registration function asks the Auth to register.
type signInRegistration struct {
	method sessioninfo.AuthMethod
	// password is the password method's settings; nil for an external method.
	password *passwordAuthSettings
	// external builds an external method over the session's cookie client, which writes
	// the method's state cookie; nil for the password method.
	external func(cookies *internalcookie.Client) (*externalMethod, error)
	// err is a misuse the registration function found in its own arguments.
	err error
}

// methodHandlers are a registered method's handlers; each method type exposes its own.
type methodHandlers struct {
	login              http.HandlerFunc
	callback           http.HandlerFunc
	frontChannelLogout http.HandlerFunc
	changeUserPassword http.HandlerFunc
}

// signInMethods are an Auth's registered sign-in methods. Registration writes them,
// under mu, until the Auth is first used; from then on they are read-only, so a request
// reads them without the lock.
type signInMethods struct {
	mu    sync.Mutex
	inUse atomic.Bool

	registered map[sessioninfo.AuthMethod]bool
	// hasher and autoUpgrade are the password method's settings, or the defaults when
	// it is not registered (account management still hashes passwords).
	hasher      *securehash.SecureHasher
	autoUpgrade bool
	// external holds the registered redirect-based methods.
	external map[sessioninfo.AuthMethod]*externalMethod
}

// registered returns the Auth's sign-in methods for reading, and closes registration:
// every read of them goes through here, so none can race a registration, and a method
// registered after one is refused rather than half-seen.
func (a *Auth[S, U]) registered() *signInMethods {
	if !a.methods.inUse.Load() {
		a.methods.mu.Lock()
		a.methods.inUse.Store(true)
		a.methods.mu.Unlock()
	}

	return &a.methods
}

// serving marks the Auth in use when h serves its first request (see registered).
// Every handler and middleware the Auth hands out goes through it.
func (a *Auth[S, U]) serving(h http.Handler) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		a.registered()
		h.ServeHTTP(w, r)
	}
}

// register registers a sign-in method and returns its handlers, or panics when the
// registration is refused: this is the one place the registration rules are enforced.
func (a *Auth[S, U]) register(reg *signInRegistration) methodHandlers {
	if a == nil {
		panic(fmt.Sprintf("session: the %s sign-in method is registered on a nil *Auth: pass the Auth NewAuth returned", reg.method))
	}

	a.methods.mu.Lock()
	defer a.methods.mu.Unlock()

	if a.methods.inUse.Load() {
		panic(fmt.Sprintf("session: the %s sign-in method is registered after the Auth is in use (it has served a request or checked a password): register every sign-in method before serving", reg.method))
	}
	if a.methods.registered[reg.method] {
		panic(fmt.Sprintf("session: the %s sign-in method is registered twice on one Auth: register each method once", reg.method))
	}
	if reg.err != nil {
		panic(fmt.Errorf("session: the %s sign-in method: %w", reg.method, reg.err))
	}

	if reg.password != nil {
		a.methods.registered[reg.method] = true
		a.methods.hasher, a.methods.autoUpgrade = reg.password.hasher, reg.password.autoUpgrade

		return methodHandlers{login: a.serving(a.passwordLogin()), changeUserPassword: a.serving(a.changeUserPasswordHandler())}
	}

	if !a.storage.IdentitiesEnabled() {
		panic(fmt.Errorf("session: the %s sign-in method links external identities: %w", reg.method, sessionstorage.ErrIdentitiesNotConfigured))
	}
	m, err := reg.external(a.cookies)
	if err != nil {
		panic(fmt.Errorf("session: the %s sign-in method: %w", reg.method, err))
	}
	a.methods.registered[reg.method] = true
	a.methods.external[reg.method] = m

	h := methodHandlers{login: a.serving(a.externalLogin(m)), callback: a.serving(a.externalCallback(m))}
	if reg.method == sessioninfo.MethodAzure {
		h.frontChannelLogout = a.serving(a.frontChannelLogout())
	}

	return h
}

// registerMethod registers reg on auth: the registration functions' one way in.
func registerMethod(auth signInRegistry, reg *signInRegistration) methodHandlers {
	if auth == nil {
		panic(fmt.Sprintf("session: the %s sign-in method is registered on a nil Auth: pass the Auth NewAuth returned", reg.method))
	}

	return auth.register(reg)
}

// PasswordMethod is the username and password sign-in method registered on an Auth:
// its handlers.
type PasswordMethod struct {
	login              http.HandlerFunc
	changeUserPassword http.HandlerFunc
}

// PasswordSignIn registers username and password sign-in on auth and returns its
// handlers. It takes the password options (HashAlgorithm, AutoUpgradeHashes); cookie and
// session options belong to NewAuth.
//
// It panics when the method is already registered on auth, when auth has served a
// request, or when it is given an option that is not a password option.
func PasswordSignIn(auth signInRegistry, options ...PasswordOption) *PasswordMethod {
	settings := &passwordAuthSettings{hasher: securehash.New(securehash.Argon2()), autoUpgrade: true}
	reg := &signInRegistration{method: sessioninfo.MethodPassword, password: settings}
	for _, opt := range options {
		o, ok := any(opt).(passwordOption)
		if !ok {
			reg.err = errors.New("PasswordSignIn takes password options (HashAlgorithm, AutoUpgradeHashes); pass cookie and session options to NewAuth")

			continue
		}
		o(settings)
	}
	h := registerMethod(auth, reg)

	return &PasswordMethod{login: h.login, changeUserPassword: h.changeUserPassword}
}

// Login accepts {"username", "password"}; on success it applies the sign-in policy and
// either starts the session or creates a pending identity (MFA). It answers
// {"mfaIsRequired": bool}, with "redirectUrl" when a PendingHook chose one; a refusal is
// 401 with {"message", "code"}, the code a sessioninfo.LoginRefusalCode.
func (m *PasswordMethod) Login() http.HandlerFunc { return m.login }

// ChangeUserPassword changes the signed-in account's password.
// {"oldPassword", "newPassword"}; every session of the account is destroyed and the
// caller continues in a new one. Route it behind ValidateSession.
func (m *PasswordMethod) ChangeUserPassword() http.HandlerFunc { return m.changeUserPassword }

// AzureMethod is the Microsoft Entra ID (Azure) OIDC sign-in method registered on an
// Auth: its handlers.
type AzureMethod struct {
	login              http.HandlerFunc
	callback           http.HandlerFunc
	frontChannelLogout http.HandlerFunc
}

// AzureSignIn registers Microsoft Entra ID (Azure) OIDC sign-in on auth and returns its
// handlers. The identity key is (tid, oid). roleSync is the required
// role-synchronization slot: RoleSync(manager) reconciles the account's roles to the
// token's roles claim whenever an Azure sign-in establishes a session, and refuses it
// (no_roles) when no recognized role results; DisableRoleSync() leaves roles to the
// application. WithLoginURL sets where refused and pending sign-ins are sent (default:
// /login).
//
// It panics when the method is already registered on auth, when auth has served a
// request, when auth's storage has no identities configuration
// (sessionstorage.ErrIdentitiesNotConfigured), or when roleSync is missing.
func AzureSignIn(auth signInRegistry, roleSync RoleSyncConfig, issuerURL, clientID, clientSecret, redirectURL string, options ...OIDCOption) *AzureMethod {
	return azureSignIn(auth, roleSync, func(cookies *internalcookie.Client) azureoidc.Authenticator {
		authn := azureoidc.New(cookies, issuerURL, clientID, clientSecret, redirectURL)
		applyLoginOptions(authn, options)

		return authn
	})
}

// azureSignIn registers the Azure method over the authenticator newAuthn builds.
func azureSignIn(auth signInRegistry, roleSync RoleSyncConfig, newAuthn func(cookies *internalcookie.Client) azureoidc.Authenticator) *AzureMethod {
	h := registerMethod(auth, &signInRegistration{
		method: sessioninfo.MethodAzure,
		external: func(cookies *internalcookie.Client) (*externalMethod, error) {
			rs, err := azureRoleSync(roleSync)
			if err != nil {
				return nil, err
			}

			return azureMethod(newAuthn(cookies), rs), nil
		},
	})

	return &AzureMethod{login: h.login, callback: h.callback, frontChannelLogout: h.frontChannelLogout}
}

// Login redirects to Microsoft. It accepts ?returnUrl=, which must be a path in this
// application (an absolute URL is refused with 400).
func (m *AzureMethod) Login() http.HandlerFunc { return m.login }

// Callback completes the provider round trip, resolves the identity, applies the
// sign-in policy, and starts the session, creates a pending identity, or redirects to
// the login URL with ?code=<LoginRefusalCode>.
//
// The redirect contract: a session established → returnUrl (default "/"); a pending
// identity → <login URL>?pending=<reason>[&returnUrl=<returnUrl>], reason "confirmation"
// or "mfa", or wherever a PendingHook sends it; a refusal → <login URL>?code=<code>.
func (m *AzureMethod) Callback() http.HandlerFunc { return m.callback }

// FrontChannelLogout handles Microsoft-initiated logout. Auth sessions do not record the
// provider's session ID yet, so it answers 501 Not Implemented.
func (m *AzureMethod) FrontChannelLogout() http.HandlerFunc { return m.frontChannelLogout }

// GoogleMethod is the Google Workspace OIDC sign-in method registered on an Auth: its
// handlers.
type GoogleMethod struct {
	login    http.HandlerFunc
	callback http.HandlerFunc
}

// GoogleSignIn registers Google Workspace OIDC sign-in on auth and returns its handlers.
// The identity key is sub. roleSync is the required role-synchronization slot
// (GoogleRoleSync or DisableRoleSync), with the semantics of AzureSignIn's;
// hostedDomain is required and enforced against the hd claim. WithLoginURL sets where
// refused and pending sign-ins are sent (default: /login).
//
// It panics when the method is already registered on auth, when auth has served a
// request, when auth's storage has no identities configuration
// (sessionstorage.ErrIdentitiesNotConfigured), or when roleSync or hostedDomain is
// missing.
func GoogleSignIn(auth signInRegistry, roleSync GoogleRoleSyncConfig, clientID, clientSecret, redirectURL, hostedDomain string, options ...OIDCOption) *GoogleMethod {
	return googleSignIn(auth, roleSync, hostedDomain, func(cookies *internalcookie.Client, scopes []string) googleoidc.Authenticator {
		authn := googleoidc.New(cookies, clientID, clientSecret, redirectURL, hostedDomain, scopes...)
		applyLoginOptions(authn, options)

		return authn
	})
}

// googleSignIn registers the Google method over the authenticator newAuthn builds with
// the extra scopes the role sync needs.
func googleSignIn(auth signInRegistry, roleSync GoogleRoleSyncConfig, hostedDomain string, newAuthn func(cookies *internalcookie.Client, scopes []string) googleoidc.Authenticator) *GoogleMethod {
	h := registerMethod(auth, &signInRegistration{
		method: sessioninfo.MethodGoogle,
		external: func(cookies *internalcookie.Client) (*externalMethod, error) {
			rs, err := googleRoleSync(roleSync, hostedDomain)
			if err != nil {
				return nil, err
			}
			// With role sync on, the sign-in also asks for the groups scope, so the access
			// token Verify hands back can read the person's own groups.
			var scopes []string
			if rs != nil {
				scopes = []string{cloudidentity.Scope}
			}

			return googleMethod(newAuthn(cookies, scopes), rs), nil
		},
	})

	return &GoogleMethod{login: h.login, callback: h.callback}
}

// Login redirects to Google. It accepts ?returnUrl=, which must be a path in this
// application (an absolute URL is refused with 400).
func (m *GoogleMethod) Login() http.HandlerFunc { return m.login }

// Callback completes the provider round trip with the redirect contract of
// AzureMethod.Callback.
func (m *GoogleMethod) Callback() http.HandlerFunc { return m.callback }

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

// WorkOSMethod is the WorkOS SSO sign-in method registered on an Auth: its handlers.
type WorkOSMethod struct {
	login    http.HandlerFunc
	callback http.HandlerFunc
}

// WorkOSSignIn registers WorkOS SSO sign-in on auth and returns its handlers. The login
// handler reads the "organization" query parameter. The identity key is
// (connection_id, idp_id). Roles are never synchronized from WorkOS. WithLoginURL sets
// where refused and pending sign-ins are sent (default: /login).
//
// It panics when the method is already registered on auth, when auth has served a
// request, or when auth's storage has no identities configuration
// (sessionstorage.ErrIdentitiesNotConfigured).
func WorkOSSignIn(auth signInRegistry, apiKey, clientID, redirectURL string, options ...WorkOSSignInOption) *WorkOSMethod {
	var (
		settings    workOSSettings
		oidcOptions []OIDCOption
	)
	for _, opt := range options {
		switch o := opt.(type) {
		case OIDCOption:
			oidcOptions = append(oidcOptions, o)
		case workOSSignInOption:
			o(&settings)
		}
	}

	return workOSSignIn(auth, func(cookies *internalcookie.Client) workossso.Authenticator {
		authn := workossso.New(cookies, apiKey, clientID, redirectURL)
		if settings.baseURL != "" {
			authn.SetBaseURL(settings.baseURL)
		}
		applyLoginOptions(authn, oidcOptions)

		return authn
	})
}

// workOSSignIn registers the WorkOS method over the authenticator newAuthn builds.
func workOSSignIn(auth signInRegistry, newAuthn func(cookies *internalcookie.Client) workossso.Authenticator) *WorkOSMethod {
	h := registerMethod(auth, &signInRegistration{
		method: sessioninfo.MethodWorkOS,
		external: func(cookies *internalcookie.Client) (*externalMethod, error) {
			return workOSMethod(newAuthn(cookies)), nil
		},
	})

	return &WorkOSMethod{login: h.login, callback: h.callback}
}

// Login redirects to WorkOS. It requires ?organization= and accepts ?returnUrl=, which
// must be a path in this application (an absolute URL is refused with 400).
func (m *WorkOSMethod) Login() http.HandlerFunc { return m.login }

// Callback completes the provider round trip with the redirect contract of
// AzureMethod.Callback.
func (m *WorkOSMethod) Callback() http.HandlerFunc { return m.callback }

// frontChannelLogout answers provider-initiated logout. Auth sessions do not record the
// provider's session ID yet, so it answers 501.
func (a *Auth[S, U]) frontChannelLogout() http.HandlerFunc {
	return a.baseSession.Handle(func(w http.ResponseWriter, r *http.Request) error {
		return httpio.NewEncoder(w).ClientMessage(r.Context(), httpio.NewNotImplementedMessage("front-channel logout is not supported by Auth sessions yet"))
	})
}
