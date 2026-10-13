package session

import (
	"fmt"
	"net/http"
	"sync"
	"sync/atomic"

	"github.com/cccteam/ccc/securehash"
	"github.com/cccteam/httpio"
	"github.com/cccteam/session/internal/sessioncore"
	"github.com/cccteam/session/sessioninfo"
	"github.com/cccteam/session/sessionstorage"
	"github.com/cccteam/session/signin"
	"github.com/go-playground/errors/v5"
)

// signInRegistry is the Auth a sign-in method is registered on. It lets the
// registration functions accept an Auth of any SessionData and UserData and return
// method types that are not generic. An external method registers through signin.Core,
// which the Auth implements with RegisterExternal.
type signInRegistry interface {
	register(reg *signInRegistration) methodHandlers
}

var (
	_ signInRegistry = (*Auth[NoCustomData, NoCustomData])(nil)
	_ signin.Core    = (*Auth[NoCustomData, NoCustomData])(nil)
)

// signInRegistration is what a registration function asks the Auth to register.
type signInRegistration struct {
	method sessioninfo.AuthMethod
	// password is the password method's settings; nil for an external method.
	password *sessioncore.PasswordSettings
	// external is an external method's registration; nil for the password method.
	external *signin.Registration
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

// signInMethods are an Auth's registered sign-in methods. Registration writes them
// under mu until the Auth is first used. After that they are read-only, and requests
// read them without the lock.
type signInMethods struct {
	mu    sync.Mutex
	inUse atomic.Bool

	registered map[sessioninfo.AuthMethod]bool
	// hasher and autoUpgrade are the password method's settings. They keep their
	// defaults when it is not registered, since user management still hashes
	// passwords.
	hasher      *securehash.SecureHasher
	autoUpgrade bool
	// external holds the registered redirect-based methods.
	external map[sessioninfo.AuthMethod]*signin.Method
}

// registered returns the Auth's sign-in methods and closes registration. Every read
// goes through here, so a read never races a registration.
func (a *Auth[S, U]) registered() *signInMethods {
	if !a.methods.inUse.Load() {
		a.methods.mu.Lock()
		a.methods.inUse.Store(true)
		a.methods.mu.Unlock()
	}

	return &a.methods
}

// serving wraps every handler and middleware the Auth hands out, so the first request
// closes registration.
func (a *Auth[S, U]) serving(h http.Handler) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		a.registered()
		h.ServeHTTP(w, r)
	}
}

// register registers a sign-in method and returns its handlers. It is the one place
// the registration rules are enforced. A refused registration panics, because it is a
// wiring mistake found at startup, the way http.ServeMux refuses a duplicate pattern.
// See the README's "Registering sign-in methods".
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
		a.methods.hasher, a.methods.autoUpgrade = reg.password.Hasher, reg.password.AutoUpgrade

		return methodHandlers{login: a.serving(a.passwordLogin()), changeUserPassword: a.serving(a.changeUserPasswordHandler())}
	}

	if !a.storage.IdentitiesEnabled() {
		panic(fmt.Errorf("session: the %s sign-in method links external identities: %w", reg.method, sessionstorage.ErrIdentitiesNotConfigured))
	}
	m, err := reg.external.Build(a.cookies)
	if err != nil {
		panic(fmt.Errorf("session: the %s sign-in method: %w", reg.method, err))
	}
	a.methods.registered[reg.method] = true
	a.methods.external[reg.method] = m

	h := methodHandlers{login: a.serving(a.externalLogin(m)), callback: a.serving(a.externalCallback(m))}
	if reg.external.FrontChannelLogout {
		h.frontChannelLogout = a.serving(a.frontChannelLogout())
	}

	return h
}

// RegisterExternal registers a redirect-based sign-in method and returns its handlers.
// It implements signin.Core: the method packages (azure, google, workos) reach it
// through signin.Register, so an application never calls it directly. It panics on a
// registration rule, as register documents.
func (a *Auth[S, U]) RegisterExternal(reg *signin.Registration) signin.Handlers {
	h := a.register(&signInRegistration{method: reg.Method, external: reg, err: reg.Err})

	return signin.Handlers{Login: h.login, Callback: h.callback, FrontChannelLogout: h.frontChannelLogout}
}

// registerMethod registers reg on auth. The registration functions all go through it.
func registerMethod(auth signInRegistry, reg *signInRegistration) methodHandlers {
	if auth == nil {
		panic(fmt.Sprintf("session: the %s sign-in method is registered on a nil Auth: pass the Auth NewAuth returned", reg.method))
	}

	return auth.register(reg)
}

// PasswordMethod holds the handlers of the username and password sign-in method.
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
	settings := sessioncore.DefaultPasswordSettings()
	reg := &signInRegistration{method: sessioninfo.MethodPassword, password: &settings}
	for _, opt := range options {
		if !settings.Apply(opt) {
			reg.err = errors.New("PasswordSignIn takes password options (HashAlgorithm, AutoUpgradeHashes); pass cookie and session options to NewAuth")
		}
	}
	h := registerMethod(auth, reg)

	return &PasswordMethod{login: h.login, changeUserPassword: h.changeUserPassword}
}

// Login accepts {"username", "password"}. On success it applies the sign-in policy and
// either starts the session or creates a pending identity for MFA. It answers
// {"mfaIsRequired": bool}, plus "redirectUrl" when a PendingHook chose one. A refusal
// is 401 with {"message", "code"}, where code is a sessioninfo.LoginRefusalCode.
func (m *PasswordMethod) Login() http.HandlerFunc { return m.login }

// ChangeUserPassword accepts {"oldPassword", "newPassword"} and changes the signed-in
// user's password. Every session of the user is destroyed and the caller
// continues in a new one. Route it behind ValidateSession.
func (m *PasswordMethod) ChangeUserPassword() http.HandlerFunc { return m.changeUserPassword }

// frontChannelLogout answers 501 until Auth sessions record the provider's session ID.
func (a *Auth[S, U]) frontChannelLogout() http.HandlerFunc {
	return a.baseSession.Handle(func(w http.ResponseWriter, r *http.Request) error {
		return httpio.NewEncoder(w).ClientMessage(r.Context(), httpio.NewNotImplementedMessage("front-channel logout is not supported by Auth sessions yet"))
	})
}
