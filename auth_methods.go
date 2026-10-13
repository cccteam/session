package session

import (
	"fmt"
	"net/http"
	"sync"
	"sync/atomic"

	"github.com/cccteam/ccc/securehash"
	"github.com/cccteam/ccc/tracer"
	"github.com/cccteam/httpio"
	"github.com/cccteam/session/internal/sessioncore"
	"github.com/cccteam/session/sessioninfo"
	"github.com/cccteam/session/signin"
	"github.com/go-playground/errors/v5"
)

// signInRegistry is the Auth the password method is registered on. It lets
// PasswordSignIn accept an Auth of any SessionData, UserData and transaction type and
// return a method type that is not generic. An external method registers through
// signin.Core, which the Auth implements with RegisterExternal.
type signInRegistry interface {
	register(reg *signInRegistration) methodHandlers
}

var (
	_ signInRegistry        = (*Auth[NoCustomData, NoCustomData, struct{}])(nil)
	_ signin.Core[struct{}] = (*Auth[NoCustomData, NoCustomData, struct{}])(nil)
)

// signInRegistration is what the password method's registration asks the Auth to
// register.
type signInRegistration struct {
	name   string
	method sessioninfo.AuthMethod
	// password is the password method's settings.
	password *sessioncore.PasswordSettings
	// err is a misuse the registration function found in its own arguments.
	err error
}

// methodHandlers are the password method's handlers.
type methodHandlers struct {
	login              http.HandlerFunc
	changeUserPassword http.HandlerFunc
}

// externalMethod is a registered redirect-based method with the user resolver its
// registration gave it.
type externalMethod[Tx any] struct {
	*signin.Method
	name    string
	resolve signin.UserResolver[Tx]
}

// signInMethods are an Auth's registered sign-in methods. Registration writes them
// under mu until the Auth is first used. After that they are read-only, and requests
// read them without the lock.
type signInMethods[Tx any] struct {
	mu    sync.Mutex
	inUse atomic.Bool

	// registered holds the names of every registration, the password method's being
	// its method name.
	registered map[string]bool
	// hasher and autoUpgrade are the password method's settings. They keep their
	// defaults when it is not registered, since user management still hashes
	// passwords.
	hasher      *securehash.SecureHasher
	autoUpgrade bool
	// external holds the registered redirect-based methods by registration name.
	external map[string]*externalMethod[Tx]
}

// registered returns the Auth's sign-in methods and closes registration. Every read
// goes through here, so a read never races a registration.
func (a *Auth[S, U, Tx]) registered() *signInMethods[Tx] {
	if !a.methods.inUse.Load() {
		a.methods.mu.Lock()
		a.methods.inUse.Store(true)
		a.methods.mu.Unlock()
	}

	return &a.methods
}

// serving wraps every handler and middleware the Auth hands out, so the first request
// closes registration.
func (a *Auth[S, U, Tx]) serving(h http.Handler) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		a.registered()
		h.ServeHTTP(w, r)
	}
}

// refuseRegistration enforces, under the methods lock, the registration rules every
// method shares. A refused registration panics, because it is a wiring mistake found
// at startup, the way http.ServeMux refuses a duplicate pattern. See the README's
// "Registering sign-in methods".
func (a *Auth[S, U, Tx]) refuseRegistration(name string, method sessioninfo.AuthMethod, misuse error) {
	if a.methods.inUse.Load() {
		panic(fmt.Sprintf("session: the %s sign-in method is registered after the Auth is in use (it has served a request or checked a password): register every sign-in method before serving", method))
	}
	if name == "" {
		panic(fmt.Sprintf("session: the %s sign-in method is registered without a name: name each registration (two Entra tenants are two registrations)", method))
	}
	if a.methods.registered[name] {
		panic(fmt.Sprintf("session: the %s sign-in method is registered twice on one Auth under the name %q: give each registration its own name", method, name))
	}
	if misuse != nil {
		panic(fmt.Errorf("session: the %s sign-in method: %w", method, misuse))
	}
}

// register registers the password method and returns its handlers.
func (a *Auth[S, U, Tx]) register(reg *signInRegistration) methodHandlers {
	if a == nil {
		panic(fmt.Sprintf("session: the %s sign-in method is registered on a nil *Auth: pass the Auth NewAuth returned", reg.method))
	}

	a.methods.mu.Lock()
	defer a.methods.mu.Unlock()

	a.refuseRegistration(reg.name, reg.method, reg.err)
	a.methods.registered[reg.name] = true
	a.methods.hasher, a.methods.autoUpgrade = reg.password.Hasher, reg.password.AutoUpgrade

	return methodHandlers{login: a.serving(a.passwordLogin()), changeUserPassword: a.serving(a.changeUserPasswordHandler())}
}

// RegisterExternal registers a redirect-based sign-in method under its registration's
// name and returns its handlers. It implements signin.Core: the method packages (azure,
// google, workos) reach it through signin.Register, so an application never calls it
// directly. It panics on a registration rule, as refuseRegistration documents, and when
// the registration has no user resolver.
func (a *Auth[S, U, Tx]) RegisterExternal(reg *signin.Registration[Tx]) signin.Handlers {
	if a == nil {
		panic(fmt.Sprintf("session: the %s sign-in method is registered on a nil *Auth: pass the Auth NewAuth returned", reg.Method))
	}

	a.methods.mu.Lock()
	defer a.methods.mu.Unlock()

	a.refuseRegistration(reg.Name, reg.Method, reg.Err)
	if reg.Resolve == nil {
		panic(fmt.Sprintf("session: the %s sign-in method links external identities and needs a user resolver: pass one to its registration", reg.Method))
	}
	m, err := reg.Build(a.cookies)
	if err != nil {
		panic(fmt.Errorf("session: the %s sign-in method: %w", reg.Method, err))
	}
	a.methods.registered[reg.Name] = true
	a.methods.external[reg.Name] = &externalMethod[Tx]{Method: m, name: reg.Name, resolve: reg.Resolve}

	h := signin.Handlers{Login: a.serving(a.externalLogin(m)), Callback: a.serving(a.externalCallback(reg.Name, m))}
	if reg.FrontChannelLogout {
		h.FrontChannelLogout = a.serving(a.frontChannelLogout())
	}

	return h
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
// request, or when it is given an option that is not a password option. The
// registration is named "password".
func PasswordSignIn(auth signInRegistry, options ...PasswordOption) *PasswordMethod {
	settings := sessioncore.DefaultPasswordSettings()
	reg := &signInRegistration{name: string(sessioninfo.MethodPassword), method: sessioninfo.MethodPassword, password: &settings}
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

// frontChannelLogout handles a provider-initiated logout: it ends every session whose
// sign-in carried the provider's session id the request names (?sid=) and answers
// 200; a request without a sid is 400. The provider calls it in a frame, with no
// session of its own, so it reads nothing from the browser.
func (a *Auth[S, U, Tx]) frontChannelLogout() http.HandlerFunc {
	return a.baseSession.Handle(func(w http.ResponseWriter, r *http.Request) error {
		ctx, span := tracer.Start(r.Context())
		defer span.End()

		sid := r.URL.Query().Get("sid")
		if sid == "" {
			return httpio.NewEncoder(w).BadRequestMessage(ctx, "missing sid query parameter")
		}
		if err := a.storage.DestroySessionsByProviderSessionID(ctx, sid); err != nil {
			return httpio.NewEncoder(w).ClientMessage(ctx, errors.Wrap(err, "sessionstorage.AuthStore.DestroySessionsByProviderSessionID()"))
		}

		return httpio.NewEncoder(w).Ok(nil)
	})
}
