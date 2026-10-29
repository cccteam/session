package session

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"maps"
	"net/http"
	"slices"
	"strings"
	"sync"
	"sync/atomic"

	"github.com/cccteam/ccc/securehash"
	"github.com/cccteam/ccc/tracer"
	"github.com/cccteam/httpio"
	"github.com/cccteam/session/internal/attempts"
	internalcookie "github.com/cccteam/session/internal/cookie"
	"github.com/cccteam/session/internal/sessioncore"
	"github.com/cccteam/session/sessioninfo"
	"github.com/cccteam/session/sessionstorage"
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

// externalMethod is a registered redirect-based method with the account rules its
// registration gave it: the standard rule the core applies and the application's own,
// either of which may be absent.
type externalMethod[Tx any] struct {
	*signin.Method
	name     string
	standard signin.StandardAccountRule
	rule     signin.AccountRule[Tx]
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
	// syncing is the name of the registration whose directory writes the roles of
	// everyone on the Auth (its Method's SyncRoles is set), "" when none does. Such a
	// registration stands alone: role authority is the Auth's, not a registration's,
	// so a second method beside it would be a second authority over the same users
	// (a person it provisions holds nothing, and the surface refuses to seat them
	// because the directory will not). refuseBeside holds the rule both ways.
	syncing string
	// listed holds the names Methods was given, the methods the login page offers, in
	// the page's order; nil when the application wired its page without Methods.
	listed []string
	// hasher and autoUpgrade are the password method's settings. They keep their
	// defaults when it is not registered, since user management still hashes
	// passwords.
	hasher      *securehash.SecureHasher
	autoUpgrade bool
	// attempts limits failed password attempts. It is built over the store under the
	// default limit, and the password method's registration replaces it with one
	// under its own, so a password check through the API is limited either way.
	attempts *attempts.Limiter
	// compare checks a password against a hash with the method's hasher; a test counts
	// the checks through it.
	compare func(hash *securehash.Hash, password string) (upgrade bool, err error)
	// dummy is a hash the method's hasher made of a random secret, compared against for
	// a name that has no user or no password, so a refusal takes as long as one for a
	// wrong password. It is made once, at the first check, when the hasher is fixed.
	dummy     *securehash.Hash
	dummyOnce sync.Once
	// external holds the registered redirect-based methods by registration name.
	external map[string]*externalMethod[Tx]
	// password is the password method's registration, nil until it is registered: its
	// username shape and whether it offers sign-up.
	password *sessioncore.PasswordSettings
	// outlets holds the names of the registered machine outlets (RegisterMachineOutlet),
	// the only outlets tokens are issued for and accepted on.
	outlets map[string]bool
}

// passwordRegistered reports whether the password method is registered.
func (m *signInMethods[Tx]) passwordRegistered() bool {
	return m.password != nil
}

// usernameIsEmail reports whether the password method declares the username as the
// email address.
func (m *signInMethods[Tx]) usernameIsEmail() bool {
	return m.password != nil && m.password.UsernameIsEmail
}

// openSignUp reports whether the password method offers sign-up.
func (m *signInMethods[Tx]) openSignUp() bool {
	return m.password != nil && m.password.OpenSignUp
}

// offeredNames are the names of the methods the login page offers, in the order it
// shows them: the listing's when the application wrote one with Methods, every
// registration's, sorted, when it wired the page without one.
func (m *signInMethods[Tx]) offeredNames() []string {
	if m.listed != nil {
		return m.listed
	}

	return slices.Sorted(maps.Keys(m.registered))
}

// offered reports whether the method registered under name is offered on the login
// page (offeredNames).
func (m *signInMethods[Tx]) offered(name string) bool {
	return slices.Contains(m.offeredNames(), name)
}

// admittingMethodNames are the names of the external registrations the login page
// offers that could admit an identity with this email address, in the page's order:
// those whose method admits the address or cannot tell (a nil AdmitsAddress). The
// invitation answers carry them, so the page hides the buttons that would refuse the
// invitee. The password method is never among them; the answers tell its presence
// apart. The list is empty, never nil, when no such registration could admit the
// address.
func (a *Auth[S, U, Tx]) admittingMethodNames(email string) []string {
	m := a.registered()
	names := []string{}
	for _, name := range m.offeredNames() {
		if ext, ok := m.external[name]; ok && (ext.AdmitsAddress == nil || ext.AdmitsAddress(email)) {
			names = append(names, name)
		}
	}

	return names
}

// couldAdmitAddress reports whether a sign-in method the login page offers could admit
// an identity with this email address, which an invitation about to be sent to it
// asks: the password method, since the invited person then creates an account with a
// password, or an external registration that admits the address or cannot tell
// (admittingMethodNames). An Auth with no method at all admits, having nothing to
// judge by.
func (a *Auth[S, U, Tx]) couldAdmitAddress(email string) bool {
	m := a.registered()

	return len(m.registered) == 0 || m.offered(string(sessioninfo.MethodPassword)) || len(a.admittingMethodNames(email)) > 0
}

// init sets the methods of a new Auth over storage, before any registration: the
// default hasher and attempt limit, no external methods.
func (m *signInMethods[Tx]) init(storage sessionstorage.AuthStore[Tx]) {
	m.registered = make(map[string]bool)
	m.hasher = securehash.New(securehash.Argon2())
	m.autoUpgrade = true
	m.attempts = attempts.New(sessioncore.DefaultAttemptLimit, storage)
	m.external = make(map[string]*externalMethod[Tx])
	m.outlets = make(map[string]bool)
	m.compare = func(hash *securehash.Hash, password string) (bool, error) {
		return m.hasher.Compare(hash, password)
	}
}

// comparePassword checks password against hash, reporting whether the hash should be
// upgraded. A nil hash (a user without a password) fails like a wrong password, so the
// hasher never sees nil.
func (m *signInMethods[Tx]) comparePassword(hash *securehash.Hash, password string) (upgrade bool, err error) {
	if hash == nil {
		return false, sessioncore.ErrNoPassword
	}
	upgrade, err = m.compare(hash, password)
	if err != nil {
		return false, errors.Wrap(err, "securehash.SecureHasher.Compare()")
	}

	return upgrade, nil
}

// dummyHash is the hash compared against for a name with no user or no password. It
// is nil only when the hasher failed to make it, which is logged by the check that
// found out.
func (m *signInMethods[Tx]) dummyHash() (*securehash.Hash, error) {
	var err error
	m.dummyOnce.Do(func() {
		secret := make([]byte, 32)
		if _, err = rand.Read(secret); err != nil {
			err = errors.Wrap(err, "rand.Read()")

			return
		}
		m.dummy, err = m.hasher.Hash(base64.RawStdEncoding.EncodeToString(secret))
		if err != nil {
			err = errors.Wrap(err, "securehash.SecureHasher.Hash()")
		}
	})

	return m.dummy, err
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
	// The registration's state cookie is named for it; a name no cookie can carry is
	// refused here rather than at the first login.
	probe := &http.Cookie{Name: internalcookie.StateCookieName(a.cookies.CookieName, name), Value: "x", Secure: true, HttpOnly: true, SameSite: http.SameSiteLaxMode}
	if err := probe.Valid(); err != nil {
		panic(fmt.Sprintf("session: the %s sign-in method is registered under the name %q, which cannot name its state cookie (%v): "+
			"use letters, digits and hyphens, such as \"lakeside-entra\"", method, name, err))
	}
	if a.methods.registered[name] {
		panic(fmt.Sprintf("session: the %s sign-in method is registered twice on one Auth under the name %q: give each registration its own name", method, name))
	}
	if misuse != nil {
		panic(fmt.Errorf("session: the %s sign-in method: %w", method, misuse))
	}
}

// refuseBeside holds the rule that a registration whose directory writes the roles
// stands alone on its Auth, in both orders of registration: the method being registered
// synchronizes roles (syncs) and another method is registered already, or a syncing
// registration is registered already and any method follows. Role authority is the
// Auth's, not a registration's: the Auth is one users table, one role file and one
// administration surface, so when a directory writes the roles it writes them for
// everyone in the table, and a second way in would be a second authority over the same
// people (a person it provisions holds nothing at their first sign-in, and the
// administration surface refuses to seat them because the directory will not). Two
// populations with two authorities are two Auths. Both messages name the two ways out.
func (a *Auth[S, U, Tx]) refuseBeside(name string, method sessioninfo.AuthMethod, syncs bool) {
	if a.methods.syncing != "" {
		panic(fmt.Sprintf("session: the %s sign-in method %q is registered beside %q, whose directory writes the roles of everyone on this Auth: "+
			"a registration that synchronizes roles stands alone. Register %q on an Auth of its own, or construct %q with DisableRoleSync so the application assigns the roles",
			method, name, a.methods.syncing, name, a.methods.syncing))
	}
	if syncs && len(a.methods.registered) > 0 {
		others := slices.Sorted(maps.Keys(a.methods.registered))
		panic(fmt.Sprintf("session: the %s sign-in method %q synchronizes roles and is registered beside %s: "+
			"a registration that synchronizes roles stands alone, since its directory writes the roles of everyone on the Auth. "+
			"Register it on an Auth of its own, or construct it with DisableRoleSync so the application assigns the roles",
			method, name, strings.Join(others, ", ")))
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
	a.refuseBeside(reg.name, reg.method, false)
	if reg.password.OpenSignUp && a.settings.mail == nil {
		panic("session: the password method is registered with OpenSignUp on an Auth without mail: a sign-up starts from a link mailed to the person, so pass WithMail to NewAuth")
	}
	a.methods.registered[reg.name] = true
	a.methods.hasher, a.methods.autoUpgrade = reg.password.Hasher, reg.password.AutoUpgrade
	a.methods.attempts = attempts.New(reg.password.Attempts, a.storage)
	settings := *reg.password
	a.methods.password = &settings
	a.storage.SetUsernameIsEmail(settings.UsernameIsEmail)

	return methodHandlers{login: a.serving(a.passwordLogin()), changeUserPassword: a.serving(a.changeUserPasswordHandler())}
}

// RegisterExternal registers a redirect-based sign-in method under its registration's
// name and returns its handlers. It implements signin.Core: the method packages (azure,
// google; workos under internal until v0.13.1) reach it through signin.Register, so an application never calls it
// directly. It panics on a registration rule, as refuseRegistration documents, when
// the registration has neither a standard account rule nor a custom one, when it
// names a standard rule that does not exist, and when a registration that synchronizes
// roles would stand beside another method, as refuseBeside documents.
func (a *Auth[S, U, Tx]) RegisterExternal(reg *signin.Registration[Tx]) signin.Handlers {
	if a == nil {
		panic(fmt.Sprintf("session: the %s sign-in method is registered on a nil *Auth: pass the Auth NewAuth returned", reg.Method))
	}

	a.methods.mu.Lock()
	defer a.methods.mu.Unlock()

	a.refuseRegistration(reg.Name, reg.Method, reg.Err)
	switch {
	case reg.StandardRule == "" && reg.AccountRule == nil:
		panic(fmt.Sprintf("session: the %s sign-in method links external identities and needs an account rule: it has no standard rule, so pass one to its registration", reg.Method))
	case reg.StandardRule != "":
		if err := reg.StandardRule.Validate(); err != nil {
			panic(fmt.Errorf("session: the %s sign-in method: Accounts: %w", reg.Method, err))
		}
	}
	if reg.FrontChannelLogout && reg.Issuers == nil {
		panic(fmt.Sprintf("session: the %s sign-in method asks for a front-channel logout handler without declaring its issuers: set Registration.Issuers", reg.Method))
	}
	m, err := reg.Build(a.cookies.ForRegistration(reg.Name))
	if err != nil {
		panic(fmt.Errorf("session: the %s sign-in method: %w", reg.Method, err))
	}
	a.refuseBeside(reg.Name, reg.Method, m.SyncRoles != nil)
	if m.SyncRoles != nil {
		a.methods.syncing = reg.Name
	}
	a.methods.registered[reg.Name] = true
	a.methods.external[reg.Name] = &externalMethod[Tx]{Method: m, name: reg.Name, standard: reg.StandardRule, rule: reg.AccountRule}

	h := signin.Handlers{Login: a.serving(a.externalLogin(m)), Callback: a.serving(a.externalCallback(reg.Name, reg.Issuers, m))}
	if reg.FrontChannelLogout {
		h.FrontChannelLogout = a.serving(a.frontChannelLogout(reg.Issuers))
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
// handlers. It takes the password options (HashAlgorithm, AutoUpgradeHashes,
// AttemptLimit, UsernameIsEmail, OpenSignUp); cookie and session options belong to
// NewAuth.
//
// It panics when the method is already registered on auth, when auth has served a
// request, when it is given an option that is not a password option, or when the
// attempt limit is not at least one failure within a positive window and lock. The
// registration is named "password".
func PasswordSignIn(auth signInRegistry, options ...PasswordOption) *PasswordMethod {
	settings := sessioncore.DefaultPasswordSettings()
	reg := &signInRegistration{name: string(sessioninfo.MethodPassword), method: sessioninfo.MethodPassword, password: &settings}
	for _, opt := range options {
		if !settings.Apply(opt) {
			reg.err = errors.New("PasswordSignIn takes password options (HashAlgorithm, AutoUpgradeHashes, AttemptLimit, UsernameIsEmail, OpenSignUp); pass cookie and session options to NewAuth")
		}
	}
	if limit := settings.Attempts; reg.err == nil && (limit.Failures < 1 || limit.Window <= 0 || limit.Lock <= 0) {
		reg.err = errors.Newf("AttemptLimit(%d, %s, %s): the limit is at least one failure within a positive window, locking for a positive period", limit.Failures, limit.Window, limit.Lock)
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
// user's password to one they chose: the old one must match and the new one differ
// (400 otherwise). The password change mark is cleared, every session of the user is
// destroyed and the caller continues in a new one. It is the one route a user who must
// change their password reaches, so it validates the session itself: route it beside
// the session read and the logout, outside ValidateSession and behind
// ValidateXSRFToken, and name its path to Methods (MethodList.ChangePassword).
func (m *PasswordMethod) ChangeUserPassword() http.HandlerFunc { return m.changeUserPassword }

// frontChannelLogout handles a provider-initiated logout: it ends every live session
// whose sign-in carried the provider's session id the request names (?sid=) under an
// issuer the registration declares, and answers 200. A request naming an issuer (?iss=)
// is scoped to it, and refused (400) when the registration does not declare it. A
// request naming none is scoped to the registration's only issuer when it has one, and
// when it serves several, to whichever of its issuers live sessions carry the id under:
// a provider's session id is unique within the provider, and every issuer a registration
// declares is that provider's. Entra sends the sid alone, and the OpenID front-channel
// logout specification leaves iss optional. A request without a sid is 400. The
// provider calls it in a frame, with no session of its own, so it reads nothing from
// the browser: a known sid under a declared issuer is the request's only credential.
func (a *Auth[S, U, Tx]) frontChannelLogout(issuers signin.Issuers) http.HandlerFunc {
	return a.baseSession.Handle(func(w http.ResponseWriter, r *http.Request) error {
		ctx, span := tracer.Start(r.Context())
		defer span.End()

		query := r.URL.Query()
		sid := query.Get("sid")
		if sid == "" {
			return httpio.NewEncoder(w).BadRequestMessage(ctx, "missing sid query parameter")
		}
		iss := query.Get("iss")
		if iss != "" && !issuers.Contains(iss) {
			return httpio.NewEncoder(w).BadRequestMessage(ctx, "iss does not name an issuer of this registration")
		}
		scoped, err := a.logoutIssuers(ctx, issuers, iss, sid)
		if err != nil {
			return httpio.NewEncoder(w).ClientMessage(ctx, err)
		}
		for _, scopedIss := range scoped {
			if err := a.storage.DestroySessionsByProviderSessionID(ctx, scopedIss, sid); err != nil {
				return httpio.NewEncoder(w).ClientMessage(ctx, errors.Wrap(err, "sessionstorage.AuthStore.DestroySessionsByProviderSessionID()"))
			}
		}

		return httpio.NewEncoder(w).Ok(nil)
	})
}

// logoutIssuers is the issuers a provider-initiated logout for sid is scoped to: the
// declared issuer the request names, the registration's only issuer when the request
// names none, or, for a registration serving several, the declared issuers live
// sessions carry sid under.
func (a *Auth[S, U, Tx]) logoutIssuers(ctx context.Context, issuers signin.Issuers, iss, sid string) ([]string, error) {
	if iss != "" {
		return []string{iss}, nil
	}
	if only, ok := issuers.Only(); ok {
		return []string{only}, nil
	}
	recorded, err := a.storage.ProviderSessionIssuers(ctx, sid)
	if err != nil {
		return nil, errors.Wrap(err, "sessionstorage.AuthStore.ProviderSessionIssuers()")
	}
	scoped := make([]string, 0, len(recorded))
	for _, recordedIss := range recorded {
		if issuers.Contains(recordedIss) {
			scoped = append(scoped, recordedIss)
		}
	}

	return scoped, nil
}
