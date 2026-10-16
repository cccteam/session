// Package signin is the contract between the Auth session and a sign-in method.
//
// The Auth session (the core) owns sessions, users, identities, the pending flow and
// the middleware. A sign-in method is a package that knows one way to establish who the
// person is: a password form in the core itself, or a redirect to an identity provider
// such as Microsoft Entra ID, Google Workspace or WorkOS. An external method registers
// on the core with Register and hands it a Method: how to begin the round trip to the
// provider, how to complete it into a verified identity, and how to synchronize the
// user's roles when the provider asserts them. The core builds the HTTP handlers, runs
// resolution, the sign-in policy and the session the same way for every method, and
// returns the handlers to the method.
//
// The package also holds the vocabulary of a sign-in's outcomes, which the application's
// hooks speak: the user resolver's Resolution, the sign-in policy's Decision and the
// causes of a refusal.
//
// A method package imports this package and never the core.
package signin

import (
	"context"
	"fmt"
	"net/http"

	"github.com/cccteam/session/cookie"
	"github.com/cccteam/session/sessioninfo"
)

// Core is what a method registers on: the Auth that session.NewAuth returned.
// *session.Auth implements it. Tx is the Auth's storage transaction type, which the
// method's user resolver receives.
type Core[Tx any] interface {
	// RegisterExternal registers a redirect-based method and returns its handlers. It
	// panics on a registration rule, because that is a wiring mistake found at startup:
	// the registration has no name or its name is already used, the core has served a
	// request, the registration has no user resolver, or reg.Err carries a misuse the
	// registration function found in its arguments.
	RegisterExternal(reg *Registration[Tx]) Handlers
}

// Registration is what a method asks the core to register.
type Registration[Tx any] struct {
	// Name identifies the registration on the core, where it must be unique. One
	// method may be registered several times under different names (two Entra
	// tenants); the name is the application's, such as "azure" or "lakeside-entra".
	Name string
	// Method names the method; it is the identity's method and the session's auth
	// event's.
	Method sessioninfo.AuthMethod
	// Resolve decides an identity of the method that is not linked to any user yet. It
	// is required: the method builds it over the resolver the application gave its
	// registration, typed to the method's identity.
	Resolve UserResolver[Tx]
	// Build builds the method over the registration's state cookie, which carries the
	// browser's half of a round trip to the provider; the core names it for the
	// registration.
	Build func(cookies StateCookies) (*Method, error)
	// FrontChannelLogout asks for the provider-initiated logout handler.
	FrontChannelLogout bool
	// Issuer is the provider's issuer. A sign-in's provider session id is recorded
	// under it, since a provider's session id is unique only within its issuer, and a
	// front-channel logout ends the sessions under this issuer and the id it names; a
	// request naming another issuer (iss) is refused. A registration without an issuer
	// records no provider session id and can serve no front-channel logout.
	Issuer string
	// Err is a misuse the registration function found in its own arguments; the core
	// panics with it.
	Err error
}

// StateCookies writes and reads a registration's state cookie: the state and PKCE
// verifier of a round trip to the provider, and the return URL the browser goes to
// afterwards. The core names the cookie for the registration (OIDC-<name>) and binds it
// to the registration, so two registrations of one method, and logins with different
// providers in one browser, never read each other's state. ReadStateCookie's readName
// is the cookie's name, or "" when the browser carries none for this registration;
// a state cookie is single-use, so the method passes readName to DeleteStateCookie.
type StateCookies interface {
	WriteStateCookie(w http.ResponseWriter, values *cookie.Values)
	ReadStateCookie(r *http.Request) (values *cookie.Values, readName string, err error)
	DeleteStateCookie(w http.ResponseWriter, name string)
}

// Method is a registered external method as the core drives it.
type Method struct {
	// Name is the method's name.
	Name sessioninfo.AuthMethod
	// LoginURL is where refused and pending sign-ins are sent.
	LoginURL func() string
	// Begin writes the method's state cookie and returns the provider URL the browser
	// goes to. returnURL is the sanitized path in the application the browser returns
	// to afterwards.
	Begin func(ctx context.Context, w http.ResponseWriter, r *http.Request, returnURL string) (string, error)
	// Complete verifies the provider's answer into a verified sign-in. Every refusal is a
	// sessioninfo.LoginRefusal.
	Complete func(ctx context.Context, w http.ResponseWriter, r *http.Request) (*Verified, error)
	// SyncRoles reconciles the user's roles to the role names the provider asserted,
	// and refuses the sign-in (no_roles) when no recognized role results. It is nil
	// when the method synchronizes no roles.
	SyncRoles func(ctx context.Context, username string, roleNames []string) error
}

// Verified is the result of a method's completed round trip.
type Verified struct {
	// Identity is who the provider says signed in, keyed by the method, its connection
	// and the provider's immutable subject.
	Identity *sessioninfo.Identity
	// ReturnURL is the sanitized path in the application the browser goes to afterwards.
	ReturnURL string
	// RoleNames are the role names the provider asserted. They are nil when the method
	// synchronizes no roles, and never nil when it does: "no roles asserted" is an empty
	// list.
	RoleNames []string
	// ProviderSessionID is the provider's own session id for this sign-in (an OpenID
	// Connect sid claim), which a provider-initiated logout names; "" when the method
	// has none.
	ProviderSessionID string
}

// Handlers are a registered method's HTTP handlers, built by the core.
type Handlers struct {
	// Login begins the round trip: it redirects the browser to the provider.
	Login http.HandlerFunc
	// Callback completes it: it resolves the identity, applies the sign-in policy and
	// establishes the session, holds it pending, or refuses it.
	Callback http.HandlerFunc
	// FrontChannelLogout handles a provider-initiated logout; nil unless the
	// registration asked for it.
	FrontChannelLogout http.HandlerFunc
}

// Register registers reg on core and returns its handlers. The registration functions
// of every method go through it: it refuses a nil core before the core can.
func Register[Tx any](core Core[Tx], reg *Registration[Tx]) Handlers {
	if core == nil {
		panic(fmt.Sprintf("session: the %s sign-in method is registered on a nil Auth: pass the Auth NewAuth returned", reg.Method))
	}

	return core.RegisterExternal(reg)
}

// RoleNames returns names, or an empty list for nil. A role-synchronizing method always
// carries a list, so "no roles asserted" stays distinct from "no role sync".
func RoleNames(names []string) []string {
	if names == nil {
		return []string{}
	}

	return names
}
