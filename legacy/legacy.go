// Package legacy holds the single-method session types that predate Auth: PasswordAuth
// (username and password) and OIDCAzure (Microsoft Entra ID), with their APIs, handler
// interfaces and options. They are deprecated: a new application uses session.Auth
// with the password method (session.PasswordSignIn) and the Microsoft Entra ID method
// (azure.SignIn), which share one session, one user model and one middleware chain.
// The types here keep working unchanged until every application has moved, and are
// then removed.
//
// Moving an application from the root package to this one is a mechanical edit: the
// import path and the qualifier of the constructor, the handler interface, the API type
// and WithLoginURL. The cookie and session options (session.WithCookieName,
// session.WithSessionTimeout, ...), the password options (session.AutoUpgradeHashes,
// session.HashAlgorithm), the role sync slot (session.RoleSync, session.DisableRoleSync)
// and session.NoCustomData stay where they are.
package legacy

import (
	"context"
	"sync"

	"github.com/cccteam/logger"
	"github.com/cccteam/session/internal/sessioncore"
)

// RouterSessionUserID is the router path parameter the PasswordAuth user-management
// handlers read the session user's ID from.
//
// Deprecated: it serves the legacy PasswordAuth handlers; the Auth session manages users
// through AuthAPI.
const RouterSessionUserID = "sessionUserID"

// PasswordOption configures NewPasswordAuth: the cookie and session options of the root
// package, session.AutoUpgradeHashes and session.HashAlgorithm.
//
// Deprecated: NewPasswordAuth is replaced by session.Auth with session.PasswordSignIn.
type PasswordOption = sessioncore.PasswordOption

// OIDCAzureOption configures NewOIDCAzure: the cookie and session options of the root
// package and WithLoginURL.
//
// Deprecated: NewOIDCAzure is replaced by session.Auth with azure.SignIn.
type OIDCAzureOption = sessioncore.OIDCAzureOption

// OIDCOption is the option WithLoginURL returns.
//
// Deprecated: azure.Config.LoginURL sets the login URL of the Auth session's method.
type OIDCOption = sessioncore.OIDCOption

// WithLoginURL sets where OIDCAzure sends a refused login. (default: /login)
//
// Deprecated: azure.Config.LoginURL sets the login URL of the Auth session's method.
func WithLoginURL(l string) OIDCOption {
	return sessioncore.WithLoginURL(l)
}

// deprecationLogged records which legacy types have announced themselves, so each is
// logged once per process.
var deprecationLogged sync.Map

// logDeprecated says at construction, once per process and type, that a legacy type is
// in use and what replaces it.
func logDeprecated(typeName, replacement string) {
	if _, seen := deprecationLogged.LoadOrStore(typeName, true); seen {
		return
	}
	logger.FromCtx(context.Background()).Warnf("session/legacy: %s is deprecated and will be removed: move to %s", typeName, replacement)
}
