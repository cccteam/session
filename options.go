package session

import (
	"time"

	"github.com/cccteam/ccc/securehash"
	"github.com/cccteam/session/internal/basesession"
	"github.com/cccteam/session/internal/cookie"
	"github.com/cccteam/session/internal/sessioncore"
)

// The option interfaces of the session types. Each is sealed: only the option types
// below, and a session type's own options, satisfy it.
type (
	// AuthOption configures an Auth session: the cookie options, the session options and
	// the Auth settings (WithIdentityLinked, WithPendingHook, WithPendingTimeout,
	// WithPendingCookieName).
	AuthOption = sessioncore.AuthOption
	// PreauthOption configures a Preauth session: the cookie options and the session
	// options.
	PreauthOption = sessioncore.PreauthOption
	// PasswordOption configures the password method (PasswordSignIn): AutoUpgradeHashes
	// and HashAlgorithm.
	PasswordOption = sessioncore.PasswordOption
)

// CookieOption configures the session cookie client. It is an option of every session
// type.
type CookieOption = sessioncore.CookieOption

// WithCookieName sets the cookie name for the session cookie.
func WithCookieName(name string) CookieOption {
	return CookieOption(cookie.WithCookieName(name))
}

// WithCookieDomain sets the domain for the session cookie.
func WithCookieDomain(domain string) CookieOption {
	return CookieOption(cookie.WithCookieDomain(domain))
}

// WithXSRFCookieName sets the cookie name for the XSRF cookie.
func WithXSRFCookieName(name string) CookieOption {
	return CookieOption(cookie.WithXSRFCookieName(name))
}

// WithXSRFHeaderName sets the header name for the XSRF header.
func WithXSRFHeaderName(name string) CookieOption {
	return CookieOption(cookie.WithXSRFHeaderName(name))
}

// BaseSessionOption configures the session itself. It is an option of every session
// type.
type BaseSessionOption = sessioncore.BaseSessionOption

// WithLogHandler sets the LogHandler. (default: httpio.Log)
func WithLogHandler(l LogHandler) BaseSessionOption {
	return BaseSessionOption(func(b *basesession.BaseSession) {
		b.Handle = l
	})
}

// WithSessionTableName sets the name of the session table. (default: Sessions) A
// name that is not a plain identifier (a letter or underscore, then up to 127 letters,
// digits or underscores) is refused by the session type's constructor, as every
// table-name option's is.
func WithSessionTableName(name string) BaseSessionOption {
	return BaseSessionOption(func(b *basesession.BaseSession) {
		b.TableNames = append(b.TableNames, basesession.TableName{Option: "WithSessionTableName", Name: name, Set: b.Storage.SetSessionTableName})
	})
}

// WithUserTableName sets the name of the user table. (default: SessionUsers)
func WithUserTableName(name string) BaseSessionOption {
	return BaseSessionOption(func(b *basesession.BaseSession) {
		b.TableNames = append(b.TableNames, basesession.TableName{Option: "WithUserTableName", Name: name, Set: b.Storage.SetUserTableName})
	})
}

// WithOIDCUserTableName sets the name of the OIDC user anchor table.
// (default: OIDCUsers)
//
// Deprecated: the OIDC user anchor serves the legacy OIDCAzure session type only
// (package legacy); Auth users are SessionUsers records. It is removed with the legacy
// types.
func WithOIDCUserTableName(name string) BaseSessionOption {
	return BaseSessionOption(func(b *basesession.BaseSession) {
		b.TableNames = append(b.TableNames, basesession.TableName{Option: "WithOIDCUserTableName", Name: name, Set: b.Storage.SetOIDCUserTableName})
	})
}

var defaultSessionTimeout = sessioncore.DefaultSessionTimeout

// WithSessionTimeout sets the session timeout. (default: 10m)
func WithSessionTimeout(d time.Duration) BaseSessionOption {
	return BaseSessionOption(func(b *basesession.BaseSession) {
		b.SessionTimeout = d
	})
}

// AutoUpgradeHashes controls if password hashes will be auto upgraded (default: true)
func AutoUpgradeHashes(a bool) PasswordOption {
	return sessioncore.AutoUpgradeHashes(a)
}

// HashAlgorithm controls hashing algrorithm (default: securehash.Argon2())
func HashAlgorithm(hasher securehash.HashAlgorithm) PasswordOption {
	return sessioncore.HashAlgorithm(hasher)
}
