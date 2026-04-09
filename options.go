package session

import (
	"context"
	"time"

	"github.com/cccteam/ccc"
	"github.com/cccteam/ccc/securehash"
	"github.com/cccteam/session/internal/azureoidc"
	"github.com/cccteam/session/internal/basesession"
	"github.com/cccteam/session/internal/cookie"
	"github.com/cccteam/session/sessioninfo"
)

// CookieOption defines a function signature for setting cookie client options.
type CookieOption cookie.Option

func (CookieOption) isOIDCAzureOption() {}
func (CookieOption) isPasswordOption()  {}
func (CookieOption) isPreauthOption()   {}

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

// BaseSessionOption defines a function signature for setting session options.
type BaseSessionOption func(*basesession.BaseSession)

func (BaseSessionOption) isOIDCAzureOption() {}
func (BaseSessionOption) isPasswordOption()  {}
func (BaseSessionOption) isPreauthOption()   {}

// WithLogHandler sets the LogHandler. (default: httpio.Log)
func WithLogHandler(l LogHandler) BaseSessionOption {
	return BaseSessionOption(func(b *basesession.BaseSession) {
		b.Handle = l
	})
}

// WithSessionTableName sets the name of the session table. (default: Sessions)
func WithSessionTableName(name string) BaseSessionOption {
	return BaseSessionOption(func(b *basesession.BaseSession) {
		b.Storage.SetSessionTableName(name)
	})
}

// WithUserTableName sets the name of the user table. (default: SessionUsers)
func WithUserTableName(name string) BaseSessionOption {
	return BaseSessionOption(func(b *basesession.BaseSession) {
		b.Storage.SetUserTableName(name)
	})
}

var defaultSessionTimeout = time.Minute * 10

// WithSessionTimeout sets the session timeout. (default: 10m)
func WithSessionTimeout(d time.Duration) BaseSessionOption {
	return BaseSessionOption(func(b *basesession.BaseSession) {
		b.SessionTimeout = d
	})
}

// OIDCOption defines a function signature for setting OIDC options.
type OIDCOption func(*azureoidc.OIDC)

func (OIDCOption) isOIDCAzureOption() {}

// WithLoginURL sets the LoginURL for the SPA. (default: /login)
func WithLoginURL(l string) OIDCOption {
	return OIDCOption(func(b *azureoidc.OIDC) {
		b.SetLoginURL(l)
	})
}

// passwordOption defines a function signature for setting Password options.
type passwordOption func(*PasswordAuth)

func (passwordOption) isPasswordOption() {}

// AutoUpgradeHashes controls if password hashes will be auto upgraded (default: true)
func AutoUpgradeHashes(a bool) PasswordOption {
	return passwordOption(func(p *PasswordAuth) {
		p.autoUpgrade = a
	})
}

// HashAlgorithm controls hashing algrorithm (default: securehash.Argon2())
func HashAlgorithm(hasher securehash.HashAlgorithm) PasswordOption {
	return passwordOption(func(p *PasswordAuth) {
		p.hasher = securehash.New(hasher)
	})
}

// WithCustomSessionTableColumns sets additional column names to be included in the session table.
// This is used for session implementations that require additional columns in the session table, such as a tenant ID column for multi-tenant applications. (default: none)
func WithCustomSessionTableColumns(columnNames ...string) PasswordOption {
	return passwordOption(func(p *PasswordAuth) {
		p.customSessionTableColumns = columnNames
		p.storage.SetCustomSessionColumns(columnNames)
	})
}

// CustomSessionDataResolver defines a function signature for resolving custom session data for a given user ID at session creation time.
type CustomSessionDataResolver func(ctx context.Context, userID ccc.UUID) ([]sessioninfo.CustomData, error)

// WithCustomSessionDataResolver sets a function that resolves custom session data for a given user ID at session creation time.
func WithCustomSessionDataResolver(resolver CustomSessionDataResolver) PasswordOption {
	return passwordOption(func(p *PasswordAuth) {
		p.customSessionDataResolver = resolver
	})
}
