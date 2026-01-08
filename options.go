package session

import (
	"time"

	"github.com/cccteam/ccc/securehash"
	"github.com/cccteam/session/internal/azureoidc"
	"github.com/cccteam/session/internal/basesession"
	"github.com/cccteam/session/internal/cookie"
)

// CookieOption defines a function signature for setting cookie client options.
type CookieOption func(*cookie.CookieClient)

func (CookieOption) isOIDCAzureOption() {}
func (CookieOption) isPasswordOption()  {}
func (CookieOption) isPreauthOption()   {}

// WithCookieName sets the cookie name for the session cookie.
func WithCookieName(name string) CookieOption {
	return CookieOption(func(c *cookie.CookieClient) {
		c.CookieName = name
	})
}

// WithCookieDomain sets the domain for the session cookie.
func WithCookieDomain(domain string) CookieOption {
	return CookieOption(func(c *cookie.CookieClient) {
		c.Domain = domain
	})
}

// WithXSRFCookieName sets the cookie name for the XSRF cookie.
func WithXSRFCookieName(name string) CookieOption {
	return CookieOption(func(c *cookie.CookieClient) {
		c.STCookieName = name
	})
}

// WithXSRFHeaderName sets the header name for the XSRF header.
func WithXSRFHeaderName(name string) CookieOption {
	return CookieOption(func(c *cookie.CookieClient) {
		c.STHeaderName = name
	})
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
