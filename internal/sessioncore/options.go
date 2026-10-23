package sessioncore

import (
	"time"

	"github.com/cccteam/ccc/securehash"
	"github.com/cccteam/session/internal/basesession"
	internalcookie "github.com/cccteam/session/internal/cookie"
	"github.com/cccteam/session/internal/dbtype"
)

// The option interfaces of the session types. Each is sealed by an unexported marker
// method, so only the option types below satisfy them; the root package aliases them
// and builds its options from these types.
type (
	// AuthOption configures an Auth session.
	AuthOption interface{ isAuthOption() }
	// PreauthOption configures a Preauth session.
	PreauthOption interface{ isPreauthOption() }
	// PasswordOption configures the password method and the legacy PasswordAuth.
	PasswordOption interface{ isPasswordOption() }
	// OIDCAzureOption configures the legacy OIDCAzure.
	OIDCAzureOption interface{ isOIDCAzureOption() }
)

// AuthOptionMarker makes the type that embeds it an AuthOption: the root package's own
// Auth settings option embeds it.
type AuthOptionMarker struct{}

func (AuthOptionMarker) isAuthOption() {}

// CookieOption is a cookie client option. It configures every session type.
type CookieOption internalcookie.Option

func (CookieOption) isAuthOption()      {}
func (CookieOption) isPreauthOption()   {}
func (CookieOption) isPasswordOption()  {}
func (CookieOption) isOIDCAzureOption() {}

// BaseSessionOption configures the base session. It configures every session type.
type BaseSessionOption func(*basesession.BaseSession)

func (BaseSessionOption) isAuthOption()      {}
func (BaseSessionOption) isPreauthOption()   {}
func (BaseSessionOption) isPasswordOption()  {}
func (BaseSessionOption) isOIDCAzureOption() {}

// LoginURLSetter is the surface OIDCOption operates on; the legacy OIDC
// authenticator implements it.
type LoginURLSetter interface {
	SetLoginURL(string)
}

// OIDCOption configures the legacy OIDCAzure's authenticator.
type OIDCOption func(LoginURLSetter)

func (OIDCOption) isOIDCAzureOption() {}

// WithLoginURL sets where the legacy OIDCAzure sends a refused login. (default: /login)
func WithLoginURL(l string) OIDCOption {
	return func(b LoginURLSetter) {
		b.SetLoginURL(l)
	}
}

// PasswordSettings are the password method's settings: how passwords are hashed,
// whether a hash made with an older algorithm is upgraded at login, and the attempt
// limit failed attempts are held to.
type PasswordSettings struct {
	Hasher      *securehash.SecureHasher
	AutoUpgrade bool
	Attempts    dbtype.SignInAttemptLimit
	// UsernameIsEmail says the username is the user's email address: the users table
	// derives the address from the username, a rename is refused, and a verified
	// address is written as the username.
	UsernameIsEmail bool
	// OpenSignUp says anyone may create an account by giving an address and following
	// the link mailed to it.
	OpenSignUp bool
}

// DefaultAttemptLimit is the attempt limit before any option: five failed attempts on
// a name within fifteen minutes lock the name for fifteen minutes.
var DefaultAttemptLimit = dbtype.SignInAttemptLimit{Failures: 5, Window: 15 * time.Minute, Lock: 15 * time.Minute}

// DefaultPasswordSettings returns the settings before any option: Argon2, upgrading,
// the default attempt limit.
func DefaultPasswordSettings() PasswordSettings {
	return PasswordSettings{Hasher: securehash.New(securehash.Argon2()), AutoUpgrade: true, Attempts: DefaultAttemptLimit}
}

// Apply applies opt when it is a password settings option and reports whether it was
// one; a cookie or base session option is not, and is left to the caller.
func (s *PasswordSettings) Apply(opt PasswordOption) bool {
	o, ok := opt.(passwordOption)
	if ok {
		o(s)
	}

	return ok
}

// passwordOption is a password settings option. It operates on the non-generic
// settings struct so one option applies to every instantiation.
type passwordOption func(*PasswordSettings)

func (passwordOption) isPasswordOption() {}

// AutoUpgradeHashes controls whether password hashes are upgraded at login. (default: true)
func AutoUpgradeHashes(a bool) PasswordOption {
	return passwordOption(func(s *PasswordSettings) {
		s.AutoUpgrade = a
	})
}

// HashAlgorithm controls the hashing algorithm. (default: securehash.Argon2())
func HashAlgorithm(hasher securehash.HashAlgorithm) PasswordOption {
	return passwordOption(func(s *PasswordSettings) {
		s.Hasher = securehash.New(hasher)
	})
}

// AttemptLimit sets the attempt limit: failures failed attempts on a name within
// window lock the name for lock. (default: DefaultAttemptLimit)
func AttemptLimit(failures int, window, lock time.Duration) PasswordOption {
	return passwordOption(func(s *PasswordSettings) {
		s.Attempts = dbtype.SignInAttemptLimit{Failures: failures, Window: window, Lock: lock}
	})
}

// UsernameIsEmail declares that the username is the user's email address. (default: the
// two are apart)
func UsernameIsEmail() PasswordOption {
	return passwordOption(func(s *PasswordSettings) {
		s.UsernameIsEmail = true
	})
}

// OpenSignUp declares that anyone may create an account by giving an address and
// following the link mailed to it. (default: accounts are created by an operator or
// through an invitation)
func OpenSignUp() PasswordOption {
	return passwordOption(func(s *PasswordSettings) {
		s.OpenSignUp = true
	})
}
