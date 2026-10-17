// Package sessioncore is what the session types are built from: the base session over
// the storage and the cookie client, the options every session type takes, session
// establishment, the API methods every session type shares, impersonation
// establishment and its guards, the custom data type checks, the password comparison
// and the login refusal redirect. The root package and the legacy package both build
// on it, so neither has to export it.
package sessioncore

import (
	"context"
	"fmt"
	"net/http"
	"net/url"
	"time"

	"github.com/cccteam/ccc"
	"github.com/cccteam/ccc/securehash"
	"github.com/cccteam/httpio"
	"github.com/cccteam/logger"
	"github.com/cccteam/session/internal/basesession"
	internalcookie "github.com/cccteam/session/internal/cookie"
	"github.com/cccteam/session/sessioninfo"
	"github.com/cccteam/session/sessionstorage"
	"github.com/go-playground/errors/v5"
)

// DefaultSessionTimeout is the idle session timeout unless WithSessionTimeout sets one.
const DefaultSessionTimeout = 10 * time.Minute

// NewBaseSession builds the BaseSession a session type runs on, applying the
// BaseSessionOptions and CookieOptions among options. Other options are left to the
// caller. The cookie client is also returned, for the OIDC authenticators that write
// their state cookie through it.
func NewBaseSession[O any](storage sessionstorage.BaseStore, cookieKey string, options []O) (*basesession.BaseSession, *internalcookie.Client, error) {
	baseSession := &basesession.BaseSession{
		Handle:         httpio.Log,
		SessionTimeout: DefaultSessionTimeout,
		Storage:        storage,
	}

	var cookieOpts []internalcookie.Option
	for _, opt := range options {
		switch o := any(opt).(type) {
		case CookieOption:
			cookieOpts = append(cookieOpts, internalcookie.Option(o))
		case BaseSessionOption:
			o(baseSession)
		}
	}
	// The table-name options are applied here, through the store's setters, so a name
	// that is not an identifier is refused under its option's name before any SQL.
	for _, table := range baseSession.TableNames {
		if err := table.Set(table.Name); err != nil {
			return nil, nil, errors.Wrapf(err, "%s()", table.Option)
		}
	}

	cookieClient, err := internalcookie.NewCookieClient(cookieKey, cookieOpts...)
	if err != nil {
		return nil, nil, errors.Wrap(err, "cookie.NewCookieClient()")
	}
	baseSession.CookieHandler = cookieClient

	return baseSession, cookieClient, nil
}

// SameSite is how a new session's auth cookie is written.
type SameSite bool

const (
	// SameSiteStrict is for a session established by a same-site request, such as a
	// login form or an API call.
	SameSiteStrict SameSite = true
	// SameSiteNone is for a session established on a provider's callback. That is a
	// cross-site redirect, which a Strict cookie would not survive. StartSession
	// upgrades it to Strict on the next request.
	SameSiteNone SameSite = false
)

// EstablishSession creates a session for every session type outside impersonation.
// create inserts the session row. The auth and XSRF cookies for the new session ID are
// written only after it succeeds. An error from create is returned unchanged, and no
// cookie is written.
func EstablishSession(
	ctx context.Context, w http.ResponseWriter, base *basesession.BaseSession, sameSite SameSite, create func(ctx context.Context) (ccc.UUID, error),
) (ccc.UUID, error) {
	id, err := create(ctx)
	if err != nil {
		return ccc.NilUUID, err
	}

	base.CookieHandler.NewAuthCookie(w, bool(sameSite), id)

	// write new XSRF Token Cookie to match the new SessionID
	base.CookieHandler.CreateXSRFTokenCookie(w, id)

	return id, nil
}

// LogSessionStarted adds a new session's ID and username to the request's log entry.
func LogSessionStarted(ctx context.Context, username string, sessionID ccc.UUID) {
	logger.FromCtx(ctx).AddRequestAttribute("Username", username).AddRequestAttribute(string(internalcookie.SessionID), sessionID)
}

// RedirectRefusedLogin returns the browser to the login page with the reason as a code:
// loginURL?code=<code>, the code read from err by sessioninfo.LoginRefusalCodeOf. The
// code is all the URL carries; the error itself goes to the log through the handler's
// return. See the "Login refusal codes" section of the README.
func RedirectRefusedLogin(w http.ResponseWriter, _ *http.Request, loginURL string, err error) {
	code := sessioninfo.LoginRefusalCodeOf(err)
	// The login URL is configuration and the code is query-escaped, so the result is
	// written as is, never cleaned.
	internalcookie.WriteRedirect(w, fmt.Sprintf("%s?code=%s", loginURL, url.QueryEscape(string(code))), http.StatusFound)
}

// ErrNoPassword is the comparison failure for a user with no password hash, such as one
// provisioned for external sign-in only.
var ErrNoPassword = errors.New("the user has no password")

// ComparePassword checks password against hash with hasher, reporting whether the hash
// should be upgraded. A nil hash (a user without a password) fails like a wrong
// password, so the hasher, which dereferences the hash, never sees nil.
func ComparePassword(hasher *securehash.SecureHasher, hash *securehash.Hash, password string) (upgrade bool, err error) {
	if hash == nil {
		return false, ErrNoPassword
	}

	upgrade, err = hasher.Compare(hash, password)
	if err != nil {
		return false, errors.Wrap(err, "securehash.SecureHasher.Compare()")
	}

	return upgrade, nil
}

// NewDecoder builds the decoder for a handler's request body. Construction fails only
// for a malformed request struct, a programming error, so it panics at startup.
func NewDecoder[T any]() *httpio.StructDecoder[T] {
	decoder, err := httpio.NewStructDecoder[T]()
	if err != nil {
		panic(err)
	}

	return decoder
}
