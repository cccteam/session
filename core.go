package session

import (
	"context"
	"net/http"

	"github.com/cccteam/ccc"
	"github.com/cccteam/ccc/tracer"
	"github.com/cccteam/httpio"
	"github.com/cccteam/logger"
	"github.com/cccteam/session/cookie"
	"github.com/cccteam/session/internal/basesession"
	internalcookie "github.com/cccteam/session/internal/cookie"
	"github.com/cccteam/session/sessioninfo"
	"github.com/cccteam/session/sessionstorage"
	"github.com/go-playground/errors/v5"
)

// This file is the core every session type is built on: construction, session
// establishment, and the API methods the types share. Each type keeps its own fields
// (its storage and its *basesession.BaseSession) and builds what it needs from them on
// demand, so a type assembled field by field behaves exactly like a constructed one.

// newBaseSession assembles the BaseSession a session type runs on: the default log
// handler and session timeout over storage, the BaseSessionOptions among options applied
// to it, and a cookie client built from the CookieOptions among options. The cookie
// client is returned as well, for the OIDC authenticators that write their state cookie
// through it. Options of any other kind are left to the caller.
func newBaseSession[O any](storage sessionstorage.BaseStore, cookieKey string, options []O) (*basesession.BaseSession, *internalcookie.Client, error) {
	baseSession := &basesession.BaseSession{
		Handle:         httpio.Log,
		SessionTimeout: defaultSessionTimeout,
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

	cookieClient, err := internalcookie.NewCookieClient(cookieKey, cookieOpts...)
	if err != nil {
		return nil, nil, errors.Wrap(err, "cookie.NewCookieClient()")
	}
	baseSession.CookieHandler = cookieClient

	return baseSession, cookieClient, nil
}

// verifyCustomDataTypes checks at construction that the storage's custom session data
// and custom user data configurations were built for S and U.
func verifyCustomDataTypes[S, U any](storage sessionstorage.BaseStore) error {
	if err := verifyCustomDataType[S](storage); err != nil {
		return err
	}

	return verifyCustomUserDataType[U](storage)
}

// verifyOIDCStorage is the construction check every OIDC provider makes: the custom data
// configurations match S and U, and custom user data has the OIDC user anchor to hang
// from.
func verifyOIDCStorage[S, U any](storage sessionstorage.BaseStore) error {
	if err := verifyCustomDataTypes[S, U](storage); err != nil {
		return err
	}
	if storage.CustomUserDataType() != nil && !storage.OIDCUsersEnabled() {
		return errors.New("custom user data on OIDC storage requires the OIDC user anchor: pass sessionstorage.WithOIDCUsers() to the storage constructor")
	}

	return nil
}

// authCookieSameSite is how a new session's auth cookie is written.
type authCookieSameSite bool

const (
	// sameSiteStrict is for a session established by a same-site request: a login form,
	// an API call.
	sameSiteStrict authCookieSameSite = true
	// sameSiteNone is for a session established on an OIDC provider's callback, a
	// cross-site redirect that a Strict cookie would not survive. StartSession upgrades
	// it to Strict on the next request.
	sameSiteNone authCookieSameSite = false
)

// establishSession is how every session type creates a session outside impersonation:
// create inserts the session row, and only once it has succeeded are the auth cookie
// (written per sameSite) and the XSRF cookie for the new session ID written. An error
// from create is returned unchanged and leaves the response without cookies.
func establishSession(
	ctx context.Context, w http.ResponseWriter, base *basesession.BaseSession, sameSite authCookieSameSite, create func(ctx context.Context) (ccc.UUID, error),
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

// logSessionStarted records the association between a new session and its username on
// the request's log entry.
func logSessionStarted(ctx context.Context, username string, sessionID ccc.UUID) {
	logger.FromCtx(ctx).AddRequestAttribute("Username", username).AddRequestAttribute(string(internalcookie.SessionID), sessionID)
}

// userDataStore is the custom user data surface of the stores that have a user record.
type userDataStore interface {
	CustomUserData(ctx context.Context, userID ccc.UUID) (any, error)
	UpdateCustomUserData(ctx context.Context, userID ccc.UUID, mutate func(data any) error) error
}

// sharedAPI implements the API methods every session type's API offers alike. A type's
// API builds one per call from its own fields and delegates to it.
type sharedAPI[SessionData, UserData any] struct {
	base  *basesession.BaseSession
	store sessionstorage.BaseStore
	// users is the store's custom user data surface; nil for Preauth, which has none.
	users userDataStore
	// storeName names the store interface in wrapped errors, e.g. "PasswordAuthStore".
	storeName string
}

// validateSession checks the session cookie and, when it is valid, stores the session
// data in the context.
func (a sharedAPI[S, U]) validateSession(ctx context.Context) (context.Context, error) {
	ctx, err := a.base.ValidateSessionAPI(ctx)
	if err != nil {
		return ctx, errors.Wrap(err, "basesession.BaseSession.ValidateSessionAPI()")
	}

	return ctx, nil
}

// startSession restores the session from its cookie or initializes a new one.
func (a sharedAPI[S, U]) startSession(ctx context.Context, w http.ResponseWriter, r *http.Request) (context.Context, error) {
	ctx, err := a.base.StartSessionAPI(ctx, w, r)
	if err != nil {
		return ctx, errors.Wrap(err, "basesession.BaseSession.StartSessionAPI()")
	}

	return ctx, nil
}

// logout destroys the current session, announcing an impersonated session's end.
func (a sharedAPI[S, U]) logout(ctx context.Context) error {
	if err := a.base.LogoutAPI(ctx); err != nil {
		return errors.Wrap(err, "basesession.BaseSession.LogoutAPI()")
	}

	return nil
}

// cookie returns the underlying cookie.Client.
func (a sharedAPI[S, U]) cookie() *cookie.Client {
	return a.base.CookieHandler.Cookie()
}

// customData returns the current session's custom session data from the context; a
// session with no custom data row yields a zero-value S.
func (a sharedAPI[S, U]) customData(ctx context.Context) (S, error) {
	data, err := sessioninfo.CustomDataFromCtx[*S](ctx)
	if err != nil {
		var zero S

		return zero, errors.Wrap(err, "sessioninfo.CustomDataFromCtx()")
	}

	return *data, nil
}

// updateCustomSessionData is the typed transactional read-modify-write of an active
// session's custom session data.
func (a sharedAPI[S, U]) updateCustomSessionData(ctx context.Context, sessionID ccc.UUID, mutate func(data *S) error) error {
	ctx, span := tracer.Start(ctx)
	defer span.End()

	if err := a.store.UpdateCustomSessionData(ctx, sessionID, eraseMutate(mutate)); err != nil {
		return errors.Wrap(err, "sessionstorage."+a.storeName+".UpdateCustomSessionData()")
	}

	return nil
}

// customUserData returns an account's custom user data; a user with no custom data row
// yields a zero-value U.
func (a sharedAPI[S, U]) customUserData(ctx context.Context, userID ccc.UUID) (U, error) {
	ctx, span := tracer.Start(ctx)
	defer span.End()

	var zero U
	data, err := a.users.CustomUserData(ctx, userID)
	if err != nil {
		return zero, errors.Wrap(err, "sessionstorage."+a.storeName+".CustomUserData()")
	}
	typed, ok := data.(*U)
	if !ok {
		return zero, errors.Newf("custom user data type mismatch: storage decoded %T, session type expects %T", data, (*U)(nil))
	}

	return *typed, nil
}

// updateCustomUserData is the typed transactional read-modify-write of an account's
// custom user data.
func (a sharedAPI[S, U]) updateCustomUserData(ctx context.Context, userID ccc.UUID, mutate func(data *U) error) error {
	ctx, span := tracer.Start(ctx)
	defer span.End()

	if err := a.users.UpdateCustomUserData(ctx, userID, eraseMutate(mutate)); err != nil {
		return errors.Wrap(err, "sessionstorage."+a.storeName+".UpdateCustomUserData()")
	}

	return nil
}

// startImpersonatedSession establishes an impersonated session; resolve is the type's
// identity resolver (see identityResolver).
func (a sharedAPI[S, U]) startImpersonatedSession(
	ctx context.Context, w http.ResponseWriter, req *ImpersonationRequest, customData []*S, resolve identityResolver,
) (ccc.UUID, error) {
	return startImpersonatedSession(ctx, w, a.base, req, customData, resolve)
}

// destroyImpersonatedSessions expires every live impersonated session established by
// actor, ending their records Revoked.
func (a sharedAPI[S, U]) destroyImpersonatedSessions(ctx context.Context, actor string) error {
	if err := a.base.DestroyImpersonatedSessions(ctx, actor); err != nil {
		return errors.Wrap(err, "basesession.BaseSession.DestroyImpersonatedSessions()")
	}

	return nil
}

// activeImpersonations lists the impersonated sessions live right now, newest first.
func (a sharedAPI[S, U]) activeImpersonations(ctx context.Context, q *ImpersonationQuery) ([]*sessioninfo.Impersonation, error) {
	imps, err := a.base.ActiveImpersonations(ctx, q)
	if err != nil {
		return nil, errors.Wrap(err, "basesession.BaseSession.ActiveImpersonations()")
	}

	return imps, nil
}

// destroyImpersonatedSession ends one live impersonated session, Revoked.
func (a sharedAPI[S, U]) destroyImpersonatedSession(ctx context.Context, sessionID ccc.UUID) error {
	if err := a.base.DestroyImpersonatedSession(ctx, sessionID); err != nil {
		return errors.Wrap(err, "basesession.BaseSession.DestroyImpersonatedSession()")
	}

	return nil
}

// endImpersonation ends the impersonated session in ctx, Released, restoring a local
// actor's own session when it is still live.
func (a sharedAPI[S, U]) endImpersonation(ctx context.Context, w http.ResponseWriter) (restored bool, err error) {
	restored, err = a.base.EndImpersonationAPI(ctx, w)
	if err != nil {
		return false, errors.Wrap(err, "basesession.BaseSession.EndImpersonationAPI()")
	}

	return restored, nil
}
