package sessioncore

import (
	"context"
	"net/http"

	"github.com/cccteam/ccc"
	"github.com/cccteam/ccc/tracer"
	"github.com/cccteam/session/cookie"
	"github.com/cccteam/session/internal/basesession"
	"github.com/cccteam/session/sessioninfo"
	"github.com/cccteam/session/sessionstorage"
	"github.com/go-playground/errors/v5"
)

// UserDataStore is the custom user data surface of the stores that have a user record.
type UserDataStore interface {
	CustomUserData(ctx context.Context, userID ccc.UUID) (any, error)
	UpdateCustomUserData(ctx context.Context, userID ccc.UUID, mutate func(data any) error) error
}

// API implements the API methods every session type shares. A type's API builds one
// per call from its own fields and delegates to it.
type API[SessionData, UserData any] struct {
	Base  *basesession.BaseSession
	Store sessionstorage.BaseStore
	// Users is the store's custom user data surface. It is nil for Preauth.
	Users UserDataStore
	// StoreName names the store interface in wrapped errors, e.g. "PasswordAuthStore".
	StoreName string
}

// ValidateSession checks the session cookie and, when it is valid, stores the session
// data in the context.
func (a API[S, U]) ValidateSession(ctx context.Context) (context.Context, error) {
	ctx, err := a.Base.ValidateSessionAPI(ctx)
	if err != nil {
		return ctx, errors.Wrap(err, "basesession.BaseSession.ValidateSessionAPI()")
	}

	return ctx, nil
}

// StartSession restores the session from its cookie or initializes a new one.
func (a API[S, U]) StartSession(ctx context.Context, w http.ResponseWriter, r *http.Request) (context.Context, error) {
	ctx, err := a.Base.StartSessionAPI(ctx, w, r)
	if err != nil {
		return ctx, errors.Wrap(err, "basesession.BaseSession.StartSessionAPI()")
	}

	return ctx, nil
}

// Logout destroys the current session, announcing an impersonated session's end.
func (a API[S, U]) Logout(ctx context.Context) error {
	if err := a.Base.LogoutAPI(ctx); err != nil {
		return errors.Wrap(err, "basesession.BaseSession.LogoutAPI()")
	}

	return nil
}

// Cookie returns the underlying cookie.Client.
func (a API[S, U]) Cookie() *cookie.Client {
	return a.Base.CookieHandler.Cookie()
}

// CustomData returns the current session's custom session data from the context. A
// session with no custom data row yields a zero-value S.
func (a API[S, U]) CustomData(ctx context.Context) (S, error) {
	data, err := sessioninfo.CustomDataFromCtx[*S](ctx)
	if err != nil {
		var zero S

		return zero, errors.Wrap(err, "sessioninfo.CustomDataFromCtx()")
	}

	return *data, nil
}

// UpdateCustomSessionData is the typed transactional read-modify-write of an active
// session's custom session data.
func (a API[S, U]) UpdateCustomSessionData(ctx context.Context, sessionID ccc.UUID, mutate func(data *S) error) error {
	ctx, span := tracer.Start(ctx)
	defer span.End()

	if err := a.Store.UpdateCustomSessionData(ctx, sessionID, EraseMutate(mutate)); err != nil {
		return errors.Wrap(err, "sessionstorage."+a.StoreName+".UpdateCustomSessionData()")
	}

	return nil
}

// CustomUserData returns a user's custom user data. A user with no custom data row
// yields a zero-value U.
func (a API[S, U]) CustomUserData(ctx context.Context, userID ccc.UUID) (U, error) {
	ctx, span := tracer.Start(ctx)
	defer span.End()

	var zero U
	data, err := a.Users.CustomUserData(ctx, userID)
	if err != nil {
		return zero, errors.Wrap(err, "sessionstorage."+a.StoreName+".CustomUserData()")
	}
	typed, ok := data.(*U)
	if !ok {
		return zero, errors.Newf("custom user data type mismatch: storage decoded %T, session type expects %T", data, (*U)(nil))
	}

	return *typed, nil
}

// UpdateCustomUserData is the typed transactional read-modify-write of a user's
// custom user data.
func (a API[S, U]) UpdateCustomUserData(ctx context.Context, userID ccc.UUID, mutate func(data *U) error) error {
	ctx, span := tracer.Start(ctx)
	defer span.End()

	if err := a.Users.UpdateCustomUserData(ctx, userID, EraseMutate(mutate)); err != nil {
		return errors.Wrap(err, "sessionstorage."+a.StoreName+".UpdateCustomUserData()")
	}

	return nil
}

// StartImpersonatedSession establishes an impersonated session. resolve is the type's
// identity resolver.
func (a API[S, U]) StartImpersonatedSession(
	ctx context.Context, w http.ResponseWriter, req *ImpersonationRequest, customData []*S, resolve IdentityResolver,
) (ccc.UUID, error) {
	return StartImpersonatedSession(ctx, w, a.Base, req, customData, resolve)
}

// DestroyImpersonatedSessions expires every live impersonated session established by
// actor, ending their records Revoked.
func (a API[S, U]) DestroyImpersonatedSessions(ctx context.Context, actor string) error {
	if err := a.Base.DestroyImpersonatedSessions(ctx, actor); err != nil {
		return errors.Wrap(err, "basesession.BaseSession.DestroyImpersonatedSessions()")
	}

	return nil
}

// ActiveImpersonations lists the impersonated sessions live right now, newest first.
func (a API[S, U]) ActiveImpersonations(ctx context.Context, q *sessioninfo.ImpersonationQuery) ([]*sessioninfo.Impersonation, error) {
	imps, err := a.Base.ActiveImpersonations(ctx, q)
	if err != nil {
		return nil, errors.Wrap(err, "basesession.BaseSession.ActiveImpersonations()")
	}

	return imps, nil
}

// DestroyImpersonatedSession ends one live impersonated session, Revoked.
func (a API[S, U]) DestroyImpersonatedSession(ctx context.Context, sessionID ccc.UUID) error {
	if err := a.Base.DestroyImpersonatedSession(ctx, sessionID); err != nil {
		return errors.Wrap(err, "basesession.BaseSession.DestroyImpersonatedSession()")
	}

	return nil
}

// EndImpersonation ends the impersonated session in ctx, Released, restoring a local
// actor's own session when it is still live.
func (a API[S, U]) EndImpersonation(ctx context.Context, w http.ResponseWriter) (restored bool, err error) {
	restored, err = a.Base.EndImpersonationAPI(ctx, w)
	if err != nil {
		return false, errors.Wrap(err, "basesession.BaseSession.EndImpersonationAPI()")
	}

	return restored, nil
}
