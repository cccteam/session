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

// PreauthOption defines the functional option type for configuring PreauthSession.
type PreauthOption interface {
	isPreauthOption()
}

var _ PreauthHandlers = &Preauth{}

// Preauth is a TypedPreauth without custom session data. It preserves the pre-generics
// API surface; use NewTypedPreauth for typed custom session data.
type Preauth = TypedPreauth[NoCustomData]

// PreauthAPI is a TypedPreauthAPI without custom session data.
type PreauthAPI = TypedPreauthAPI[NoCustomData]

// TypedPreauth handles session management for pre-authentication scenarios, with
// custom session data typed as T (caller-supplied at Login).
type TypedPreauth[T any] struct {
	storage     sessionstorage.PreauthStore
	baseSession *basesession.BaseSession
}

// NewPreauth creates a new PreauthSession instance.
// cookieKey: A Base64-encoded string representing at least 32 bytes
// of cryptographically secure random data.
func NewPreauth(storage sessionstorage.PreauthStore, cookieKey string, options ...PreauthOption) (*Preauth, error) {
	return NewTypedPreauth[NoCustomData](storage, cookieKey, options...)
}

// NewTypedPreauth creates a new TypedPreauth for the custom session data struct type T.
// The storage must carry a custom session data configuration built for the same T; a
// mismatch is a construction error. Preauth custom session data is caller-supplied at
// Login (trust-the-caller); there is no resolver input source.
// cookieKey: A Base64-encoded string representing at least 32 bytes
// of cryptographically secure random data.
func NewTypedPreauth[T any](storage sessionstorage.PreauthStore, cookieKey string, options ...PreauthOption) (*TypedPreauth[T], error) {
	if err := verifyCustomDataType[T](storage); err != nil {
		return nil, err
	}

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
		return nil, errors.Wrap(err, "cookie.NewCookieClient()")
	}
	baseSession.CookieHandler = cookieClient

	return &TypedPreauth[T]{
		baseSession: baseSession,
		storage:     storage,
	}, nil
}

// NewSession creates a new session for a pre-authenticated user.
//
// Deprecated: Use p.API().Login() instead
func (p *TypedPreauth[T]) NewSession(ctx context.Context, w http.ResponseWriter, _ *http.Request, username string) (ccc.UUID, error) {
	return p.API().Login(ctx, w, username)
}

// Authenticated is the handler reports if the session is authenticated
func (p *TypedPreauth[T]) Authenticated() http.HandlerFunc {
	return p.baseSession.Authenticated()
}

// Logout destroys the current session
func (p *TypedPreauth[T]) Logout() http.HandlerFunc {
	return p.baseSession.Logout()
}

// SetXSRFToken sets the XSRF Token
func (p *TypedPreauth[T]) SetXSRFToken(next http.Handler) http.Handler {
	return p.baseSession.SetXSRFToken(next)
}

// StartSession initializes a session by restoring it from a cookie, or if that fails, initializing
// a new session. The session cookie is then updated and the sessionID is inserted into the context.
func (p *TypedPreauth[T]) StartSession(next http.Handler) http.Handler {
	return p.baseSession.StartSession(next)
}

// ValidateSession checks the sessionID in the database to validate that it has not expired and
// updates the last activity timestamp if it is still valid. StartSession handler must be called
// before calling ValidateSession
func (p *TypedPreauth[T]) ValidateSession(next http.Handler) http.Handler {
	return p.baseSession.ValidateSession(next)
}

// ValidateXSRFToken validates the XSRF Token
func (p *TypedPreauth[T]) ValidateXSRFToken(next http.Handler) http.Handler {
	return p.baseSession.ValidateXSRFToken(next)
}

// API provides programatic access to Preauth handler internals
func (p *TypedPreauth[T]) API() *TypedPreauthAPI[T] {
	return newPreauthAPI(p)
}

// TypedPreauthAPI provides programatic access to TypedPreauth handler internals
type TypedPreauthAPI[T any] struct {
	preauth *TypedPreauth[T]
}

func newPreauthAPI[T any](preauth *TypedPreauth[T]) *TypedPreauthAPI[T] {
	return &TypedPreauthAPI[T]{
		preauth: preauth,
	}
}

// Login creates a new session for a pre-authenticated user.
//
// Preauth is trust-the-caller: no user record is required or consulted, which makes it
// the right tool for stepping-stone sessions (e.g. MFA-pending) where identity is not
// yet fully established. For a full session backed by an existing user record after
// external authentication, use PasswordAuth's StartAuthenticatedSession instead.
//
// Optional customData (at most one *T) is written atomically with the session insert —
// the session and its custom data row land together or not at all. The library does not
// validate the data beyond the custom session data configuration, which must be
// attached to the storage for customData to be accepted. See the "Custom session data"
// section of the README for the full lifecycle.
func (p *TypedPreauthAPI[T]) Login(ctx context.Context, w http.ResponseWriter, username string, customData ...*T) (ccc.UUID, error) {
	ctx, span := tracer.Start(ctx)
	defer span.End()

	if len(customData) > 1 {
		return ccc.NilUUID, errors.New("at most one customData value may be provided; it is the complete custom session data row")
	}
	var data any
	if len(customData) == 1 && customData[0] != nil {
		data = customData[0]
	}

	// Create new Session in database
	sessionID, err := p.preauth.storage.NewSession(ctx, username, data)
	if err != nil {
		return ccc.NilUUID, errors.Wrap(err, "sessionstorage.PreauthStore.NewSession()")
	}

	// Write new Auth Cookie
	p.preauth.baseSession.CookieHandler.NewAuthCookie(w, true, sessionID)

	// Write new XSRF Token Cookie to match the new SessionID
	p.preauth.baseSession.CookieHandler.CreateXSRFTokenCookie(w, sessionID)

	// Log the association between the sessionID and Username
	logger.FromCtx(ctx).AddRequestAttribute("Username", username).AddRequestAttribute(string(internalcookie.SessionID), sessionID)

	return sessionID, nil
}

// UpdateCustomSessionData updates the custom session data for an active session via a
// transactional read-modify-write: mutate receives the current row (zero-value T when
// no row exists), and the full row is written back; a mutate error aborts with nothing
// written. It is intended for genuine mid-session updates only — initial population
// belongs in the creation path (caller-supplied data on Login), which is atomic with
// the session insert. See the "Custom session data" section of the README for the full
// lifecycle.
func (p *TypedPreauthAPI[T]) UpdateCustomSessionData(ctx context.Context, sessionID ccc.UUID, mutate func(data *T) error) error {
	ctx, span := tracer.Start(ctx)
	defer span.End()

	if err := p.preauth.storage.UpdateCustomSessionData(ctx, sessionID, eraseMutate(mutate)); err != nil {
		return errors.Wrap(err, "sessionstorage.PreauthStore.UpdateCustomSessionData()")
	}

	return nil
}

// CustomData returns the strongly typed custom session data for the current session
// from the context. A session with no custom data row yields a zero-value T.
func (p *TypedPreauthAPI[T]) CustomData(ctx context.Context) (T, error) {
	data, err := sessioninfo.CustomDataFromCtx[*T](ctx)
	if err != nil {
		var zero T

		return zero, errors.Wrap(err, "sessioninfo.CustomDataFromCtx()")
	}

	return *data, nil
}

// Logout destroys the current session
func (p *TypedPreauthAPI[T]) Logout(ctx context.Context) error {
	// Destroy session in database
	if err := p.preauth.baseSession.Storage.DestroySession(ctx, sessioninfo.IDFromCtx(ctx)); err != nil {
		return errors.Wrap(err, "sessionstorage.BaseStore.DestroySession()")
	}

	return nil
}

// StartSession initializes a session by restoring it from a cookie, or if
// that fails, initializing a new session. The session cookie is then updated and
// the sessionID is inserted into the context.
func (p *TypedPreauthAPI[T]) StartSession(ctx context.Context, w http.ResponseWriter, r *http.Request) (context.Context, error) {
	ctx, err := p.preauth.baseSession.StartSessionAPI(ctx, w, r)
	if err != nil {
		return ctx, errors.Wrap(err, "basesession.BaseSession.StartSessionAPI()")
	}

	return ctx, nil
}

// ValidateSession checks the sessionID in the database to validate that it has not expired
// and updates the last activity timestamp if it is still valid.
// StartSession handler must be called before calling ValidateSession
func (p *TypedPreauthAPI[T]) ValidateSession(ctx context.Context) (context.Context, error) {
	ctx, err := p.preauth.baseSession.ValidateSessionAPI(ctx)
	if err != nil {
		return ctx, errors.Wrap(err, "basesession.BaseSession.ValidateSessionAPI()")
	}

	return ctx, nil
}

// DestroyAllUserSessions destroys all sessions for a given user
func (p *TypedPreauthAPI[T]) DestroyAllUserSessions(ctx context.Context, username string) error {
	if err := p.preauth.storage.DestroyAllUserSessions(ctx, username); err != nil {
		return errors.Wrap(err, "sessionstorage.PreauthStore.DestroyAllUserSessions()")
	}

	return nil
}

// Cookie returns the underlying cookie.Client
func (p *TypedPreauthAPI[T]) Cookie() *cookie.Client {
	return p.preauth.baseSession.CookieHandler.Cookie()
}
