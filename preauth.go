package session

import (
	"context"
	"net/http"

	"github.com/cccteam/ccc"
	"github.com/cccteam/ccc/tracer"
	"github.com/cccteam/session/cookie"
	"github.com/cccteam/session/internal/basesession"
	"github.com/cccteam/session/sessionstorage"
	"github.com/go-playground/errors/v5"
)

// PreauthOption defines the functional option type for configuring PreauthSession.
type PreauthOption interface {
	isPreauthOption()
}

var _ PreauthHandlers = &Preauth[NoCustomData]{}

// Preauth handles session management for pre-authentication scenarios, with custom
// session data typed as SessionData (caller-supplied at Login); use NoCustomData when
// custom session data is not used. Preauth is trust-the-caller with no user record, so
// it has no custom user data axis — durable per-user data needs a user anchor
// (password auth's SessionUsers, or the OIDC user anchor).
type Preauth[SessionData any] struct {
	storage     sessionstorage.PreauthStore
	baseSession *basesession.BaseSession
}

// NewPreauth creates a new Preauth for the custom session data struct type SessionData
// (use NoCustomData when custom session data is not used). The storage must carry a
// custom session data configuration built for the same SessionData; a mismatch is a
// construction error, as is any custom user data configuration — Preauth has no user
// record to anchor durable data to. Preauth custom session data is caller-supplied at
// Login (trust-the-caller); there is no resolver input source.
// cookieKey: A Base64-encoded string representing at least 32 bytes
// of cryptographically secure random data.
func NewPreauth[SessionData any](storage sessionstorage.PreauthStore, cookieKey string, options ...PreauthOption) (*Preauth[SessionData], error) {
	if err := verifyCustomDataType[SessionData](storage); err != nil {
		return nil, err
	}
	if storage.CustomUserDataType() != nil {
		return nil, errors.New("custom user data is not supported for Preauth: there is no user record to anchor it to")
	}
	if storage.OIDCUsersEnabled() {
		return nil, errors.New("the OIDC user anchor (WithOIDCUsers) is OIDC-only")
	}

	baseSession, _, err := newBaseSession(storage, cookieKey, options)
	if err != nil {
		return nil, err
	}

	return &Preauth[SessionData]{
		baseSession: baseSession,
		storage:     storage,
	}, nil
}

// NewSession creates a new session for a pre-authenticated user.
//
// Deprecated: Use p.API().Login() instead
func (p *Preauth[T]) NewSession(ctx context.Context, w http.ResponseWriter, _ *http.Request, username string) (ccc.UUID, error) {
	return p.API().Login(ctx, w, username)
}

// Authenticated is the handler reports if the session is authenticated
func (p *Preauth[T]) Authenticated() http.HandlerFunc {
	return p.baseSession.Authenticated()
}

// Logout destroys the current session
func (p *Preauth[T]) Logout() http.HandlerFunc {
	return p.baseSession.Logout()
}

// SetXSRFToken sets the XSRF Token
func (p *Preauth[T]) SetXSRFToken(next http.Handler) http.Handler {
	return p.baseSession.SetXSRFToken(next)
}

// StartSession initializes a session by restoring it from a cookie, or if that fails, initializing
// a new session. The session cookie is then updated and the sessionID is inserted into the context.
func (p *Preauth[T]) StartSession(next http.Handler) http.Handler {
	return p.baseSession.StartSession(next)
}

// ValidateSession checks the sessionID in the database to validate that it has not expired and
// updates the last activity timestamp if it is still valid. StartSession handler must be called
// before calling ValidateSession
func (p *Preauth[T]) ValidateSession(next http.Handler) http.Handler {
	return p.baseSession.ValidateSession(next)
}

// ValidateXSRFToken validates the XSRF Token
func (p *Preauth[T]) ValidateXSRFToken(next http.Handler) http.Handler {
	return p.baseSession.ValidateXSRFToken(next)
}

// EnforceReadOnlyMask refuses non-safe requests from a read-only impersonated session
// with 403 Forbidden, evidenced as a WriteBlocked event; every other request passes.
// Place it after ValidateSession. See the "Impersonated sessions" section of the README.
func (p *Preauth[T]) EnforceReadOnlyMask(next http.Handler) http.Handler {
	return p.baseSession.EnforceReadOnlyMask(next)
}

// EndImpersonation ends the impersonated session (record ended Released) and, for a
// local actor whose own session is still live, returns the browser to that session; the
// body's restored flag says whether it did. Route it inside the validated group. See the
// "Impersonated sessions" section of the README.
func (p *Preauth[T]) EndImpersonation() http.HandlerFunc {
	return p.baseSession.EndImpersonation()
}

// API provides programatic access to Preauth handler internals
func (p *Preauth[T]) API() *PreauthAPI[T] {
	return newPreauthAPI(p)
}

// PreauthAPI provides programatic access to Preauth handler internals
type PreauthAPI[SessionData any] struct {
	preauth *Preauth[SessionData]
}

func newPreauthAPI[T any](preauth *Preauth[T]) *PreauthAPI[T] {
	return &PreauthAPI[T]{
		preauth: preauth,
	}
}

// shared returns the API methods every session type shares, over this session's fields.
// Preauth has no user record, so its custom user data surface is left nil.
func (p *PreauthAPI[T]) shared() sharedAPI[T, NoCustomData] {
	return sharedAPI[T, NoCustomData]{base: p.preauth.baseSession, store: p.preauth.storage, storeName: "PreauthStore"}
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
func (p *PreauthAPI[T]) Login(ctx context.Context, w http.ResponseWriter, username string, customData ...*T) (ccc.UUID, error) {
	ctx, span := tracer.Start(ctx)
	defer span.End()

	if len(customData) > 1 {
		return ccc.NilUUID, errors.New("at most one customData value may be provided; it is the complete custom session data row")
	}
	var data any
	if len(customData) == 1 && customData[0] != nil {
		data = customData[0]
	}

	sessionID, err := establishSession(ctx, w, p.preauth.baseSession, sameSiteStrict, func(ctx context.Context) (ccc.UUID, error) {
		id, err := p.preauth.storage.NewSession(ctx, username, data)
		if err != nil {
			return ccc.NilUUID, errors.Wrap(err, "sessionstorage.PreauthStore.NewSession()")
		}

		return id, nil
	})
	if err != nil {
		return ccc.NilUUID, err
	}

	logSessionStarted(ctx, username, sessionID)

	return sessionID, nil
}

// UpdateCustomSessionData updates the custom session data for an active session via a
// transactional read-modify-write: mutate receives the current row (zero-value T when
// no row exists), and the full row is written back; a mutate error aborts with nothing
// written. It is intended for genuine mid-session updates only — initial population
// belongs in the creation path (caller-supplied data on Login), which is atomic with
// the session insert. See the "Custom session data" section of the README for the full
// lifecycle.
func (p *PreauthAPI[T]) UpdateCustomSessionData(ctx context.Context, sessionID ccc.UUID, mutate func(data *T) error) error {
	return p.shared().updateCustomSessionData(ctx, sessionID, mutate)
}

// CustomData returns the strongly typed custom session data for the current session
// from the context. A session with no custom data row yields a zero-value T.
func (p *PreauthAPI[T]) CustomData(ctx context.Context) (T, error) {
	return p.shared().customData(ctx)
}

// Logout destroys the current session. For an impersonated session the end is
// announced as an Ended event, as on every other session type.
func (p *PreauthAPI[T]) Logout(ctx context.Context) error {
	return p.shared().logout(ctx)
}

// StartSession initializes a session by restoring it from a cookie, or if
// that fails, initializing a new session. The session cookie is then updated and
// the sessionID is inserted into the context.
func (p *PreauthAPI[T]) StartSession(ctx context.Context, w http.ResponseWriter, r *http.Request) (context.Context, error) {
	return p.shared().startSession(ctx, w, r)
}

// ValidateSession checks the sessionID in the database to validate that it has not expired
// and updates the last activity timestamp if it is still valid.
// StartSession handler must be called before calling ValidateSession
func (p *PreauthAPI[T]) ValidateSession(ctx context.Context) (context.Context, error) {
	return p.shared().validateSession(ctx)
}

// DestroyAllUserSessions destroys all sessions for a given user
func (p *PreauthAPI[T]) DestroyAllUserSessions(ctx context.Context, username string) error {
	if err := p.preauth.storage.DestroyAllUserSessions(ctx, username); err != nil {
		return errors.Wrap(err, "sessionstorage.PreauthStore.DestroyAllUserSessions()")
	}

	return nil
}

// Cookie returns the underlying cookie.Client
func (p *PreauthAPI[T]) Cookie() *cookie.Client {
	return p.shared().cookie()
}
