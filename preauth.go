package session

import (
	"context"
	"net/http"

	"github.com/cccteam/ccc"
	"github.com/cccteam/httpio"
	"github.com/cccteam/session/internal/basesession"
	"github.com/cccteam/session/internal/cookie"
	"github.com/cccteam/session/internal/types"
	"github.com/cccteam/session/sessioninfo"
	"github.com/cccteam/session/sessionstorage"
	"github.com/go-playground/errors/v5"
	"github.com/gorilla/securecookie"
)

// PreauthOption defines the functional option type for configuring PreauthSession.
type PreauthOption interface {
	isPreauthOption()
}

var _ PreauthHandlers = &Preauth{}

// Preauth handles session management for pre-authentication scenarios.
type Preauth struct {
	storage     sessionstorage.PreauthStore
	baseSession *basesession.BaseSession
}

// NewPreauth creates a new PreauthSession instance.
func NewPreauth(storage sessionstorage.PreauthStore, secureCookie *securecookie.SecureCookie, options ...PreauthOption) *Preauth {
	cookieClient := cookie.NewCookieClient(secureCookie)
	baseSession := &basesession.BaseSession{
		Handle:         httpio.Log,
		CookieHandler:  cookieClient,
		SessionTimeout: defaultSessionTimeout,
		Storage:        storage,
	}

	for _, opt := range options {
		switch o := any(opt).(type) {
		case CookieOption:
			o(cookieClient)
		case BaseSessionOption:
			o(baseSession)
		}
	}

	return &Preauth{
		baseSession: baseSession,
		storage:     storage,
	}
}

// NewSession creates a new session for a pre-authenticated user.
func (p *Preauth) NewSession(ctx context.Context, w http.ResponseWriter, r *http.Request, username string) (ccc.UUID, error) {
	ctx, span := ccc.StartTrace(ctx)
	defer span.End()

	// Create new Session in database
	id, err := p.storage.NewSession(ctx, username)
	if err != nil {
		return ccc.NilUUID, errors.Wrap(err, "PreauthSessionStorage.NewSession()")
	}

	// Write new Auth Cookie
	if _, err := p.baseSession.NewAuthCookie(w, true, id); err != nil {
		return ccc.NilUUID, errors.Wrap(err, "PreauthSession.NewAuthCookie()")
	}

	// Write new XSRF Token Cookie to match the new SessionID
	p.baseSession.SetXSRFTokenCookie(w, r, id, types.XSRFCookieLife)

	return id, nil
}

// Authenticated is the handler reports if the session is authenticated
func (p *Preauth) Authenticated() http.HandlerFunc {
	return p.baseSession.Authenticated()
}

// Logout destroys the current session
func (p *Preauth) Logout() http.HandlerFunc {
	return p.baseSession.Logout()
}

// SetXSRFToken sets the XSRF Token
func (p *Preauth) SetXSRFToken(next http.Handler) http.Handler {
	return p.baseSession.SetXSRFToken(next)
}

// StartSession initializes a session by restoring it from a cookie, or if that fails, initializing
// a new session. The session cookie is then updated and the sessionID is inserted into the context.
func (p *Preauth) StartSession(next http.Handler) http.Handler {
	return p.baseSession.StartSession(next)
}

// ValidateSession checks the sessionID in the database to validate that it has not expired and
// updates the last activity timestamp if it is still valid. StartSession handler must be called
// before calling ValidateSession
func (p *Preauth) ValidateSession(next http.Handler) http.Handler {
	return p.baseSession.ValidateSession(next)
}

// ValidateXSRFToken validates the XSRF Token
func (p *Preauth) ValidateXSRFToken(next http.Handler) http.Handler {
	return p.baseSession.ValidateXSRFToken(next)
}

// API provides programatic access to Preauth handler internals
func (p *Preauth) API() *PreauthAPI {
	return newPreauthAPI(p)
}

// PreauthAPI provides programatic access to Preauth handler internals
type PreauthAPI struct {
	preauth *Preauth
}

func newPreauthAPI(preauth *Preauth) *PreauthAPI {
	return &PreauthAPI{
		preauth: preauth,
	}
}

// Logout destroys the current session
func (p *PreauthAPI) Logout(ctx context.Context) error {
	// Destroy session in database
	if err := p.preauth.baseSession.Storage.DestroySession(ctx, sessioninfo.IDFromCtx(ctx)); err != nil {
		return errors.Wrap(err, "PreauthSession.DestroySession()")
	}

	return nil
}

// StartSession initializes a session by restoring it from a cookie, or if
// that fails, initializing a new session. The session cookie is then updated and
// the sessionID is inserted into the context.
func (p *PreauthAPI) StartSession(ctx context.Context, w http.ResponseWriter, r *http.Request) (context.Context, error) {
	ctx, err := p.preauth.baseSession.StartSessionAPI(ctx, w, r)
	if err != nil {
		return ctx, errors.Wrap(err, "PreauthSession.StartSessionAPI()")
	}

	return ctx, nil
}

// ValidateSession checks the sessionID in the database to validate that it has not expired
// and updates the last activity timestamp if it is still valid.
// StartSession handler must be called before calling ValidateSession
func (p *PreauthAPI) ValidateSession(ctx context.Context) (context.Context, error) {
	ctx, err := p.preauth.baseSession.CheckSessionAPI(ctx)
	if err != nil {
		return ctx, errors.Wrap(err, "PreauthSession.CheckSessionAPI()")
	}

	return ctx, nil
}
