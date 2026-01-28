package session

import (
	"context"
	"net/http"

	"github.com/cccteam/ccc"
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

// Preauth handles session management for pre-authentication scenarios.
type Preauth struct {
	storage     sessionstorage.PreauthStore
	baseSession *basesession.BaseSession
}

// NewPreauth creates a new PreauthSession instance.
// cookieKey: A Base64-encoded string representing at least 32 bytes
// of cryptographically secure random data.
func NewPreauth(storage sessionstorage.PreauthStore, cookieKey string, options ...PreauthOption) (*Preauth, error) {
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

	return &Preauth{
		baseSession: baseSession,
		storage:     storage,
	}, nil
}

// NewSession creates a new session for a pre-authenticated user.
//
// Deprecated: Use p.API().Login() instead
func (p *Preauth) NewSession(ctx context.Context, w http.ResponseWriter, _ *http.Request, username string) (ccc.UUID, error) {
	return p.API().Login(ctx, w, username)
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

// Login creates a new session for a pre-authenticated user.
func (p *PreauthAPI) Login(ctx context.Context, w http.ResponseWriter, username string) (ccc.UUID, error) {
	ctx, span := ccc.StartTrace(ctx)
	defer span.End()

	// Create new Session in database
	sessionID, err := p.preauth.storage.NewSession(ctx, username)
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

// Logout destroys the current session
func (p *PreauthAPI) Logout(ctx context.Context) error {
	// Destroy session in database
	if err := p.preauth.baseSession.Storage.DestroySession(ctx, sessioninfo.IDFromCtx(ctx)); err != nil {
		return errors.Wrap(err, "sessionstorage.BaseStore.DestroySession()")
	}

	return nil
}

// StartSession initializes a session by restoring it from a cookie, or if
// that fails, initializing a new session. The session cookie is then updated and
// the sessionID is inserted into the context.
func (p *PreauthAPI) StartSession(ctx context.Context, w http.ResponseWriter, r *http.Request) (context.Context, error) {
	ctx, err := p.preauth.baseSession.StartSessionAPI(ctx, w, r)
	if err != nil {
		return ctx, errors.Wrap(err, "basesession.BaseSession.StartSessionAPI()")
	}

	return ctx, nil
}

// ValidateSession checks the sessionID in the database to validate that it has not expired
// and updates the last activity timestamp if it is still valid.
// StartSession handler must be called before calling ValidateSession
func (p *PreauthAPI) ValidateSession(ctx context.Context) (context.Context, error) {
	ctx, err := p.preauth.baseSession.ValidateSessionAPI(ctx)
	if err != nil {
		return ctx, errors.Wrap(err, "basesession.BaseSession.ValidateSessionAPI()")
	}

	return ctx, nil
}

// Cookie returns the underlying cookie.Client
func (p *PreauthAPI) Cookie() *cookie.Client {
	return p.preauth.baseSession.CookieHandler.Cookie()
}
