package session

import (
	"context"
	"net/http"

	"github.com/cccteam/ccc"
	"github.com/cccteam/httpio"
	"github.com/cccteam/session/internal/basesession"
	"github.com/cccteam/session/internal/cookie"
	"github.com/cccteam/session/internal/types"
	"github.com/cccteam/session/sessionstorage"
	"github.com/go-playground/errors/v5"
	"github.com/gorilla/securecookie"
)

// PreAuthOption defines the functional option type for configuring PreauthSession.
type PreAuthOption interface {
	isPreAuthOption()
}

var _ PreAuthHandlers = &Preauth{}

// Preauth handles session management for pre-authentication scenarios.
type Preauth struct {
	storage sessionstorage.Preauth
	*basesession.BaseSession
}

// NewPreauth creates a new PreauthSession instance.
func NewPreauth(
	preauthSession sessionstorage.Preauth,
	secureCookie *securecookie.SecureCookie, options ...PreAuthOption,
) *Preauth {
	cookieOpts := make([]cookie.Option, 0, len(options))
	for _, opt := range options {
		if o, ok := any(opt).(cookie.Option); ok {
			cookieOpts = append(cookieOpts, o)
		}
	}

	baseSession := &basesession.BaseSession{
		Handle:         httpio.Log,
		CookieHandler:  cookie.NewCookieClient(secureCookie, cookieOpts...),
		SessionTimeout: defaultSessionTimeout,
		Storage:        preauthSession,
	}
	for _, opt := range options {
		if o, ok := any(opt).(BaseSessionOption); ok {
			o(baseSession)
		}
	}

	return &Preauth{
		BaseSession: baseSession,
		storage:     preauthSession,
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
	if _, err := p.NewAuthCookie(w, true, id); err != nil {
		return ccc.NilUUID, errors.Wrap(err, "PreauthSession.NewAuthCookie()")
	}

	// Write new XSRF Token Cookie to match the new SessionID
	p.SetXSRFTokenCookie(w, r, id, types.XSRFCookieLife)

	return id, nil
}
