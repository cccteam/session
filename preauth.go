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

// PreauthOption defines the functional option type for configuring PreauthSession.
type PreauthOption interface {
	isPreauthOption()
}

var _ PreauthHandlers = &Preauth{}

// Preauth handles session management for pre-authentication scenarios.
type Preauth struct {
	storage sessionstorage.Preauth
	*basesession.BaseSession
}

// NewPreauth creates a new PreauthSession instance.
func NewPreauth(storage sessionstorage.Preauth, secureCookie *securecookie.SecureCookie, options ...PreauthOption) *Preauth {
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
		BaseSession: baseSession,
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
	if _, err := p.NewAuthCookie(w, true, id); err != nil {
		return ccc.NilUUID, errors.Wrap(err, "PreauthSession.NewAuthCookie()")
	}

	// Write new XSRF Token Cookie to match the new SessionID
	p.SetXSRFTokenCookie(w, r, id, types.XSRFCookieLife)

	return id, nil
}
