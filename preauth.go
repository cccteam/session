package session

import (
	"context"
	"net/http"
	"time"

	"github.com/cccteam/ccc"
	"github.com/go-playground/errors/v5"
	"github.com/gorilla/securecookie"
	"go.opentelemetry.io/otel"
)

type PreAuthOption interface {
	isPreAuthOption()
}

var _ PreAuthHandlers = &PreauthSession{}

type PreauthSession struct {
	storage PreauthSessionStorage
	session
}

func NewPreauth(
	preauthSession PreauthSessionStorage, userPermissionManager UserPermissionManager,
	logHandler LogHandler, secureCookie *securecookie.SecureCookie, sessionTimeout time.Duration,
	options ...PreAuthOption,
) *PreauthSession {
	cookieOpts := make([]CookieOption, 0, len(options))
	for _, opt := range options {
		if o, ok := any(opt).(CookieOption); ok {
			cookieOpts = append(cookieOpts, o)
		}
	}

	return &PreauthSession{
		session: session{
			perms:          userPermissionManager,
			handle:         logHandler,
			cookieManager:  newCookieClient(secureCookie, cookieOpts...),
			sessionTimeout: sessionTimeout,
			storage:        preauthSession,
		},
		storage: preauthSession,
	}
}

func (p *PreauthSession) NewSession(ctx context.Context, w http.ResponseWriter, r *http.Request, username string) (ccc.UUID, error) {
	ctx, span := otel.Tracer(name).Start(ctx, "PreauthSession.NewSession()")
	defer span.End()

	// Create new Session in database
	id, err := p.storage.NewSession(ctx, username)
	if err != nil {
		return ccc.NilUUID, errors.Wrap(err, "PreauthSessionStorage.NewSession()")
	}

	// Write new Auth Cookie
	if _, err := p.newAuthCookie(w, false, id); err != nil {
		return ccc.NilUUID, err
	}

	// Write new XSRF Token Cookie to match the new SessionID
	p.setXSRFTokenCookie(w, r, id, xsrfCookieLife)

	return id, nil
}
