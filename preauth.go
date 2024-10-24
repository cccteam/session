package session

import (
	"context"
	"net/http"
	"time"

	"github.com/cccteam/ccc"
	"github.com/go-playground/errors/v5"
	"github.com/gorilla/securecookie"
)

var _ PreAuthHandlers = &PreauthSession{}

type PreauthSession struct {
	storage PreauthSessionStorage
	session
}

func NewPreauth(
	preauthSession PreauthSessionStorage, userPermissionManager UserPermissionManager,
	logHandler LogHandler, secureCookie *securecookie.SecureCookie, sessionTimeout time.Duration,
) *PreauthSession {
	return &PreauthSession{
		session: session{
			perms:          userPermissionManager,
			handle:         logHandler,
			cookieManager:  newCookieClient(secureCookie),
			sessionTimeout: sessionTimeout,
			storage:        preauthSession,
		},
		storage: preauthSession,
	}
}

func (p *PreauthSession) NewSession(ctx context.Context, w http.ResponseWriter, r *http.Request, username string) (ccc.UUID, error) {
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
