package session

import (
	"time"

	cloudspanner "cloud.google.com/go/spanner"
	"github.com/gorilla/securecookie"
)

type PreauthSpannerSession struct {
	session
	storage *SpannerPreauthSessionManager
}

func NewPreauthSpannerSession(userManager UserManager, db *cloudspanner.Client, logHandler LogHandler, secureCookie *securecookie.SecureCookie, sessionTimeout time.Duration) *PreauthSpannerSession {
	return &PreauthSpannerSession{
		session: session{
			access:         userManager,
			handle:         logHandler,
			cookieManager:  newCookieClient(secureCookie),
			sessionTimeout: sessionTimeout,
		},
		storage: NewSpannerPreauthSessionManager(userManager, db),
	}
}
