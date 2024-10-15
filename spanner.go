package session

import (
	cloudspanner "cloud.google.com/go/spanner"
)

type PreauthSpannerSession struct {
	session
	storage *SpannerPreauthSessionManager
}

func NewPreauthSpannerSession(userManager UserManager, db *cloudspanner.Client) *PreauthSpannerSession {
	return &PreauthSpannerSession{
		session: session{
			access: userManager,
		},
		storage: NewSpannerPreauthSessionManager(userManager, db),
	}
}
