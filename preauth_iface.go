package session

import (
	"context"
	"net/http"

	"github.com/cccteam/ccc"
)

var _ PreAuthHandlers = &PreauthSession{}

type PreAuthHandlers interface {
	sessionHandlers
	NewSession(ctx context.Context, w http.ResponseWriter, r *http.Request, username string) (ccc.UUID, error)
	NewSessionWithDomain(ctx context.Context, w http.ResponseWriter, r *http.Request, username string, domain string) (ccc.UUID, error)
}
