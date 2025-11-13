package session

import (
	"context"
	"net/http"

	"github.com/cccteam/ccc"
	"github.com/cccteam/session/internal/basesession"
)

var _ PreAuthHandlers = &PreauthSession{}

// PreAuthHandlers defines the interface for pre-authentication session handlers.
type PreAuthHandlers interface {
	basesession.Handlers
	NewSession(ctx context.Context, w http.ResponseWriter, r *http.Request, username string) (ccc.UUID, error)
}
