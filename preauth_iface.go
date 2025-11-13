package session

import (
	"context"
	"net/http"

	"github.com/cccteam/ccc"
	"github.com/cccteam/session/internal/basesession"
)

var _ PreauthHandlers = &Preauth{}

// PreauthHandlers defines the interface for pre-authentication session handlers.
type PreauthHandlers interface {
	basesession.Handlers
	NewSession(ctx context.Context, w http.ResponseWriter, r *http.Request, username string) (ccc.UUID, error)
}
