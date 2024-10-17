package session

import (
	"context"
	"net/http"

	"github.com/cccteam/ccc"
)

type PreAuthHandlers interface {
	NewSession(ctx context.Context, w http.ResponseWriter, username string) (ccc.UUID, error)
	sessionHandlers
}
