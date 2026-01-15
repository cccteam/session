package cookie

import (
	"net/http"

	"github.com/cccteam/ccc"
	"github.com/cccteam/session/internal/types"
)

// Handler Interface included for testability
type Handler interface {
	NewAuthCookie(w http.ResponseWriter, sameSiteStrict bool, sessionID ccc.UUID) (map[types.SCKey]string, error)
	ReadAuthCookie(r *http.Request) (params map[types.SCKey]string, found bool, err error)
	WriteAuthCookie(w http.ResponseWriter, sameSiteStrict bool, cval map[types.SCKey]string) error
	RefreshXSRFTokenCookie(w http.ResponseWriter, r *http.Request, sessionID ccc.UUID) (set bool, err error)
	CreateXSRFTokenCookie(w http.ResponseWriter, sessionID ccc.UUID) error
	HasValidXSRFToken(r *http.Request) (bool, error)
}
