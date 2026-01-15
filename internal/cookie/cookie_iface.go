package cookie

import (
	"net/http"

	"github.com/cccteam/ccc"
)

// Handler Interface included for testability
type Handler interface {
	NewAuthCookie(w http.ResponseWriter, sameSiteStrict bool, sessionID ccc.UUID) (Values, error)
	ReadAuthCookie(r *http.Request) (params Values, found bool, err error)
	WriteAuthCookie(w http.ResponseWriter, sameSiteStrict bool, cval Values) error
	RefreshXSRFTokenCookie(w http.ResponseWriter, r *http.Request, sessionID ccc.UUID) (set bool, err error)
	CreateXSRFTokenCookie(w http.ResponseWriter, sessionID ccc.UUID) error
	HasValidXSRFToken(r *http.Request) (bool, error)
}
