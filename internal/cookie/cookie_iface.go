package cookie

import (
	"net/http"

	"github.com/cccteam/ccc"
	"github.com/cccteam/session/cookie"
)

var _ Handler = &Client{}

// Handler Interface included for testability
type Handler interface {
	NewAuthCookie(w http.ResponseWriter, sameSiteStrict bool, sessionID ccc.UUID) *cookie.Values
	ReadAuthCookie(r *http.Request) (values *cookie.Values, found bool, err error)
	WriteAuthCookie(w http.ResponseWriter, sameSiteStrict bool, values *cookie.Values)
	RefreshXSRFTokenCookie(w http.ResponseWriter, r *http.Request, sessionID ccc.UUID) (set bool, err error)
	CreateXSRFTokenCookie(w http.ResponseWriter, sessionID ccc.UUID)
	HasValidXSRFToken(r *http.Request) (bool, error)
	Cookie() *cookie.Client
}
