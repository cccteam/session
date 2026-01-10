package cookie

import (
	"net/http"
	"time"

	"github.com/cccteam/ccc"
	"github.com/cccteam/session/internal/types"
)

// CookieHandler Interface included for testability
type CookieHandler interface {
	NewAuthCookie(w http.ResponseWriter, sameSiteStrict bool, sessionID ccc.UUID) (map[types.SCKey]string, error)
	ReadAuthCookie(r *http.Request) (map[types.SCKey]string, bool)
	WriteAuthCookie(w http.ResponseWriter, sameSiteStrict bool, cval map[types.SCKey]string) error
	RefreshXSRFTokenCookie(w http.ResponseWriter, r *http.Request, sessionID ccc.UUID, cookieExpiration time.Duration) (set bool, err error)
	CreateXSRFTokenCookie(w http.ResponseWriter, sessionID ccc.UUID, cookieExpiration time.Duration) error
	HasValidXSRFToken(r *http.Request) bool
}
