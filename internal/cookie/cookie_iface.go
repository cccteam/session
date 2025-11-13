package cookie

import (
	"net/http"
	"time"

	"github.com/cccteam/ccc"
	"github.com/cccteam/session/internal/types"
)

// CookieManager Interface included for testability
type CookieManager interface {
	NewAuthCookie(w http.ResponseWriter, sameSiteStrict bool, sessionID ccc.UUID) (map[types.SCKey]string, error)
	ReadAuthCookie(r *http.Request) (map[types.SCKey]string, bool)
	WriteAuthCookie(w http.ResponseWriter, sameSiteStrict bool, cval map[types.SCKey]string) error
	SetXSRFTokenCookie(w http.ResponseWriter, r *http.Request, sessionID ccc.UUID, cookieExpiration time.Duration) (set bool)
	HasValidXSRFToken(r *http.Request) bool
}
