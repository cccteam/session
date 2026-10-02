package session

import (
	"fmt"
	"net/http"
	"net/url"

	"github.com/cccteam/session/sessioninfo"
)

// redirectRefusedLogin returns the browser to the login page with the reason as a code:
// loginURL?code=<code>, the code read from err by sessioninfo.LoginRefusalCodeOf. The
// code is all the URL carries; the error itself goes to the log through the handler's
// return. See the "Login refusal codes" section of the README.
func redirectRefusedLogin(w http.ResponseWriter, r *http.Request, loginURL string, err error) {
	code := sessioninfo.LoginRefusalCodeOf(err)
	http.Redirect(w, r, fmt.Sprintf("%s?code=%s", loginURL, url.QueryEscape(string(code))), http.StatusFound)
}
