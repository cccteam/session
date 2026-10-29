package signin

import (
	"net/http"

	"github.com/cccteam/httpio"
)

// LoginOptions are what a login request asks of the provider beyond the return
// address: the hints a login page adds to the provider's authorization request. The
// provider may ignore them; the identity always comes from the verified token.
type LoginOptions struct {
	// LoginHint is the account the provider is asked to pick, its login_hint
	// parameter, or "" for none. The Google method reads it from ?login_hint=.
	LoginHint string
	// SelectAccount asks the provider to show its account chooser, its
	// prompt=select_account parameter. A login page sets it after a refusal and under
	// "Use a different account", so a provider holding one signed-in account does not
	// sign that account in again without asking. The Google and Entra methods read it
	// from ?prompt=select_account.
	SelectAccount bool
}

// promptSelectAccount is the one value of ?prompt= a login route accepts: the
// provider's account chooser. none and consent stay the library's to decide.
const promptSelectAccount = "select_account"

// SelectAccount reads ?prompt= from a login request: select_account asks the provider
// for its account chooser, an absent or empty value asks for nothing, and any other
// value is a login page's mistake, refused with 400.
func SelectAccount(r *http.Request) (bool, error) {
	switch r.URL.Query().Get("prompt") {
	case "":
		return false, nil
	case promptSelectAccount:
		return true, nil
	default:
		return false, httpio.NewBadRequestMessage("prompt must be select_account or absent")
	}
}
