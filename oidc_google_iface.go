package session

import (
	"net/http"

	"github.com/cccteam/session/internal/basesession"
)

var _ OIDCGoogleHandlers = &OIDCGoogle[NoCustomData, NoCustomData]{}

// OIDCGoogleHandlers defines the interface for OIDC Google session handlers. There is
// no FrontChannelLogout: Google supports no IdP-initiated logout (no
// end_session_endpoint, no sid claim).
type OIDCGoogleHandlers interface {
	CallbackOIDC() http.HandlerFunc
	Login() http.HandlerFunc
	basesession.Handlers
}
