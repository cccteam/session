package legacy

import (
	"net/http"

	"github.com/cccteam/session"
	"github.com/cccteam/session/internal/basesession"
)

var _ OIDCAzureHandlers = &OIDCAzure[session.NoCustomData, session.NoCustomData]{}

// OIDCAzureHandlers defines the interface for OIDC Azure session handlers.
//
// Deprecated: the legacy Microsoft Entra ID session; use session.Auth with azure.SignIn, which shares the session, the user model and the middleware with every other sign-in method.
type OIDCAzureHandlers interface {
	CallbackOIDC() http.HandlerFunc
	FrontChannelLogout() http.HandlerFunc
	Login() http.HandlerFunc
	basesession.Handlers
}
