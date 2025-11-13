package session

import (
	"net/http"

	"github.com/cccteam/session/internal/basesession"
)

var _ OIDCAzureHandlers = &OIDCAzureSession{}

// OIDCAzureHandlers defines the interface for OIDC Azure session handlers.
type OIDCAzureHandlers interface {
	CallbackOIDC() http.HandlerFunc
	FrontChannelLogout() http.HandlerFunc
	Login() http.HandlerFunc
	basesession.Handlers
}
