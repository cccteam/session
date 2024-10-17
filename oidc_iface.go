package session

import "net/http"

var _ OIDCAzureHandlers = &OIDCAzureSession{}

type OIDCAzureHandlers interface {
	CallbackOIDC() http.HandlerFunc
	FrontChannelLogout() http.HandlerFunc
	Login() http.HandlerFunc
	sessionHandlers
}
