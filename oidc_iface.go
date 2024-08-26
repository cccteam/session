package session

import "net/http"

type OIDCAzureHandlers interface {
	Authenticated() http.HandlerFunc
	CallbackOIDC() http.HandlerFunc
	FrontChannelLogout() http.HandlerFunc
	Login() http.HandlerFunc
	Logout() http.HandlerFunc
}
