package basesession

import http "net/http"

type Handlers interface {
	Authenticated() http.HandlerFunc
	Logout() http.HandlerFunc
	StartSession(next http.Handler) http.Handler
	ValidateSession(next http.Handler) http.Handler
	SetXSRFToken(next http.Handler) http.Handler
	ValidateXSRFToken(next http.Handler) http.Handler
}
