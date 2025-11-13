package basesession

import http "net/http"

// Handlers defines the interface for session handlers used by all session implementations
type Handlers interface {
	Authenticated() http.HandlerFunc
	Logout() http.HandlerFunc
	StartSession(next http.Handler) http.Handler
	ValidateSession(next http.Handler) http.Handler
	SetXSRFToken(next http.Handler) http.Handler
	ValidateXSRFToken(next http.Handler) http.Handler
}
