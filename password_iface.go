package session

import (
	"net/http"

	"github.com/cccteam/session/internal/basesession"
)

var _ PasswordAuthHandlers = &PasswordAuth{}

// PasswordAuthHandlers defines the interface for password authentication handlers.
type PasswordAuthHandlers interface {
	ActivateUser() http.HandlerFunc
	Authenticated() http.HandlerFunc
	ChangeUserPassword() http.HandlerFunc
	DeactivateUser() http.HandlerFunc
	Login() http.HandlerFunc
	ValidateSession(next http.Handler) http.Handler
	basesession.Handlers
}
