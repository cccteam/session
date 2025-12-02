package session

import (
	"net/http"

	"github.com/cccteam/session/internal/basesession"
)

var _ PasswordHandlers = &Password{}

// PasswordHandlers defines the interface for password authentication handlers.
type PasswordHandlers interface {
	Authenticated() http.HandlerFunc
	ChangeUserPassword() http.HandlerFunc
	Login() http.HandlerFunc
	ValidateSession(next http.Handler) http.Handler
	basesession.Handlers
}
