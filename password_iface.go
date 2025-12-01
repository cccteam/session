package session

import (
	"net/http"

	"github.com/cccteam/session/internal/basesession"
)

var _ PasswordHandlers = &Password{}

// PasswordHandlers defines the interface for OIDC Azure session handlers.
type PasswordHandlers interface {
	Login() http.HandlerFunc
	ChangeUserPassword() http.HandlerFunc
	basesession.Handlers
}
