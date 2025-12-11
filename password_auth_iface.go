package session

import (
	"net/http"

	"github.com/cccteam/session/internal/basesession"
)

var _ PasswordAuthHandlers = &PasswordAuth{}

// PasswordAuthHandlers defines the interface for password authentication handlers.
type PasswordAuthHandlers interface {
	// ActivateUser handles activating a user account.
	ActivateUser() http.HandlerFunc
	// Authenticated is the handler reports if the session is authenticated.
	Authenticated() http.HandlerFunc
	// ChangeUserPassword handles modifications to a user password.
	ChangeUserPassword() http.HandlerFunc
	// CreateUser handles creating a user account.
	CreateUser() http.HandlerFunc
	// DeactivateUser handles deactivating a user account.
	DeactivateUser() http.HandlerFunc
	// DeleteUser handles deleting a user account.
	DeleteUser() http.HandlerFunc
	// Login validates the username and password.
	Login() http.HandlerFunc
	// ValidateSession checks the sessionID in the database to validate that it has not expired
	// and updates the last activity timestamp if it is still valid.
	ValidateSession(next http.Handler) http.Handler
	basesession.Handlers
}
