package session

import (
	"encoding/json"
	"net/http"
	"time"

	"github.com/cccteam/ccc/accesstypes"
	"github.com/cccteam/httpio"
	"github.com/gorilla/securecookie"
	"go.opentelemetry.io/otel"
	"golang.org/x/crypto/bcrypt"
)

// PasswordOption defines the functional option type for configuring PasswordSession.
type PasswordOption interface {
	isPasswordOption()
}

var _ PasswordHandlers = &PasswordSession{}

// PasswordSession handles session management for username/password authentication.
type PasswordSession struct {
	credentials PasswordCredentialReader
	storage     PasswordSessionStorage
	session
}

// NewPassword creates a new PasswordSession instance.
func NewPassword(
	credentialReader PasswordCredentialReader, passwordSession PasswordSessionStorage, userPermissionManager UserPermissionManager,
	logHandler LogHandler, secureCookie *securecookie.SecureCookie, sessionTimeout time.Duration,
	options ...PasswordOption,
) *PasswordSession {
	cookieOpts := make([]CookieOption, 0, len(options))
	for _, opt := range options {
		if o, ok := any(opt).(CookieOption); ok {
			cookieOpts = append(cookieOpts, o)
		}
	}

	return &PasswordSession{
		credentials: credentialReader,
		storage:     passwordSession,
		session: session{
			perms:          userPermissionManager,
			handle:         logHandler,
			cookieManager:  newCookieClient(secureCookie, cookieOpts...),
			sessionTimeout: sessionTimeout,
			storage:        passwordSession,
		},
	}
}

// Login authenticates a user using username and password credentials.
func (p *PasswordSession) Login() http.HandlerFunc {
	type request struct {
		Username string `json:"username" validate:"required"`
		Password string `json:"password" validate:"required"`
	}
	type response struct {
		Authenticated bool                                 `json:"authenticated"`
		Username      string                               `json:"username"`
		Permissions   accesstypes.UserPermissionCollection `json:"permissions"`
	}

	return p.handle(func(w http.ResponseWriter, r *http.Request) error {
		ctx, span := otel.Tracer(name).Start(r.Context(), "PasswordSession.Login()")
		defer span.End()

		payload := &request{}
		if err := json.NewDecoder(r.Body).Decode(payload); err != nil {
			return httpio.NewEncoder(w).BadRequestMessageWithError(ctx, err, "invalid request body")
		}

		if payload.Username == "" || payload.Password == "" {
			return httpio.NewEncoder(w).BadRequestMessage(ctx, "username and password are required")
		}
		hashedPassword, err := p.credentials.HashedPassword(ctx, payload.Username)
		if err != nil {
			return httpio.NewEncoder(w).UnauthorizedMessageWithError(ctx, err, "invalid username or password")
		}

		if err := bcrypt.CompareHashAndPassword([]byte(hashedPassword), []byte(payload.Password)); err != nil {
			return httpio.NewEncoder(w).UnauthorizedMessageWithError(ctx, err, "invalid username or password")
		}

		sessionID, err := p.storage.NewSession(ctx, payload.Username)
		if err != nil {
			return httpio.NewEncoder(w).ClientMessage(ctx, err)
		}

		if _, err := p.newAuthCookie(w, false, sessionID); err != nil {
			return httpio.NewEncoder(w).ClientMessage(ctx, err)
		}

		p.setXSRFTokenCookie(w, r, sessionID, xsrfCookieLife)

		permissions, err := p.perms.UserPermissions(ctx, accesstypes.User(payload.Username))
		if err != nil {
			return httpio.NewEncoder(w).ClientMessage(ctx, err)
		}

		res := response{
			Authenticated: true,
			Username:      payload.Username,
			Permissions:   permissions,
		}

		return httpio.NewEncoder(w).Ok(res)
	})
}
