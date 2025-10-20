package session

import (
	"encoding/json"
	"net/http"
	"strings"
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

var dummyPasswordHash = func() []byte {
	hash, err := bcrypt.GenerateFromPassword([]byte("dummy-password"), bcrypt.DefaultCost)
	if err != nil {
		// fallback to a well-known bcrypt hash for the word "password"
		return []byte("$2a$10$CwTycUXWue0Thq9StjUM0uJ8iU91vK8G6D/Ejko116IhVQbK5EOi")
	}

	return hash
}()

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
		Username string `json:"username"`
		Password string `json:"password"`
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
			return httpio.NewEncoder(w).BadRequestMessage(ctx, "invalid request body")
		}

		payload.Username = strings.TrimSpace(payload.Username)
		if payload.Username == "" || payload.Password == "" {
			return httpio.NewEncoder(w).BadRequestMessage(ctx, "username and password are required")
		}

		hashedPassword, err := p.credentials.HashedPassword(ctx, payload.Username)
		if err != nil {
			if httpio.HasNotFound(err) || httpio.HasUnauthorized(err) {
				_ = bcrypt.CompareHashAndPassword(dummyPasswordHash, []byte(payload.Password))

				return httpio.NewEncoder(w).ClientMessage(ctx, httpio.NewUnauthorizedMessage("invalid username or password"))
			}

			return httpio.NewEncoder(w).ClientMessage(ctx, err)
		}

		if err := bcrypt.CompareHashAndPassword([]byte(hashedPassword), []byte(payload.Password)); err != nil {
			return httpio.NewEncoder(w).ClientMessage(ctx, httpio.NewUnauthorizedMessage("invalid username or password"))
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
