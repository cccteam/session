package session

import (
	"context"
	"encoding/json"
	"net/http"
	"time"

	"github.com/cccteam/ccc"
	"github.com/cccteam/httpio"
	"github.com/cccteam/session/dbtype"
	"github.com/go-playground/errors/v5"
	"github.com/gorilla/securecookie"
	"go.opentelemetry.io/otel"
	"golang.org/x/crypto/bcrypt"
)

// UserpassSession implements the UserpassHandlers interface for handling username/password authentication.
type UserpassSession struct {
	userManager UserManager
	session
}

// UserpassSessionStorage defines an interface for managing username/password sessions.
type UserpassSessionStorage interface {
	NewSession(ctx context.Context, username string) (ccc.UUID, error)
	User(ctx context.Context, username string) (*dbtype.User, error)
	CreateUser(ctx context.Context, username, password string) error
	storageManager
}

// NewUserpass creates a new UserpassSession.
func NewUserpass(
	sessionStorage UserpassSessionStorage, userManager UserManager,
	logHandler LogHandler, secureCookie *securecookie.SecureCookie, sessionTimeout time.Duration,
) *UserpassSession {
	return &UserpassSession{
		userManager: userManager,
		session: session{
			perms:          userManager,
			handle:         logHandler,
			cookieManager:  newCookieClient(secureCookie),
			sessionTimeout: sessionTimeout,
			storage:        sessionStorage,
		},
	}
}

// Login is a handler for authenticating a user with a username and password.
func (s *UserpassSession) Login() http.HandlerFunc {
	type request struct {
		Username string `json:"username"`
		Password string `json:"password"`
	}

	return s.handle(func(w http.ResponseWriter, r *http.Request) error {
		ctx, span := otel.Tracer(name).Start(r.Context(), "UserpassSession.Login()")
		defer span.End()

		// decode request
		req := &request{}
		if err := json.NewDecoder(r.Body).Decode(req); err != nil {
			return httpio.NewEncoder(w).BadRequestMessage(ctx, "invalid request body")
		}

		// get user from database
		user, err := s.storage.(UserpassSessionStorage).User(ctx, req.Username)
		if err != nil {
			if httpio.HasNotFound(err) {
				return httpio.NewEncoder(w).UnauthorizedMessage(ctx, "invalid username or password")
			}
			return httpio.NewEncoder(w).ClientMessage(ctx, err)
		}

		// compare password
		if err := bcrypt.CompareHashAndPassword([]byte(user.Password), []byte(req.Password)); err != nil {
			return httpio.NewEncoder(w).UnauthorizedMessage(ctx, "invalid username or password")
		}

		// user is successfully authenticated, start a new session
		sessionID, err := s.startNewSession(ctx, w, req.Username)
		if err != nil {
			return httpio.NewEncoder(w).ClientMessage(ctx, err)
		}

		// write new XSRF Token Cookie to match the new SessionID
		s.setXSRFTokenCookie(w, r, sessionID, xsrfCookieLife)

		return httpio.NewEncoder(w).Ok(nil)
	})
}

// startNewSession starts a new session for the given username and returns the session ID
func (s *UserpassSession) startNewSession(ctx context.Context, w http.ResponseWriter, username string) (ccc.UUID, error) {
	// Create new Session in database
	id, err := s.storage.(UserpassSessionStorage).NewSession(ctx, username)
	if err != nil {
		return ccc.NilUUID, errors.Wrap(err, "UserpassSessionStorage.NewSession()")
	}

	if _, err := s.newAuthCookie(w, false, id); err != nil {
		return ccc.NilUUID, err
	}

	return id, nil
}

// CreateUser is a handler for creating a new user.
func (s *UserpassSession) CreateUser() http.HandlerFunc {
	type request struct {
		Username string `json:"username"`
		Password string `json:"password"`
	}

	return s.handle(func(w http.ResponseWriter, r *http.Request) error {
		ctx, span := otel.Tracer(name).Start(r.Context(), "UserpassSession.CreateUser()")
		defer span.End()

		// decode request
		req := &request{}
		if err := json.NewDecoder(r.Body).Decode(req); err != nil {
			return httpio.NewEncoder(w).BadRequestMessage(ctx, "invalid request body")
		}

		// hash password
		hashedPassword, err := bcrypt.GenerateFromPassword([]byte(req.Password), bcrypt.DefaultCost)
		if err != nil {
			return httpio.NewEncoder(w).ClientMessage(ctx, err)
		}

		// create user in database
		if err := s.storage.(UserpassSessionStorage).CreateUser(ctx, req.Username, string(hashedPassword)); err != nil {
			return httpio.NewEncoder(w).ClientMessage(ctx, err)
		}

		return httpio.NewEncoder(w).Ok(nil)
	})
}
