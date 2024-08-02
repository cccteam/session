package session

import (
	"context"
	"net/http"
	"session/oidc"
	"session/users"
	"strconv"
	"time"

	"github.com/cccteam/httpio"
	"github.com/cccteam/logger"
	"github.com/go-playground/errors/v5"
	"github.com/gofrs/uuid"
	"github.com/gorilla/securecookie"
	"go.opentelemetry.io/otel"
)

const (
	ErrUnauthorized = "ErrUnauthorized"
)

type Session struct {
	sessionTimeout time.Duration
	oidc           oidc.Authenticator
	userClient     users.UserManager
	appName        string
	cookieManager
}

// TODO: How do we override all this functionality? Do we make it all interfaces and allow them to replace or do we just force a local version?
func New(
	oidc oidc.Authenticator,
	sessionTimeout time.Duration,
	userClient users.UserManager,
	secureCookie *securecookie.SecureCookie,
	appName string) *Session {
	return &Session{oidc: oidc, sessionTimeout: sessionTimeout, userClient: userClient, cookieManager: newCookieClient(secureCookie), appName: appName} //TODO: Validate theres not a better way when we try to implement this into one of our apps
}

// SetTimeout is a Handler to set the session timeout
func (s *Session) SetTimeout(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		r = r.WithContext(context.WithValue(r.Context(), ctxSessionExpirationDuration, s.sessionTimeout))

		next.ServeHTTP(w, r)
	})
}

// Start establishes a session cookie if none exists
//
// It also stores the sessionID in the request context.
func (s *Session) Start(next http.Handler) http.Handler {
	return s.handle(func(w http.ResponseWriter, r *http.Request) error {
		ctx, span := otel.Tracer(s.appName).Start(r.Context(), "session.StartSession()")
		defer span.End()

		// Read Auth Cookie
		cookieValue, ok := s.readAuthCookie(r)
		if !ok || !validSessionID(cookieValue[scSessionID]) {
			var err error
			cookieValue, err = s.newAuthCookie(w, true, uuid.NewV4)
			if err != nil {
				return httpio.NewEncoder(w).ClientMessage(ctx, err)
			}
		}

		// Upgrade cookie to SameSite=Strict
		// since CallbackOIDC() sets it to None to allow OAuth flow to work
		if cookieValue[scSameSiteStrict] != strconv.FormatBool(true) {
			if err := s.writeAuthCookie(w, true, cookieValue); err != nil {
				return httpio.NewEncoder(w).ClientMessage(ctx, err)
			}
		}

		// Store sessionID in context
		r = r.WithContext(context.WithValue(r.Context(), ctxSessionID, cookieValue[scSessionID]))

		// Add session ID to logging context
		logger.Req(r).AddRequestAttribute("session ID", cookieValue[scSessionID])
		l := logger.Req(r).WithAttributes().AddAttribute("session ID", cookieValue[scSessionID]).Logger()
		r = r.WithContext(logger.NewCtx(r.Context(), l))

		next.ServeHTTP(w, r)

		return nil
	})
}

// Validate checks the sessionID in the database to validate that it has not expired
// and updates the last activity timestamp if it is still valid.
func (s *Session) Validate(next http.Handler) http.Handler {
	return s.handle(func(w http.ResponseWriter, r *http.Request) error {
		ctx, span := otel.Tracer(s.appName).Start(r.Context(), "session.Validate()")
		defer span.End()

		r, err := s.check(r)
		if err != nil {
			return httpio.NewEncoder(w).ClientMessage(ctx, err)
		}

		next.ServeHTTP(w, r)

		return nil
	})
}

func (s *Session) check(r *http.Request) (req *http.Request, err error) {
	ctx, span := otel.Tracer(s.appName).Start(r.Context(), "session.checkSession()")
	defer span.End()

	// Validate that the sessionID is in database
	sessInfo, err := s.userClient.Session(ctx, sessionIDFromRequest(r))
	if err != nil {
		return r, httpio.NewUnauthorizedMessageWithError(err, "invalid session")
	}

	// Check for expiration
	if sessInfo.Expired || time.Since(sessInfo.UpdatedAt) > sessionExpirationFromRequest(r) {
		return r, httpio.NewUnauthorizedMessage("session expired")
	}

	// Update Activity
	if err := s.userClient.UpdateSessionActivity(ctx, sessInfo.ID); err != nil {
		return r, errors.Wrap(err, "users.SessionManager.UpdateSessionActivity()")
	}

	// Store session info in context
	r = r.WithContext(context.WithValue(ctx, ctxSessionInfo, sessInfo))

	// Add user to logging context
	logger.Req(r).AddRequestAttribute("username", sessInfo.Username)
	l := logger.Req(r).WithAttributes().AddAttribute("username", sessInfo.Username).Logger()
	r = r.WithContext(logger.NewCtx(r.Context(), l))

	return r, nil
}

// validSessionID checks that the sessionID is a valid uuid
func validSessionID(sessionID string) bool {
	if _, err := uuid.FromString(sessionID); err != nil {
		return false
	}

	return true
}
