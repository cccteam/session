// Package session implements the session management for the application.
package session

import (
	"context"
	"net/http"
	"strconv"
	"time"

	"github.com/cccteam/ccc"
	"github.com/cccteam/httpio"
	"github.com/cccteam/logger"
	"github.com/cccteam/session/sessioninfo"
	"github.com/go-playground/errors/v5"
	"go.opentelemetry.io/otel"
)

const name = "github.com/cccteam/session"

// stxKey is a type for storing values in the request context
type ctxKey string

const (
	// Keys used within the request Context
	ctxSessionID ctxKey = "sessionID"
)

// LogHandler defines the functional option type for handling logs.
type LogHandler func(handler func(w http.ResponseWriter, r *http.Request) error) http.HandlerFunc

type session struct {
	sessionTimeout time.Duration
	handle         LogHandler
	storage        storageManager
	cookieManager
}

// ValidateSession checks the sessionID in the database to validate that it has not expired
// and updates the last activity timestamp if it is still valid.
func (s *session) ValidateSession(next http.Handler) http.Handler {
	return s.handle(func(w http.ResponseWriter, r *http.Request) error {
		ctx, span := otel.Tracer(name).Start(r.Context(), "App.ValidateSession()")
		defer span.End()

		r, err := s.checkSession(r)
		if err != nil {
			return httpio.NewEncoder(w).ClientMessage(ctx, err)
		}

		next.ServeHTTP(w, r)

		return nil
	})
}

func (s *session) StartSession(next http.Handler) http.Handler {
	return s.handle(func(w http.ResponseWriter, r *http.Request) error {
		ctx, span := otel.Tracer(name).Start(r.Context(), "session.StartSession()")
		defer span.End()

		// Read Auth Cookie
		cval, foundAuthCookie := s.readAuthCookie(r)
		sessionID, validSessionID := validSessionID(cval[scSessionID])
		if !foundAuthCookie || !validSessionID {
			var err error
			sessionID, err = ccc.NewUUID()
			if err != nil {
				return httpio.NewEncoder(w).ClientMessage(ctx, err)
			}
			cval, err = s.newAuthCookie(w, true, sessionID)
			if err != nil {
				return httpio.NewEncoder(w).ClientMessage(ctx, err)
			}
		}

		// Upgrade cookie to SameSite=Strict
		// since CallbackOIDC() sets it to None to allow OAuth flow to work
		if cval[scSameSiteStrict] != strconv.FormatBool(true) {
			if err := s.writeAuthCookie(w, true, cval); err != nil {
				return httpio.NewEncoder(w).ClientMessage(ctx, err)
			}
		}

		// Store sessionID in context
		r = r.WithContext(context.WithValue(r.Context(), ctxSessionID, sessionID))

		// Add session ID to logging context
		logger.Req(r).AddRequestAttribute("session ID", cval[scSessionID])
		l := logger.Req(r).WithAttributes().AddAttribute("session ID", cval[scSessionID]).Logger()
		r = r.WithContext(logger.NewCtx(r.Context(), l))

		next.ServeHTTP(w, r)

		return nil
	})
}

func (s *session) checkSession(r *http.Request) (req *http.Request, err error) {
	ctx, span := otel.Tracer(name).Start(r.Context(), "App.checkSession()")
	defer span.End()

	// Validate that the sessionID is in database
	sessInfo, err := s.storage.Session(ctx, sessionIDFromRequest(r))
	if err != nil {
		return r, httpio.NewUnauthorizedMessageWithError(err, "invalid session")
	}

	// Check for expiration
	if sessInfo.Expired || time.Since(sessInfo.UpdatedAt) > s.sessionTimeout {
		return r, httpio.NewUnauthorizedMessage("session expired")
	}

	// Update Activity
	if err := s.storage.UpdateSessionActivity(ctx, sessInfo.ID); err != nil {
		return r, errors.Wrap(err, "storageManager.UpdateSessionActivity()")
	}

	// Store session info in context
	r = r.WithContext(context.WithValue(ctx, sessioninfo.CtxSessionInfo, sessInfo))

	// Add user to logging context
	logger.Req(r).AddRequestAttribute("username", sessInfo.Username)
	l := logger.Req(r).WithAttributes().AddAttribute("username", sessInfo.Username).Logger()
	r = r.WithContext(logger.NewCtx(r.Context(), l))

	return r, nil
}

// Authenticated is the handler reports if the session is authenticated
func (s *session) Authenticated() http.HandlerFunc {
	type response struct {
		Authenticated bool   `json:"authenticated"`
		Username      string `json:"username"`
	}

	return s.handle(func(w http.ResponseWriter, r *http.Request) error {
		ctx, span := otel.Tracer(name).Start(r.Context(), "App.Authenticated()")
		defer span.End()

		r, err := s.checkSession(r.WithContext(ctx))
		if err != nil {
			if httpio.HasUnauthorized(err) {
				return httpio.NewEncoder(w).Ok(response{})
			}

			return httpio.NewEncoder(w).ClientMessage(ctx, err)
		}

		sessInfo := sessioninfo.FromRequest(r)

		// set response values
		res := response{
			Authenticated: true,
			Username:      sessInfo.Username,
		}

		return httpio.NewEncoder(w).Ok(res)
	})
}

// Logout is a handler which destroys the current session
func (s *session) Logout() http.HandlerFunc {
	return s.handle(func(w http.ResponseWriter, r *http.Request) error {
		ctx, span := otel.Tracer(name).Start(r.Context(), "App.Logout()")
		defer span.End()

		// Destroy session in database
		if err := s.storage.DestroySession(ctx, sessionIDFromRequest(r)); err != nil {
			return httpio.NewEncoder(w).ClientMessage(ctx, err)
		}

		return httpio.NewEncoder(w).Ok(nil)
	})
}

func sessionIDFromRequest(r *http.Request) ccc.UUID {
	id, ok := r.Context().Value(ctxSessionID).(ccc.UUID)
	if !ok {
		logger.Req(r).Errorf("failed to find %s in request context", ctxSessionID)
	}

	return id
}

// validSessionID checks that the sessionID is a valid uuid
func validSessionID(sessionID string) (ccc.UUID, bool) {
	sessionUUID, err := ccc.UUIDFromString(sessionID)
	if err != nil {
		return ccc.NilUUID, false
	}

	return sessionUUID, true
}
