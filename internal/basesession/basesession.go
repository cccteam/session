// Package basesession implements the session management for the application.
package basesession

import (
	"context"
	"net/http"
	"strconv"
	"time"

	"github.com/cccteam/ccc"
	"github.com/cccteam/httpio"
	"github.com/cccteam/logger"
	"github.com/cccteam/session/internal/cookie"
	"github.com/cccteam/session/internal/types"
	"github.com/cccteam/session/sessioninfo"
	"github.com/cccteam/session/sessionstorage"
	"github.com/go-playground/errors/v5"
)

// LogHandler defines the handler signature required for handling logs.
type LogHandler func(handler func(w http.ResponseWriter, r *http.Request) error) http.HandlerFunc

// BaseSession implements the shared features for all session implementations
type BaseSession struct {
	SessionTimeout time.Duration
	Handle         LogHandler
	Storage        sessionstorage.BaseStore
	CookieHandler  cookie.Handler
}

// StartSession initializes a session by restoring it from a cookie, or if
// that fails, initializing a new session. The session cookie is then updated and
// the sessionID is inserted into the context.
func (s *BaseSession) StartSession(next http.Handler) http.Handler {
	return s.Handle(func(w http.ResponseWriter, r *http.Request) error {
		ctx, span := ccc.StartTrace(r.Context())
		defer span.End()

		ctx, err := s.StartSessionAPI(ctx, w, r)
		if err != nil {
			return httpio.NewEncoder(w).ClientMessage(ctx, err)
		}

		next.ServeHTTP(w, r.WithContext(ctx))

		return nil
	})
}

// StartSessionAPI exposes the internals of the StartSession Handler for use with the API interface
func (s *BaseSession) StartSessionAPI(ctx context.Context, w http.ResponseWriter, r *http.Request) (context.Context, error) {
	// Read Auth Cookie
	cval, foundAuthCookie, err := s.CookieHandler.ReadAuthCookie(r)
	if err != nil {
		return ctx, errors.Wrap(err, "cookie.CookieHandler.ReadAuthCookie()")
	}

	sessionID, validSessionID := types.ValidSessionID(cval[types.SCSessionID])
	if !foundAuthCookie || !validSessionID {
		var err error
		sessionID, err = ccc.NewUUID()
		if err != nil {
			return ctx, errors.Wrap(err, "ccc.NewUUID()")
		}
		cval, err = s.CookieHandler.NewAuthCookie(w, true, sessionID)
		if err != nil {
			return ctx, errors.Wrap(err, "cookie.CookieHandler.NewAuthCookie()")
		}
	}

	// Upgrade cookie to SameSite=Strict
	// since CallbackOIDC() sets it to None to allow OAuth flow to work
	if cval[types.SCSameSiteStrict] != strconv.FormatBool(true) {
		if err := s.CookieHandler.WriteAuthCookie(w, true, cval); err != nil {
			return ctx, errors.Wrap(err, "cookie.CookieHandler.WriteAuthCookie()")
		}
	}

	// Store sessionID in context
	ctx = context.WithValue(ctx, types.CTXSessionID, sessionID)

	// Add session ID to logging context
	l := logger.FromCtx(ctx).AddRequestAttribute("session ID", sessionID).
		WithAttributes().AddAttribute("session ID", sessionID).Logger()

	ctx = logger.NewCtx(ctx, l)

	return ctx, nil
}

// ValidateSession checks the sessionID in the database to validate that it has not expired
// and updates the last activity timestamp if it is still valid.
// StartSession handler must be called before calling ValidateSession
func (s *BaseSession) ValidateSession(next http.Handler) http.Handler {
	return s.Handle(func(w http.ResponseWriter, r *http.Request) error {
		ctx, span := ccc.StartTrace(r.Context())
		defer span.End()

		ctx, err := s.ValidateSessionAPI(ctx)
		if err != nil {
			return httpio.NewEncoder(w).ClientMessage(ctx, err)
		}

		next.ServeHTTP(w, r.WithContext(ctx))

		return nil
	})
}

// ValidateSessionAPI checks the session cookie and if it is valid, stores the session data into the context
func (s *BaseSession) ValidateSessionAPI(ctx context.Context) (context.Context, error) {
	ctx, span := ccc.StartTrace(ctx)
	defer span.End()

	// Validate that the sessionID is in database
	sessInfo, err := s.Storage.Session(ctx, sessioninfo.IDFromCtx(ctx))
	if err != nil {
		return ctx, httpio.NewUnauthorizedMessageWithError(err, "invalid session")
	}

	// Check for expiration
	if sessInfo.Expired || time.Since(sessInfo.UpdatedAt) > s.SessionTimeout {
		return ctx, httpio.NewUnauthorizedMessage("session expired")
	}

	// Update last activity (rate limit updates)
	if time.Since(sessInfo.UpdatedAt) > time.Second*5 {
		if err := s.Storage.UpdateSessionActivity(ctx, sessInfo.ID); err != nil {
			return ctx, errors.Wrap(err, "sessionstorage.BaseStore.UpdateSessionActivity()")
		}
	}

	// Store session info in context
	ctx = context.WithValue(ctx, sessioninfo.CtxSessionInfo, sessInfo)

	// Add user to logging context
	l := logger.FromCtx(ctx).
		AddRequestAttribute("username", sessInfo.Username).
		WithAttributes().AddAttribute("username", sessInfo.Username).Logger()

	return logger.NewCtx(ctx, l), nil
}

// Authenticated is the handler reports if the session is authenticated
func (s *BaseSession) Authenticated() http.HandlerFunc {
	type response struct {
		Authenticated bool   `json:"authenticated"`
		Username      string `json:"username"`
	}

	return s.Handle(func(w http.ResponseWriter, r *http.Request) error {
		ctx, span := ccc.StartTrace(r.Context())
		defer span.End()

		ctx, err := s.ValidateSessionAPI(ctx)
		if err != nil {
			if httpio.HasUnauthorized(err) {
				return httpio.NewEncoder(w).Ok(response{})
			}

			return httpio.NewEncoder(w).ClientMessage(ctx, err)
		}

		sessInfo := sessioninfo.FromCtx(ctx)

		// set response values
		res := response{
			Authenticated: true,
			Username:      sessInfo.Username,
		}

		return httpio.NewEncoder(w).Ok(res)
	})
}

// Logout destroys the current session
func (s *BaseSession) Logout() http.HandlerFunc {
	return s.Handle(func(w http.ResponseWriter, r *http.Request) error {
		ctx, span := ccc.StartTrace(r.Context())
		defer span.End()

		// Destroy session in database
		if err := s.Storage.DestroySession(ctx, sessioninfo.IDFromCtx(ctx)); err != nil {
			return httpio.NewEncoder(w).ClientMessage(ctx, err)
		}

		return httpio.NewEncoder(w).Ok(nil)
	})
}

// SetXSRFToken sets the XSRF Token
func (s *BaseSession) SetXSRFToken(next http.Handler) http.Handler {
	return s.Handle(func(w http.ResponseWriter, r *http.Request) error {
		set, err := s.CookieHandler.RefreshXSRFTokenCookie(w, r, sessioninfo.IDFromRequest(r), types.XSRFCookieLife)
		if err != nil {
			return httpio.NewEncoder(w).ClientMessage(r.Context(), err)
		}

		if set && !types.SafeMethods.Contain(r.Method) {
			// Cookie was not present and request requires XSRF Token, so
			// redirect request to try again now that the XSRF Token Cookie is set
			http.Redirect(w, r, r.RequestURI, http.StatusTemporaryRedirect)

			return nil
		}

		next.ServeHTTP(w, r)

		return nil
	})
}

// ValidateXSRFToken validates the XSRF Token
func (s *BaseSession) ValidateXSRFToken(next http.Handler) http.Handler {
	return s.Handle(func(w http.ResponseWriter, r *http.Request) error {
		// Validate XSRFToken for non-safe
		if !types.SafeMethods.Contain(r.Method) {
			hasValidXSRFToken, err := s.CookieHandler.HasValidXSRFToken(r)
			if err != nil {
				return httpio.NewEncoder(w).ClientMessage(r.Context(), err)
			}

			if !hasValidXSRFToken {
				// Token validation failed
				return httpio.NewEncoder(w).ClientMessage(r.Context(), httpio.NewForbiddenMessage("invalid XSRF token"))
			}
		}

		next.ServeHTTP(w, r)

		return nil
	})
}
