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
	Storage        sessionstorage.Base
	cookie.CookieHandler
}

// StartSession initializes a session by restoring it from a cookie, or if
// that failes, initializing a new session. The session cookie is then updated and
// the sessionID is inserted into the context.
func (s *BaseSession) StartSession(next http.Handler) http.Handler {
	return s.Handle(func(w http.ResponseWriter, r *http.Request) error {
		ctx, span := ccc.StartTrace(r.Context())
		defer span.End()

		// Read Auth Cookie
		cval, foundAuthCookie := s.ReadAuthCookie(r)
		sessionID, validSessionID := types.ValidSessionID(cval[types.SCSessionID])
		if !foundAuthCookie || !validSessionID {
			var err error
			sessionID, err = ccc.NewUUID()
			if err != nil {
				return httpio.NewEncoder(w).ClientMessage(ctx, err)
			}
			cval, err = s.NewAuthCookie(w, true, sessionID)
			if err != nil {
				return httpio.NewEncoder(w).ClientMessage(ctx, err)
			}
		}

		// Upgrade cookie to SameSite=Strict
		// since CallbackOIDC() sets it to None to allow OAuth flow to work
		if cval[types.SCSameSiteStrict] != strconv.FormatBool(true) {
			if err := s.WriteAuthCookie(w, true, cval); err != nil {
				return httpio.NewEncoder(w).ClientMessage(ctx, err)
			}
		}

		// Store sessionID in context
		ctx = context.WithValue(ctx, types.CTXSessionID, sessionID)

		// Add session ID to logging context
		logger.Req(r).AddRequestAttribute("session ID", cval[types.SCSessionID])
		l := logger.Req(r).WithAttributes().AddAttribute("session ID", cval[types.SCSessionID]).Logger()
		ctx = logger.NewCtx(ctx, l)

		next.ServeHTTP(w, r.WithContext(ctx))

		return nil
	})
}

// ValidateSession checks the sessionID in the database to validate that it has not expired
// and updates the last activity timestamp if it is still valid.
// StartSession handler must be called before calling ValidateSession
func (s *BaseSession) ValidateSession(next http.Handler) http.Handler {
	return s.Handle(func(w http.ResponseWriter, r *http.Request) error {
		ctx, span := ccc.StartTrace(r.Context())
		defer span.End()

		r, err := s.checkSession(r)
		if err != nil {
			return httpio.NewEncoder(w).ClientMessage(ctx, err)
		}

		next.ServeHTTP(w, r)

		return nil
	})
}

func (s *BaseSession) checkSession(r *http.Request) (req *http.Request, err error) {
	ctx, span := ccc.StartTrace(r.Context())
	defer span.End()

	// Validate that the sessionID is in database
	sessInfo, err := s.Storage.Session(ctx, types.SessionIDFromCtx(ctx))
	if err != nil {
		return r.WithContext(ctx), httpio.NewUnauthorizedMessageWithError(err, "invalid session")
	}

	// Check for expiration
	if sessInfo.Expired || time.Since(sessInfo.UpdatedAt) > s.SessionTimeout {
		return r.WithContext(ctx), httpio.NewUnauthorizedMessage("session expired")
	}

	// Update Activity
	if err := s.Storage.UpdateSessionActivity(ctx, sessInfo.ID); err != nil {
		return r.WithContext(ctx), errors.Wrap(err, "storageManager.UpdateSessionActivity()")
	}

	// Store session info in context
	ctx = context.WithValue(ctx, sessioninfo.CtxSessionInfo, sessInfo)

	// Add user to logging context
	logger.Req(r).AddRequestAttribute("username", sessInfo.Username)
	l := logger.Req(r).WithAttributes().AddAttribute("username", sessInfo.Username).Logger()
	ctx = logger.NewCtx(ctx, l)

	return r.WithContext(ctx), nil
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
func (s *BaseSession) Logout() http.HandlerFunc {
	return s.Handle(func(w http.ResponseWriter, r *http.Request) error {
		ctx, span := ccc.StartTrace(r.Context())
		defer span.End()

		// Destroy session in database
		if err := s.Storage.DestroySession(ctx, types.SessionIDFromCtx(ctx)); err != nil {
			return httpio.NewEncoder(w).ClientMessage(ctx, err)
		}

		return httpio.NewEncoder(w).Ok(nil)
	})
}

// SetXSRFToken sets the XSRF Token
func (s *BaseSession) SetXSRFToken(next http.Handler) http.Handler {
	return s.Handle(func(w http.ResponseWriter, r *http.Request) error {
		if s.SetXSRFTokenCookie(w, r, types.SessionIDFromRequest(r), types.XSRFCookieLife) && !types.SafeMethods.Contain(r.Method) {
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
		if !types.SafeMethods.Contain(r.Method) && !s.HasValidXSRFToken(r) {
			// Token validation failed
			return httpio.NewEncoder(w).ClientMessage(r.Context(), httpio.NewForbiddenMessage("invalid XSRF token"))
		}

		next.ServeHTTP(w, r)

		return nil
	})
}
