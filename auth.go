package session

import (
	"net/http"
	"time"

	"github.com/cccteam/ccc"
	"github.com/cccteam/ccc/accesstypes"
	"github.com/cccteam/httpio"
	"github.com/cccteam/logger"
	"github.com/cccteam/session/sessioninfo"
	"go.opentelemetry.io/otel"
)

// stxKey is a type for storing values in the request context
type ctxKey string

const (
	// Keys used within the request Context
	ctxSessionID                 ctxKey = "sessionID"
	ctxSessionExpirationDuration ctxKey = "sessionExpirationDuration"
)

// Authenticated is the handler reports if the session is authenticated
func (s *session) Authenticated() http.HandlerFunc {
	type response struct {
		Authenticated bool                                 `json:"authenticated"`
		Username      string                               `json:"username"`
		Permissions   accesstypes.UserPermissionCollection `json:"permissions"`
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

		permissions, err := s.access.UserPermissions(ctx, accesstypes.User(sessInfo.Username))
		if err != nil {
			return httpio.NewEncoder(w).ClientMessage(ctx, err)
		}

		// set response values
		res := response{
			Authenticated: true,
			Username:      sessInfo.Username,
			Permissions:   permissions,
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

func sessionExpirationFromRequest(r *http.Request) time.Duration {
	d, ok := r.Context().Value(ctxSessionExpirationDuration).(time.Duration)
	if !ok {
		logger.Req(r).Errorf("failed to find %s in request context", ctxSessionExpirationDuration)
	}

	return d
}
