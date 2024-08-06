package session

import (
	"context"
	"net/http"
	"time"

	"github.com/cccteam/httpio"
	"github.com/cccteam/logger"
	"github.com/gofrs/uuid"
	"github.com/pkg/errors"
	"go.opentelemetry.io/otel"

	"session/access"
	"session/dbx"
)

type (
	ctxKey string
)

const (
	// Keys used within the request Context
	ctxSessionID                 ctxKey = "sessionID"
	ctxSessionInfo               ctxKey = "sessionInfo"
	ctxSessionExpirationDuration ctxKey = "sessionExpirationDuration"
)

// Authenticated is the handler reports if the session is authenticated
func (s *session) Authenticated() http.HandlerFunc {
	type response struct {
		Authenticated bool                                  `json:"authenticated"`
		Username      string                                `json:"username"`
		Permissions   map[access.Domain][]access.Permission `json:"permissions"`
	}

	return s.Handle(func(w http.ResponseWriter, r *http.Request) error {
		ctx, span := otel.Tracer(s.appName).Start(r.Context(), "session.Authenticated()")
		defer span.End()

		r, err := s.check(r.WithContext(ctx))
		if err != nil {
			if httpio.HasUnauthorized(err) {
				return httpio.NewEncoder(w).Ok(response{})
			}

			return httpio.NewEncoder(w).ClientMessage(ctx, err)
		}

		sessInfo := sessionInfoFromRequest(r)

		// set response values
		res := response{
			Authenticated: true,
			Username:      sessInfo.Username,
			Permissions:   sessInfo.Permissions,
		}

		return httpio.NewEncoder(w).Ok(res)
	})
}

func (s *session) Login() http.HandlerFunc {
	return s.Handle(func(w http.ResponseWriter, r *http.Request) error {
		ctx, span := otel.Tracer(s.appName).Start(r.Context(), "session.Login()")
		defer span.End()

		returnURL := r.URL.Query().Get("returnUrl")
		authCodeURL, err := s.oidc.AuthCodeURL(w, returnURL)
		if err != nil {
			return httpio.NewEncoder(w).ClientMessage(ctx, err)
		}

		http.Redirect(w, r, authCodeURL, http.StatusFound)

		return nil
	})
}

// Logout is a handler which destroys the current session
func (s *session) Logout() http.HandlerFunc {
	return s.Handle(func(w http.ResponseWriter, r *http.Request) error {
		ctx, span := otel.Tracer(s.appName).Start(r.Context(), "session.Logout()")
		defer span.End()

		// Destroy session in database
		if err := s.storage.DestroySession(ctx, sessionIDFromRequest(r)); err != nil {
			return httpio.NewEncoder(w).ClientMessage(ctx, err)
		}

		return httpio.NewEncoder(w).Ok(nil)
	})
}

// sessionIDFromRequest extracts the Session ID from the Request Context
func sessionIDFromRequest(r *http.Request) string {
	id, ok := r.Context().Value(ctxSessionID).(string)
	if !ok {
		logger.Req(r).Errorf("failed to find %s in request context", ctxSessionID)
	}

	return id
}

// sessionInfoFromRequest extracts session information from the Request Context
func sessionInfoFromRequest(r *http.Request) *access.SessionInfo {
	sessionInfo, ok := r.Context().Value(ctxSessionInfo).(*access.SessionInfo)
	if !ok {
		logger.Req(r).Errorf("failed to find %s in request context", ctxSessionInfo)
	}

	return sessionInfo
}

// sessionExpirationFromRequest extracts the session timeout from the Request Context
func sessionExpirationFromRequest(r *http.Request) time.Duration {
	d, ok := r.Context().Value(ctxSessionExpirationDuration).(time.Duration)
	if !ok {
		logger.Req(r).Errorf("failed to find %s in request context", ctxSessionExpirationDuration)
	}

	return d
}

// StartNew starts a new session for the given username and returns the session ID
func (s *session) StartNew(ctx context.Context, w http.ResponseWriter, username, oidcSID string) (string, error) {
	cookieValue, err := s.newAuthCookie(w, false, uuid.NewV4)
	if err != nil {
		return "", err
	}

	dbSess := &dbx.SessionInfo{
		ID:        cookieValue[scSessionID],
		OidcSID:   oidcSID,
		Username:  username,
		CreatedAt: time.Now(),
		UpdatedAt: time.Now(),
	}

	// Create new Session in database
	sessInfo, err := s.storage.NewSession(ctx, dbSess) //TODO: this isn't really hooked up to anything but an interface that we don't even have an implementation struct of. Swap it with a real sessionManager
	if err != nil {
		return "", errors.Wrap(err, "users.NewSession()")
	}

	return sessInfo.ID, nil
}
