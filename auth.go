package session

import (
	"context"
	"fmt"
	"net/http"
	"net/url"
	"time"

	"github.com/cccteam/httpio"
	"github.com/cccteam/logger"
	"github.com/gofrs/uuid"
	"github.com/pkg/errors"
	"go.opentelemetry.io/otel"

	"session/dbx"
	"session/users"
	"session/util"
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
func (s *Session) Authenticated() http.HandlerFunc {
	type response struct {
		Authenticated bool                                `json:"authenticated"`
		Username      string                              `json:"username"`
		Permissions   map[users.Domain][]users.Permission `json:"permissions"`
	}

	return s.handle(func(w http.ResponseWriter, r *http.Request) error {
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

func (s *Session) Login() http.HandlerFunc {
	return s.handle(func(w http.ResponseWriter, r *http.Request) error {
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

// CallbackOIDC is the handler for the callback from the OIDC auth provider
func (s *Session) CallbackOIDC() http.HandlerFunc {
	type claims struct {
		Username string   `json:"preferred_username"`
		Roles    []string `json:"roles"`
	}

	return s.handle(func(w http.ResponseWriter, r *http.Request) error {
		ctx, span := otel.Tracer(s.appName).Start(r.Context(), "session.CallbackOIDC()")
		defer span.End()

		claims := &claims{}
		returnURL, oidcSID, err := s.oidc.Verify(ctx, w, r, claims)
		if err != nil {
			http.Redirect(w, r, fmt.Sprintf("/login?message=%s", url.QueryEscape(httpio.Message(err))), http.StatusFound)

			return errors.Wrap(err, "oidc.Verify")
		}

		// user is successfully authenticated, start a new session
		sessionID, err := s.startNew(ctx, w, claims.Username, oidcSID)
		if err != nil {
			http.Redirect(w, r, fmt.Sprintf("/login?message=%s", url.QueryEscape("Internal Server Error")), http.StatusFound)

			return errors.Wrap(err, "session.startNewSession()")
		}

		// write new XSRF Token Cookie to match the new SessionID
		if ok := s.setXSRFTokenCookie(w, r, sessionID, xsrfCookieLife); !ok {
			http.Redirect(w, r, fmt.Sprintf("/login?message=%s", url.QueryEscape("Internal Server Error")), http.StatusFound)

			return errors.New("Failed to set XSRF Token Cookie")
		}

		hasRole, err := s.assignUserRoles(ctx, users.User(claims.Username), claims.Roles)
		if err != nil {
			http.Redirect(w, r, fmt.Sprintf("/login?message=%s", url.QueryEscape("Internal Server Error")), http.StatusFound)

			return errors.Wrap(err, "session.assignUserRoles()")
		}
		if !hasRole {
			err := httpio.NewUnauthorizedMessage("Unauthorized: user has no roles")
			http.Redirect(w, r, fmt.Sprintf("/login?message=%s", url.QueryEscape(httpio.Message(err))), http.StatusFound)

			return err
		}

		http.Redirect(w, r, returnURL, http.StatusFound)

		return nil
	})
}

// Logout is a handler which destroys the current session
func (s *Session) Logout() http.HandlerFunc {
	return s.handle(func(w http.ResponseWriter, r *http.Request) error {
		ctx, span := otel.Tracer(s.appName).Start(r.Context(), "session.Logout()")
		defer span.End()

		// Destroy session in database
		if err := s.userClient.DestroySession(ctx, sessionIDFromRequest(r)); err != nil {
			return httpio.NewEncoder(w).ClientMessage(ctx, err)
		}

		return httpio.NewEncoder(w).Ok(nil)
	})
}

// FrontChannelLogout is a handler which destroys the current session for a logout request initiated by the OIDC provider
func (s *Session) FrontChannelLogout() http.HandlerFunc {
	return s.handle(func(w http.ResponseWriter, r *http.Request) error {
		ctx, span := otel.Tracer(s.appName).Start(r.Context(), "session.FrontChannelLogout()")
		defer span.End()

		sid := r.URL.Query().Get("sid")
		if sid == "" {
			return httpio.NewEncoder(w).BadRequestMessage(ctx, "missing sid query parameter")
		}

		if err := s.userClient.DestroySessionOIDC(ctx, sid); err != nil {
			logger.Req(r).Error("failed to destroy session in db via OIDC sid")
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
func sessionInfoFromRequest(r *http.Request) *users.SessionInfo {
	sessionInfo, ok := r.Context().Value(ctxSessionInfo).(*users.SessionInfo)
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

// startNew starts a new session for the given username and returns the session ID
func (s *Session) startNew(ctx context.Context, w http.ResponseWriter, username, oidcSID string) (string, error) {
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
	sessInfo, err := s.userClient.NewSession(ctx, dbSess)
	if err != nil {
		return "", errors.Wrap(err, "users.NewSession()")
	}

	return sessInfo.ID, nil
}

// assignUserRoles ensures that the user is assigned to the specified roles ONLY
// returns true if the user has at least one assigned role (after the operation is complete)
func (s *Session) assignUserRoles(ctx context.Context, username users.User, roles []string) (hasRole bool, err error) {
	ctx, span := otel.Tracer(s.appName).Start(ctx, "session.assignUserRoles()")
	defer span.End()

	domains, err := s.userClient.Domains(ctx)
	if err != nil {
		return false, errors.Wrap(err, "UserManager.Domains()")
	}

	existingRoles, err := s.userClient.UserRoles(ctx, username, domains...)
	if err != nil {
		return false, errors.Wrap(err, "UserManager.UserRoles()")
	}

	for _, domain := range domains {
		var rolesToAssign []users.Role
		for _, r := range roles {
			if s.userClient.RoleExists(ctx, users.Role(r), domain) {
				rolesToAssign = append(rolesToAssign, users.Role(r))
			}
		}

		newRoles := util.Exclude(rolesToAssign, existingRoles[domain])
		if len(newRoles) > 0 {
			if err := s.userClient.AddUserRoles(ctx, username, newRoles, domain); err != nil {
				return false, errors.Wrap(err, "UserManager.AddUserRoles()")
			}
		}

		removeRoles := util.Exclude(existingRoles[domain], rolesToAssign)
		for _, r := range removeRoles {
			if err := s.userClient.DeleteUserRole(ctx, username, r, domain); err != nil {
				return false, errors.Wrap(err, "UserManager.DeleteUserRole()")
			}
		}

		hasRole = hasRole || len(rolesToAssign) > 0
	}

	return hasRole, nil
}
