package session

import (
	"context"
	"fmt"
	"net/http"
	"net/url"
	"time"

	"github.com/cccteam/access"
	"github.com/cccteam/ccc"
	"github.com/cccteam/httpio"
	"github.com/cccteam/logger"
	"github.com/cccteam/session/oidc"
	"github.com/cccteam/session/util"
	"github.com/go-playground/errors/v5"
	"github.com/gorilla/securecookie"
	"go.opentelemetry.io/otel"
)

type OIDCAzureSession struct {
	oidc    oidc.Authenticator
	storage OIDCAzureSessionStorage
	session
}

func NewOIDCAzure(
	oidcAuthenticator oidc.Authenticator, oidcSession OIDCAzureSessionStorage, userManager UserManager,
	logHandler LogHandler, secureCookie *securecookie.SecureCookie, sessionTimeout time.Duration,
) *OIDCAzureSession {
	return &OIDCAzureSession{
		oidc: oidcAuthenticator,
		session: session{
			access:         userManager,
			handle:         logHandler,
			cookieManager:  newCookieClient(secureCookie),
			sessionTimeout: sessionTimeout,
			storage:        oidcSession,
		},
		storage: oidcSession,
	}
}

func (o *OIDCAzureSession) Login() http.HandlerFunc {
	return o.handle(func(w http.ResponseWriter, r *http.Request) error {
		ctx, span := otel.Tracer(name).Start(r.Context(), "App.Login()")
		defer span.End()

		returnURL := r.URL.Query().Get("returnUrl")
		authCodeURL, err := o.oidc.AuthCodeURL(w, returnURL)
		if err != nil {
			return httpio.NewEncoder(w).ClientMessage(ctx, err)
		}

		http.Redirect(w, r, authCodeURL, http.StatusFound)

		return nil
	})
}

// CallbackOIDC is the handler for the callback from the OIDC auth provider
func (o *OIDCAzureSession) CallbackOIDC() http.HandlerFunc {
	type claims struct {
		Username string   `json:"preferred_username"`
		Roles    []string `json:"roles"`
	}

	return o.handle(func(w http.ResponseWriter, r *http.Request) error {
		ctx, span := otel.Tracer(name).Start(r.Context(), "App.CallbackOIDC()")
		defer span.End()

		claims := &claims{}
		returnURL, oidcSID, err := o.oidc.Verify(ctx, w, r, claims)
		if err != nil {
			http.Redirect(w, r, fmt.Sprintf("/login?message=%s", url.QueryEscape(httpio.Message(err))), http.StatusFound)

			return errors.Wrap(err, "oidc.Verify")
		}

		// user is successfully authenticated, start a new session
		sessionID, err := o.startNewSession(ctx, w, claims.Username, oidcSID)
		if err != nil {
			http.Redirect(w, r, fmt.Sprintf("/login?message=%s", url.QueryEscape("Internal Server Error")), http.StatusFound)

			return errors.Wrap(err, "app.startNewSession()")
		}

		// write new XSRF Token Cookie to match the new SessionID
		if ok := o.setXSRFTokenCookie(w, r, sessionID, xsrfCookieLife); !ok {
			http.Redirect(w, r, fmt.Sprintf("/login?message=%s", url.QueryEscape("Internal Server Error")), http.StatusFound)

			return errors.New("Failed to set XSRF Token Cookie")
		}

		hasRole, err := o.assignUserRoles(ctx, access.User(claims.Username), claims.Roles)
		if err != nil {
			http.Redirect(w, r, fmt.Sprintf("/login?message=%s", url.QueryEscape("Internal Server Error")), http.StatusFound)

			return errors.Wrap(err, "app.assignUserRoles()")
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

// FrontChannelLogout is a handler which destroys the current session for a logout request initiated by the OIDC provider
func (o *OIDCAzureSession) FrontChannelLogout() http.HandlerFunc {
	return o.handle(func(w http.ResponseWriter, r *http.Request) error {
		ctx, span := otel.Tracer(name).Start(r.Context(), "App.FrontChannelLogout()")
		defer span.End()

		sid := r.URL.Query().Get("sid")
		if sid == "" {
			return httpio.NewEncoder(w).BadRequestMessage(ctx, "missing sid query parameter")
		}

		if err := o.storage.DestroySessionOIDC(ctx, sid); err != nil {
			logger.Req(r).Error("failed to destroy session in db via OIDC sid")
		}

		return httpio.NewEncoder(w).Ok(nil)
	})
}

// assignUserRoles ensures that the user is assigned to the specified roles ONLY
// returns true if the user has at least one assigned role (after the operation is complete)
func (o *OIDCAzureSession) assignUserRoles(ctx context.Context, username access.User, roles []string) (hasRole bool, err error) {
	ctx, span := otel.Tracer(name).Start(ctx, "App.assignUserRoles()")
	defer span.End()

	domains, err := o.access.Domains(ctx)
	if err != nil {
		return false, errors.Wrap(err, "UserManager.Domains()")
	}

	existingRoles, err := o.access.UserRoles(ctx, username, domains...)
	if err != nil {
		return false, errors.Wrap(err, "UserManager.UserRoles()")
	}

	for _, domain := range domains {
		var rolesToAssign []access.Role
		for _, r := range roles {
			if o.access.RoleExists(ctx, access.Role(r), domain) {
				rolesToAssign = append(rolesToAssign, access.Role(r))
			}
		}

		newRoles := util.Exclude(rolesToAssign, existingRoles[domain])
		if len(newRoles) > 0 {
			if err := o.access.AddUserRoles(ctx, username, newRoles, domain); err != nil {
				return false, errors.Wrap(err, "UserManager.AddUserRoles()")
			}
		}

		removeRoles := util.Exclude(existingRoles[domain], rolesToAssign)
		for _, r := range removeRoles {
			if err := o.access.DeleteUserRole(ctx, username, r, domain); err != nil {
				return false, errors.Wrap(err, "UserManager.DeleteUserRole()")
			}
		}

		hasRole = hasRole || len(rolesToAssign) > 0
	}

	return hasRole, nil
}

// startNewSession starts a new session for the given username and returns the session ID
func (o *OIDCAzureSession) startNewSession(ctx context.Context, w http.ResponseWriter, username, oidcSID string) (ccc.UUID, error) {
	// Create new Session in database
	id, err := o.storage.NewSession(ctx, username, oidcSID)
	if err != nil {
		return ccc.NilUUID, errors.Wrap(err, "users.NewSession()")
	}

	if _, err := o.newAuthCookie(w, false, id); err != nil {
		return ccc.NilUUID, err
	}

	return id, nil
}
