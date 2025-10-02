package session

import (
	"context"
	"fmt"
	"net/http"
	"net/url"
	"time"

	"github.com/cccteam/ccc"
	"github.com/cccteam/ccc/accesstypes"
	"github.com/cccteam/httpio"
	"github.com/cccteam/logger"
	"github.com/cccteam/session/oidc"
	"github.com/cccteam/session/util"
	"github.com/go-playground/errors/v5"
	"github.com/gorilla/securecookie"
	"go.opentelemetry.io/otel"
)

// OIDCAzureOption defines the interface for functional options used when creating a new OIDCAzureSession.
type OIDCAzureOption interface {
	isOIDCAzureOption()
}

var _ OIDCAzureHandlers = &OIDCAzureSession{}

// OIDCAzureSession implements the OIDCAzureHandlers interface for handling OIDC authentication with Azure.
type OIDCAzureSession struct {
	userManager UserManager
	oidc        oidc.Authenticator
	storage     OIDCAzureSessionStorage
	session
}

// NewOIDCAzure creates a new OIDCAzureSession.
func NewOIDCAzure(
	oidcAuthenticator oidc.Authenticator, oidcSession OIDCAzureSessionStorage, userManager UserManager,
	logHandler LogHandler, secureCookie *securecookie.SecureCookie, sessionTimeout time.Duration,
	options ...OIDCAzureOption,
) *OIDCAzureSession {
	cookieOpts := make([]CookieOption, 0, len(options))
	for _, opt := range options {
		if o, ok := any(opt).(CookieOption); ok {
			cookieOpts = append(cookieOpts, o)
		}
	}

	return &OIDCAzureSession{
		userManager: userManager,
		oidc:        oidcAuthenticator,
		session: session{
			perms:          userManager,
			handle:         logHandler,
			cookieManager:  newCookieClient(secureCookie, cookieOpts...),
			sessionTimeout: sessionTimeout,
			storage:        oidcSession,
		},
		storage: oidcSession,
	}
}

// Login initiates the OIDC login flow by redirecting the user to the authorization URL.
func (o *OIDCAzureSession) Login() http.HandlerFunc {
	return o.handle(func(w http.ResponseWriter, r *http.Request) error {
		ctx, span := otel.Tracer(name).Start(r.Context(), "OIDCAzureSession.Login()")
		defer span.End()

		returnURL := r.URL.Query().Get("returnUrl")
		authCodeURL, err := o.oidc.AuthCodeURL(r.Context(), w, returnURL)
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
		ctx, span := otel.Tracer(name).Start(r.Context(), "OIDCAzureSession.CallbackOIDC()")
		defer span.End()

		claims := &claims{}
		returnURL, oidcSID, err := o.oidc.Verify(ctx, w, r, claims)
		if err != nil {
			http.Redirect(w, r, fmt.Sprintf("%s?message=%s", o.oidc.LoginURL(), url.QueryEscape(httpio.Message(err))), http.StatusFound)

			return errors.Wrap(err, "oidc.Verify()")
		}

		// user is successfully authenticated, start a new session
		sessionID, err := o.startNewSession(ctx, w, claims.Username, oidcSID)
		if err != nil {
			http.Redirect(w, r, fmt.Sprintf("%s?message=%s", o.oidc.LoginURL(), url.QueryEscape("Internal Server Error")), http.StatusFound)

			return errors.Wrap(err, "OIDCAzureSession.startNewSession()")
		}

		// write new XSRF Token Cookie to match the new SessionID
		o.setXSRFTokenCookie(w, r, sessionID, xsrfCookieLife)

		hasRole, err := o.assignUserRoles(ctx, accesstypes.User(claims.Username), claims.Roles)
		if err != nil {
			http.Redirect(w, r, fmt.Sprintf("%s?message=%s", o.oidc.LoginURL(), url.QueryEscape("Internal Server Error")), http.StatusFound)

			return errors.Wrap(err, "OIDCAzureSession.assignUserRoles()")
		}
		if !hasRole {
			err := httpio.NewUnauthorizedMessage("Unauthorized: user has no roles")
			http.Redirect(w, r, fmt.Sprintf("%s?message=%s", o.oidc.LoginURL(), url.QueryEscape(httpio.Message(err))), http.StatusFound)

			return err
		}

		http.Redirect(w, r, returnURL, http.StatusFound)

		return nil
	})
}

// FrontChannelLogout is a handler which destroys the current session for a logout request initiated by the OIDC provider
func (o *OIDCAzureSession) FrontChannelLogout() http.HandlerFunc {
	return o.handle(func(w http.ResponseWriter, r *http.Request) error {
		ctx, span := otel.Tracer(name).Start(r.Context(), "OIDCAzureSession.FrontChannelLogout()")
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
func (o *OIDCAzureSession) assignUserRoles(ctx context.Context, username accesstypes.User, roles []string) (hasRole bool, err error) {
	ctx, span := otel.Tracer(name).Start(ctx, "OIDCAzureSession.assignUserRoles()")
	defer span.End()

	domains, err := o.userManager.Domains(ctx)
	if err != nil {
		return false, errors.Wrap(err, "UserManager.Domains()")
	}

	existingRoles, err := o.userManager.UserRoles(ctx, username, domains...)
	if err != nil {
		return false, errors.Wrap(err, "UserManager.UserRoles()")
	}

	for _, domain := range domains {
		var rolesToAssign []accesstypes.Role
		for _, r := range roles {
			if o.userManager.RoleExists(ctx, domain, accesstypes.Role(r)) {
				rolesToAssign = append(rolesToAssign, accesstypes.Role(r))
			}
		}

		newRoles := util.Exclude(rolesToAssign, existingRoles[domain])
		if len(newRoles) > 0 {
			if err := o.userManager.AddUserRoles(ctx, domain, username, newRoles...); err != nil {
				return false, errors.Wrap(err, "UserManager.AddUserRoles()")
			}
			logger.Ctx(ctx).Infof("User %s assigned to roles %v in domain %s", username, newRoles, domain)
		}

		removeRoles := util.Exclude(existingRoles[domain], rolesToAssign)
		if len(removeRoles) > 0 {
			if err := o.userManager.DeleteUserRoles(ctx, domain, username, removeRoles...); err != nil {
				return false, errors.Wrap(err, "UserManager.DeleteUserRole()")
			}
			logger.Ctx(ctx).Infof("User %s removed from roles %v in domain %s", username, removeRoles, domain)
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
		return ccc.NilUUID, errors.Wrap(err, "OIDCAzureSessionStorage.NewSession()")
	}

	if _, err := o.newAuthCookie(w, false, id); err != nil {
		return ccc.NilUUID, err
	}

	return id, nil
}
