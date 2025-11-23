package session

import (
	"context"
	"fmt"
	"net/http"
	"net/url"

	"github.com/cccteam/ccc"
	"github.com/cccteam/ccc/accesstypes"
	"github.com/cccteam/httpio"
	"github.com/cccteam/logger"
	"github.com/cccteam/session/internal/azureoidc"
	"github.com/cccteam/session/internal/basesession"
	"github.com/cccteam/session/internal/cookie"
	"github.com/cccteam/session/internal/types"
	"github.com/cccteam/session/internal/util"
	"github.com/cccteam/session/sessionstorage"
	"github.com/go-playground/errors/v5"
	"github.com/gorilla/securecookie"
)

// OIDCAzureOption defines the interface for functional options used when creating a new OIDCAzure.
type OIDCAzureOption interface {
	isOIDCAzureOption()
}

var _ OIDCAzureHandlers = &OIDCAzure{}

// OIDCAzure implements the OIDCAzureHandlers interface for handling OIDC authentication with Azure.
type OIDCAzure struct {
	userRoleManager UserRoleManager
	oidc            azureoidc.Authenticator
	storage         sessionstorage.OIDCImplementation
	*basesession.BaseSession
}

// NewOIDCAzure creates a new OIDCAzure.
func NewOIDCAzure(
	storage sessionstorage.OIDCImplementation, userRoleManager UserRoleManager,
	secureCookie *securecookie.SecureCookie,
	issuerURL, clientID, clientSecret, redirectURL string,
	options ...OIDCAzureOption,
) *OIDCAzure {
	oidc := azureoidc.New(secureCookie, issuerURL, clientID, clientSecret, redirectURL)
	cookieClient := cookie.NewCookieClient(secureCookie)
	baseSession := &basesession.BaseSession{
		Handle:         httpio.Log,
		CookieHandler:  cookieClient,
		SessionTimeout: defaultSessionTimeout,
		Storage:        storage,
	}

	for _, opt := range options {
		switch o := any(opt).(type) {
		case CookieOption:
			o(cookieClient)
		case BaseSessionOption:
			o(baseSession)
		case OIDCOption:
			o(oidc)
		}
	}

	return &OIDCAzure{
		userRoleManager: userRoleManager,
		oidc:            oidc,
		BaseSession:     baseSession,
		storage:         storage,
	}
}

// Login initiates the OIDC login flow by redirecting the user to the authorization URL.
func (o *OIDCAzure) Login() http.HandlerFunc {
	return o.Handle(func(w http.ResponseWriter, r *http.Request) error {
		ctx, span := ccc.StartTrace(r.Context())
		defer span.End()

		returnURL := r.URL.Query().Get("returnUrl")
		authCodeURL, err := o.oidc.AuthCodeURL(ctx, w, returnURL)
		if err != nil {
			return httpio.NewEncoder(w).ClientMessage(ctx, err)
		}

		http.Redirect(w, r, authCodeURL, http.StatusFound)

		return nil
	})
}

// CallbackOIDC is the handler for the callback from the OIDC auth provider
func (o *OIDCAzure) CallbackOIDC() http.HandlerFunc {
	type claims struct {
		Username string   `json:"preferred_username"`
		Roles    []string `json:"roles"`
	}

	return o.Handle(func(w http.ResponseWriter, r *http.Request) error {
		ctx, span := ccc.StartTrace(r.Context())
		defer span.End()

		claims := &claims{}
		returnURL, oidcSID, err := o.oidc.Verify(ctx, w, r, claims)
		if err != nil {
			http.Redirect(w, r, fmt.Sprintf("%s?message=%s", o.oidc.LoginURL(), url.QueryEscape(httpio.Message(err))), http.StatusFound)

			return errors.Wrap(err, "oidc.Verify()")
		}

		// user is successfully authenticated, start a new session
		sessionID, err := o.startNewSession(ctx, w, r, claims.Username, oidcSID)
		if err != nil {
			http.Redirect(w, r, fmt.Sprintf("%s?message=%s", o.oidc.LoginURL(), url.QueryEscape("Internal Server Error")), http.StatusFound)

			return errors.Wrap(err, "OIDCAzureSession.startNewSession()")
		}

		// Log the association between the sessionID and Username
		logger.Ctx(ctx).AddRequestAttribute("Username", claims.Username).AddRequestAttribute(string(types.SCSessionID), sessionID)

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
func (o *OIDCAzure) FrontChannelLogout() http.HandlerFunc {
	return o.Handle(func(w http.ResponseWriter, r *http.Request) error {
		ctx, span := ccc.StartTrace(r.Context())
		defer span.End()

		sid := r.URL.Query().Get("sid")
		if sid == "" {
			return httpio.NewEncoder(w).BadRequestMessage(ctx, "missing sid query parameter")
		}

		if err := o.storage.DestroySessionOIDC(ctx, sid); err != nil {
			logger.Req(r).Error(errors.Wrap(err, "failed to destroy session in db via OIDC sid"))
		}

		return httpio.NewEncoder(w).Ok(nil)
	})
}

// assignUserRoles ensures that the user is assigned to the specified roles ONLY
// returns true if the user has at least one assigned role (after the operation is complete)
func (o *OIDCAzure) assignUserRoles(ctx context.Context, username accesstypes.User, roles []string) (hasRole bool, err error) {
	ctx, span := ccc.StartTrace(ctx)
	defer span.End()

	domains, err := o.userRoleManager.Domains(ctx)
	if err != nil {
		return false, errors.Wrap(err, "UserManager.Domains()")
	}

	existingRoles, err := o.userRoleManager.UserRoles(ctx, username, domains...)
	if err != nil {
		return false, errors.Wrap(err, "UserManager.UserRoles()")
	}

	for _, domain := range domains {
		var rolesToAssign []accesstypes.Role
		for _, r := range roles {
			if o.userRoleManager.RoleExists(ctx, domain, accesstypes.Role(r)) {
				rolesToAssign = append(rolesToAssign, accesstypes.Role(r))
			}
		}

		newRoles := util.Exclude(rolesToAssign, existingRoles[domain])
		if len(newRoles) > 0 {
			if err := o.userRoleManager.AddUserRoles(ctx, domain, username, newRoles...); err != nil {
				return false, errors.Wrap(err, "UserManager.AddUserRoles()")
			}
			logger.Ctx(ctx).Infof("User %s assigned to roles %v in domain %s", username, newRoles, domain)
		}

		removeRoles := util.Exclude(existingRoles[domain], rolesToAssign)
		if len(removeRoles) > 0 {
			if err := o.userRoleManager.DeleteUserRoles(ctx, domain, username, removeRoles...); err != nil {
				return false, errors.Wrap(err, "UserManager.DeleteUserRole()")
			}
			logger.Ctx(ctx).Infof("User %s removed from roles %v in domain %s", username, removeRoles, domain)
		}

		hasRole = hasRole || len(rolesToAssign) > 0
	}

	return hasRole, nil
}

// startNewSession starts a new session for the given username and returns the session ID
func (o *OIDCAzure) startNewSession(ctx context.Context, w http.ResponseWriter, r *http.Request, username, oidcSID string) (ccc.UUID, error) {
	// Create new Session in database
	id, err := o.storage.NewSession(ctx, username, oidcSID)
	if err != nil {
		return ccc.NilUUID, errors.Wrap(err, "OIDCAzureSessionStorage.NewSession()")
	}

	if _, err := o.NewAuthCookie(w, false, id); err != nil {
		return ccc.NilUUID, errors.Wrap(err, "OIDCAzureSession.NewAuthCookie()")
	}

	// write new XSRF Token Cookie to match the new SessionID
	o.SetXSRFTokenCookie(w, r, id, types.XSRFCookieLife)

	return id, nil
}
