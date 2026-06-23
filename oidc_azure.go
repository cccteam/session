package session

import (
	"context"
	"fmt"
	"net/http"
	"net/url"

	"github.com/cccteam/ccc"
	"github.com/cccteam/ccc/accesstypes"
	"github.com/cccteam/ccc/tracer"
	"github.com/cccteam/httpio"
	"github.com/cccteam/logger"
	"github.com/cccteam/session/cookie"
	"github.com/cccteam/session/internal/azureoidc"
	"github.com/cccteam/session/internal/basesession"
	internalcookie "github.com/cccteam/session/internal/cookie"
	"github.com/cccteam/session/internal/util"
	"github.com/cccteam/session/sessionstorage"
	"github.com/go-playground/errors/v5"
)

// OIDCAzureOption defines the interface for functional options used when creating a new OIDCAzure.
type OIDCAzureOption interface {
	isOIDCAzureOption()
}

var _ OIDCAzureHandlers = &OIDCAzure{}

// OIDCAzure implements the OIDCAzureHandlers interface for handling OIDC authentication with Azure.
//
// Role synchronization: the OIDC callback provides an integrated authentication and
// role-synchronization flow designed for organizations that manage users and roles
// centrally through Active Directory group/app-role assignments, avoiding the need
// for a separate Admin UI. On every login the callback reconciles the user's roles to
// the token's role claims: roles named in the token are assigned (where a role of
// that name exists), and any role the user currently holds that is NOT in the token
// is removed. The login is rejected as Unauthorized unless the token yields at least
// one recognized role.
//
// DESIGN LIMITATION — role synchronization is domain-blind (global): the token's
// roles are applied identically in every domain/tenant where the role name exists.
//
// Use this flow when:
//   - the application is single-tenant, or
//   - the application is multi-tenant but a user's roles should apply uniformly
//     across all tenants.
//
// Do NOT rely on this flow's role synchronization when strict multi-tenancy is
// required (different roles per domain, e.g. Admin in tenant A but Viewer in tenant
// B). Encoding tenancy into AD groups (Admin_TenantA, …) leads to an unmaintainable
// explosion of groups; per-domain roles should instead be managed inside the
// application, with OIDC role synchronization disabled.
//
// Because the reconciliation removes roles absent from the token, application-side
// role assignment cannot coexist with this flow — any manually assigned role would be
// silently reverted at the user's next login. Role management must be either
// IdP-driven (this flow) or application-driven, never both for the same app.
//
// DisabledUserRoleManager disables the persistence half of the synchronization (no
// roles are written or removed), but the login gate above still requires at least one
// role claim in the token. A configuration option to fully disable role maintenance
// during login (for application-managed roles) is planned but not yet implemented.
type OIDCAzure struct {
	userRoleManager UserRoleManager
	oidc            azureoidc.Authenticator
	storage         sessionstorage.OIDCStore
	baseSession     *basesession.BaseSession
	onAuthenticated OnAuthenticatedFunc
}

// Claims contains the verified OIDC ID-token claims captured during the callback.
type Claims struct {
	Username string   `json:"preferred_username"`
	Oid      string   `json:"oid"`
	Name     string   `json:"name"`
	Email    string   `json:"email"`
	Roles    []string `json:"roles"`
}

// OnAuthenticatedFunc is an informational callback invoked after a successful login, once the
// session has been initialized, with the session ID and the verified claims. It cannot affect
// the login.
type OnAuthenticatedFunc func(ctx context.Context, sessionID ccc.UUID, claims Claims)

// NewOIDCAzure creates a new OIDCAzure.
// cookieKey: A Base64-encoded string representing at least 32 bytes
// of cryptographically secure random data.
func NewOIDCAzure(
	storage sessionstorage.OIDCStore, userRoleManager UserRoleManager,
	cookieKey string,
	issuerURL, clientID, clientSecret, redirectURL string,
	options ...OIDCAzureOption,
) (*OIDCAzure, error) {
	var cookieOpts []internalcookie.Option
	for _, opt := range options {
		if o, ok := opt.(CookieOption); ok {
			cookieOpts = append(cookieOpts, internalcookie.Option(o))
		}
	}

	cookieClient, err := internalcookie.NewCookieClient(cookieKey, cookieOpts...)
	if err != nil {
		return nil, errors.Wrap(err, "cookie.NewCookieClient()")
	}

	oidc := azureoidc.New(cookieClient, issuerURL, clientID, clientSecret, redirectURL)
	baseSession := &basesession.BaseSession{
		Handle:         httpio.Log,
		CookieHandler:  cookieClient,
		SessionTimeout: defaultSessionTimeout,
		Storage:        storage,
	}

	a := &OIDCAzure{
		userRoleManager: userRoleManager,
		oidc:            oidc,
		baseSession:     baseSession,
		storage:         storage,
	}

	for _, opt := range options {
		switch o := any(opt).(type) {
		case BaseSessionOption:
			o(baseSession)
		case OIDCOption:
			o(oidc)
		case oidcAzureOption:
			o(a)
		}
	}

	return a, nil
}

// Authenticated is the handler reports if the session is authenticated
func (o *OIDCAzure) Authenticated() http.HandlerFunc {
	return o.baseSession.Authenticated()
}

// Logout destroys the current session
func (o *OIDCAzure) Logout() http.HandlerFunc {
	return o.baseSession.Logout()
}

// SetXSRFToken sets the XSRF Token
func (o *OIDCAzure) SetXSRFToken(next http.Handler) http.Handler {
	return o.baseSession.SetXSRFToken(next)
}

// StartSession initializes a session by restoring it from a cookie, or if that fails, initializing
// a new session. The session cookie is then updated and the sessionID is inserted into the context.
func (o *OIDCAzure) StartSession(next http.Handler) http.Handler {
	return o.baseSession.StartSession(next)
}

// ValidateSession checks the sessionID in the database to validate that it has not expired and updates
// the last activity timestamp if it is still valid. StartSession handler must be called before
// calling ValidateSession
func (o *OIDCAzure) ValidateSession(next http.Handler) http.Handler {
	return o.baseSession.ValidateSession(next)
}

// ValidateXSRFToken validates the XSRF Token
func (o *OIDCAzure) ValidateXSRFToken(next http.Handler) http.Handler {
	return o.baseSession.ValidateXSRFToken(next)
}

// Login initiates the OIDC login flow by redirecting the user to the authorization URL.
func (o *OIDCAzure) Login() http.HandlerFunc {
	return o.baseSession.Handle(func(w http.ResponseWriter, r *http.Request) error {
		ctx, span := tracer.Start(r.Context())
		defer span.End()

		returnURL := r.URL.Query().Get("returnUrl")
		authCodeURL, err := o.oidc.AuthCodeURL(ctx, w, returnURL)
		if err != nil {
			http.Redirect(w, r, fmt.Sprintf("%s?message=%s", o.oidc.LoginURL(), url.QueryEscape("Internal Server Error")), http.StatusFound)

			return errors.Wrap(err, "azureoidc.Authenticator.AuthCodeURL()")
		}

		http.Redirect(w, r, authCodeURL, http.StatusFound)

		return nil
	})
}

// CallbackOIDC is the handler for the callback from the OIDC auth provider.
//
// Besides completing authentication, it reconciles the user's roles to the token's
// role claims and rejects logins that yield no recognized role — see the OIDCAzure
// type documentation for the role-synchronization semantics and their multi-tenancy
// limitations.
func (o *OIDCAzure) CallbackOIDC() http.HandlerFunc {
	return o.baseSession.Handle(func(w http.ResponseWriter, r *http.Request) error {
		ctx, span := tracer.Start(r.Context())
		defer span.End()

		claims := &Claims{}
		returnURL, oidcSID, err := o.oidc.Verify(ctx, w, r, claims)
		if err != nil {
			http.Redirect(w, r, fmt.Sprintf("%s?message=%s", o.oidc.LoginURL(), url.QueryEscape(httpio.Message(err))), http.StatusFound)

			return errors.Wrap(err, "azureoidc.Authenticator.Verify()")
		}

		// user is successfully authenticated, start a new session
		sessionID, err := o.startNewSession(ctx, w, claims.Username, oidcSID)
		if err != nil {
			http.Redirect(w, r, fmt.Sprintf("%s?message=%s", o.oidc.LoginURL(), url.QueryEscape("Internal Server Error")), http.StatusFound)

			return errors.Wrap(err, "OIDCAzure.startNewSession()")
		}

		// Log the association between the sessionID and Username
		logger.FromCtx(ctx).AddRequestAttribute("Username", claims.Username).AddRequestAttribute(string(internalcookie.SessionID), sessionID)

		hasRole, err := o.assignUserRoles(ctx, accesstypes.User(claims.Username), claims.Roles)
		if err != nil {
			http.Redirect(w, r, fmt.Sprintf("%s?message=%s", o.oidc.LoginURL(), url.QueryEscape("Internal Server Error")), http.StatusFound)

			return errors.Wrap(err, "OIDCAzure.assignUserRoles()")
		}
		if !hasRole {
			err := httpio.NewUnauthorizedMessage("Unauthorized: user has no roles")
			http.Redirect(w, r, fmt.Sprintf("%s?message=%s", o.oidc.LoginURL(), url.QueryEscape(httpio.Message(err))), http.StatusFound)

			return err
		}

		// Notify the consumer of the verified claims. This is informational and does not affect login.
		if o.onAuthenticated != nil {
			o.onAuthenticated(ctx, sessionID, *claims)
		}

		http.Redirect(w, r, returnURL, http.StatusFound)

		return nil
	})
}

// FrontChannelLogout is a handler which destroys the current session for a logout request initiated by the OIDC provider
func (o *OIDCAzure) FrontChannelLogout() http.HandlerFunc {
	return o.baseSession.Handle(func(w http.ResponseWriter, r *http.Request) error {
		ctx, span := tracer.Start(r.Context())
		defer span.End()

		sid := r.URL.Query().Get("sid")
		if sid == "" {
			return httpio.NewEncoder(w).BadRequestMessage(ctx, "missing sid query parameter")
		}

		if err := o.storage.DestroySessionOIDC(ctx, sid); err != nil {
			logger.FromReq(r).Info(errors.Wrap(err, "sessionstorage.OIDCStore.DestroySessionOIDC()"))
		}

		return httpio.NewEncoder(w).Ok(nil)
	})
}

// assignUserRoles ensures that the user is assigned to the specified roles ONLY
// returns true if the user has at least one assigned role (after the operation is complete)
func (o *OIDCAzure) assignUserRoles(ctx context.Context, username accesstypes.User, roles []string) (hasRole bool, err error) {
	ctx, span := tracer.Start(ctx)
	defer span.End()

	domains, err := o.userRoleManager.Domains(ctx)
	if err != nil {
		return false, errors.Wrap(err, "UserRoleManager.Domains()")
	}

	existingRoles, err := o.userRoleManager.UserRoles(ctx, username, domains...)
	if err != nil {
		return false, errors.Wrap(err, "UserRoleManager.UserRoles()")
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
				return false, errors.Wrap(err, "UserRoleManager.AddUserRoles()")
			}
			logger.FromCtx(ctx).Infof("User %s assigned to roles %v in domain %s", username, newRoles, domain)
		}

		removeRoles := util.Exclude(existingRoles[domain], rolesToAssign)
		if len(removeRoles) > 0 {
			if err := o.userRoleManager.DeleteUserRoles(ctx, domain, username, removeRoles...); err != nil {
				return false, errors.Wrap(err, "UserRoleManager.DeleteUserRoles()")
			}
			logger.FromCtx(ctx).Infof("User %s removed from roles %v in domain %s", username, removeRoles, domain)
		}

		hasRole = hasRole || len(rolesToAssign) > 0
	}

	return hasRole, nil
}

// startNewSession starts a new session for the given username and returns the session ID
func (o *OIDCAzure) startNewSession(ctx context.Context, w http.ResponseWriter, username, oidcSID string) (ccc.UUID, error) {
	// Create new Session in database
	id, err := o.storage.NewSession(ctx, username, oidcSID)
	if err != nil {
		return ccc.NilUUID, errors.Wrap(err, "sessionstorage.OIDCStore.NewSession()")
	}

	o.baseSession.CookieHandler.NewAuthCookie(w, false, id)

	// write new XSRF Token Cookie to match the new SessionID
	o.baseSession.CookieHandler.CreateXSRFTokenCookie(w, id)

	return id, nil
}

// API provides programatic access to OIDCAzure
func (o *OIDCAzure) API() *OIDCAzureAPI {
	return newOIDCAzureAPI(o)
}

// OIDCAzureAPI provides programatic access to OIDCAzure
type OIDCAzureAPI struct {
	oidc *OIDCAzure
}

func newOIDCAzureAPI(oidc *OIDCAzure) *OIDCAzureAPI {
	return &OIDCAzureAPI{
		oidc: oidc,
	}
}

// ValidateSession checks the session cookie and if it is valid, stores the session data into the context
func (p *OIDCAzureAPI) ValidateSession(ctx context.Context) (context.Context, error) {
	ctx, err := p.oidc.baseSession.ValidateSessionAPI(ctx)
	if err != nil {
		return ctx, errors.Wrap(err, "basesession.BaseSession.ValidateSessionAPI()")
	}

	return ctx, nil
}

// Cookie returns the underlying cookie.Client
func (p *OIDCAzureAPI) Cookie() *cookie.Client {
	return p.oidc.baseSession.CookieHandler.Cookie()
}
