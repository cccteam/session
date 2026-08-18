package session

import (
	"context"
	"encoding/json"
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
	"github.com/cccteam/session/sessioninfo"
	"github.com/cccteam/session/sessionstorage"
	"github.com/go-playground/errors/v5"
)

// OIDCAzureOption defines the interface for functional options used when creating a new OIDCAzure.
type OIDCAzureOption interface {
	isOIDCAzureOption()
}

var _ OIDCAzureHandlers = &OIDCAzure{}

// OIDCAzure is a TypedOIDCAzure without custom session data. It preserves the
// pre-generics API surface; use NewTypedOIDCAzure for typed custom session data.
type OIDCAzure = TypedOIDCAzure[NoCustomData]

// OIDCAzureAPI is a TypedOIDCAzureAPI without custom session data.
type OIDCAzureAPI = TypedOIDCAzureAPI[NoCustomData]

// TypedOIDCAzure implements the OIDCAzureHandlers interface for handling OIDC authentication with Azure,
// with custom session data typed as T (populated by a resolver from the verified claims).
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
type TypedOIDCAzure[T any] struct {
	userRoleManager UserRoleManager
	oidc            azureoidc.Authenticator
	storage         sessionstorage.OIDCStore
	baseSession     *basesession.BaseSession
}

// NewOIDCAzure creates a new OIDCAzure.
// cookieKey: A Base64-encoded string representing at least 32 bytes
// of cryptographically secure random data.
func NewOIDCAzure(
	storage sessionstorage.OIDCStore, userRoleManager UserRoleManager,
	cookieKey string,
	issuerURL, clientID, clientSecret, redirectURL string,
	options ...OIDCAzureOption,
) (*OIDCAzure, error) {
	return NewTypedOIDCAzure[NoCustomData](storage, userRoleManager, cookieKey, issuerURL, clientID, clientSecret, redirectURL, options...)
}

// NewTypedOIDCAzure creates a new TypedOIDCAzure for the custom session data struct
// type T. The storage must carry a custom session data configuration built for the
// same T; a mismatch is a construction error. The configuration's resolver receives
// the raw verified ID-token claims via req.Claims.
// cookieKey: A Base64-encoded string representing at least 32 bytes
// of cryptographically secure random data.
func NewTypedOIDCAzure[T any](
	storage sessionstorage.OIDCStore, userRoleManager UserRoleManager,
	cookieKey string,
	issuerURL, clientID, clientSecret, redirectURL string,
	options ...OIDCAzureOption,
) (*TypedOIDCAzure[T], error) {
	if err := verifyCustomDataType[T](storage); err != nil {
		return nil, err
	}
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

	for _, opt := range options {
		switch o := any(opt).(type) {
		case BaseSessionOption:
			o(baseSession)
		case OIDCOption:
			o(oidc)
		}
	}

	return &TypedOIDCAzure[T]{
		userRoleManager: userRoleManager,
		oidc:            oidc,
		baseSession:     baseSession,
		storage:         storage,
	}, nil
}

// Authenticated is the handler reports if the session is authenticated
func (o *TypedOIDCAzure[T]) Authenticated() http.HandlerFunc {
	return o.baseSession.Authenticated()
}

// Logout destroys the current session
func (o *TypedOIDCAzure[T]) Logout() http.HandlerFunc {
	return o.baseSession.Logout()
}

// SetXSRFToken sets the XSRF Token
func (o *TypedOIDCAzure[T]) SetXSRFToken(next http.Handler) http.Handler {
	return o.baseSession.SetXSRFToken(next)
}

// StartSession initializes a session by restoring it from a cookie, or if that fails, initializing
// a new session. The session cookie is then updated and the sessionID is inserted into the context.
func (o *TypedOIDCAzure[T]) StartSession(next http.Handler) http.Handler {
	return o.baseSession.StartSession(next)
}

// ValidateSession checks the sessionID in the database to validate that it has not expired and updates
// the last activity timestamp if it is still valid. StartSession handler must be called before
// calling ValidateSession
func (o *TypedOIDCAzure[T]) ValidateSession(next http.Handler) http.Handler {
	return o.baseSession.ValidateSession(next)
}

// ValidateXSRFToken validates the XSRF Token
func (o *TypedOIDCAzure[T]) ValidateXSRFToken(next http.Handler) http.Handler {
	return o.baseSession.ValidateXSRFToken(next)
}

// Login initiates the OIDC login flow by redirecting the user to the authorization URL.
func (o *TypedOIDCAzure[T]) Login() http.HandlerFunc {
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
func (o *TypedOIDCAzure[T]) CallbackOIDC() http.HandlerFunc {
	type claims struct {
		Username string   `json:"preferred_username"`
		Roles    []string `json:"roles"`
	}

	return o.baseSession.Handle(func(w http.ResponseWriter, r *http.Request) error {
		ctx, span := tracer.Start(r.Context())
		defer span.End()

		// Capture the full verified claims payload so a configured custom session data
		// resolver receives every claim, then decode the fields this handler needs.
		var rawClaims json.RawMessage
		returnURL, oidcSID, err := o.oidc.Verify(ctx, w, r, &rawClaims)
		if err != nil {
			http.Redirect(w, r, fmt.Sprintf("%s?message=%s", o.oidc.LoginURL(), url.QueryEscape(httpio.Message(err))), http.StatusFound)

			return errors.Wrap(err, "azureoidc.Authenticator.Verify()")
		}

		claims := &claims{}
		if err := json.Unmarshal(rawClaims, claims); err != nil {
			http.Redirect(w, r, fmt.Sprintf("%s?message=%s", o.oidc.LoginURL(), url.QueryEscape("Internal Server Error")), http.StatusFound)

			return errors.Wrap(err, "json.Unmarshal()")
		}

		// Reconcile roles BEFORE creating the session so a rejected login never
		// leaves a live session or auth cookie behind.
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

		// user is successfully authenticated and authorized, start a new session. A
		// configured custom session data resolver runs inside the session-insert
		// transaction; a resolver error aborts the login here, before any cookie is
		// written.
		sessionID, err := o.startNewSession(ctx, w, claims.Username, oidcSID, rawClaims)
		if err != nil {
			message := httpio.Message(err)
			if message == "" {
				message = "Internal Server Error"
			}
			http.Redirect(w, r, fmt.Sprintf("%s?message=%s", o.oidc.LoginURL(), url.QueryEscape(message)), http.StatusFound)

			return errors.Wrap(err, "OIDCAzure.startNewSession()")
		}

		// Log the association between the sessionID and Username
		logger.FromCtx(ctx).AddRequestAttribute("Username", claims.Username).AddRequestAttribute(string(internalcookie.SessionID), sessionID)

		http.Redirect(w, r, returnURL, http.StatusFound)

		return nil
	})
}

// FrontChannelLogout is a handler which destroys the current session for a logout request initiated by the OIDC provider
func (o *TypedOIDCAzure[T]) FrontChannelLogout() http.HandlerFunc {
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
func (o *TypedOIDCAzure[T]) assignUserRoles(ctx context.Context, username accesstypes.User, roles []string) (hasRole bool, err error) {
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

// startNewSession starts a new session for the given username and returns the session ID.
// claims carries the raw verified ID-token claims into any configured custom session data
// resolver, which runs inside the session-insert transaction; a resolver error aborts the
// session creation and no cookies are written.
func (o *TypedOIDCAzure[T]) startNewSession(ctx context.Context, w http.ResponseWriter, username, oidcSID string, claims json.RawMessage) (ccc.UUID, error) {
	// Create new Session in database
	id, err := o.storage.NewSession(ctx, username, oidcSID, claims)
	if err != nil {
		return ccc.NilUUID, errors.Wrap(err, "sessionstorage.OIDCStore.NewSession()")
	}

	o.baseSession.CookieHandler.NewAuthCookie(w, false, id)

	// write new XSRF Token Cookie to match the new SessionID
	o.baseSession.CookieHandler.CreateXSRFTokenCookie(w, id)

	return id, nil
}

// API provides programatic access to OIDCAzure
func (o *TypedOIDCAzure[T]) API() *TypedOIDCAzureAPI[T] {
	return newOIDCAzureAPI(o)
}

// TypedOIDCAzureAPI provides programatic access to TypedOIDCAzure handler internals
type TypedOIDCAzureAPI[T any] struct {
	oidc *TypedOIDCAzure[T]
}

func newOIDCAzureAPI[T any](oidc *TypedOIDCAzure[T]) *TypedOIDCAzureAPI[T] {
	return &TypedOIDCAzureAPI[T]{
		oidc: oidc,
	}
}

// ValidateSession checks the session cookie and if it is valid, stores the session data into the context
func (p *TypedOIDCAzureAPI[T]) ValidateSession(ctx context.Context) (context.Context, error) {
	ctx, err := p.oidc.baseSession.ValidateSessionAPI(ctx)
	if err != nil {
		return ctx, errors.Wrap(err, "basesession.BaseSession.ValidateSessionAPI()")
	}

	return ctx, nil
}

// Cookie returns the underlying cookie.Client
func (p *TypedOIDCAzureAPI[T]) Cookie() *cookie.Client {
	return p.oidc.baseSession.CookieHandler.Cookie()
}

// UpdateCustomSessionData updates the custom session data for an active session via a
// transactional read-modify-write: mutate receives the current row (zero-value T when
// no row exists), and the full row is written back; a mutate error aborts with nothing
// written. It is intended for genuine mid-session updates only (e.g. a tenant switch
// the caller has authorized) — initial population belongs in the creation path (the
// configured resolver), which is atomic with the session insert. See the "Custom
// session data" section of the README for the full lifecycle.
func (p *TypedOIDCAzureAPI[T]) UpdateCustomSessionData(ctx context.Context, sessionID ccc.UUID, mutate func(data *T) error) error {
	ctx, span := tracer.Start(ctx)
	defer span.End()

	if err := p.oidc.storage.UpdateCustomSessionData(ctx, sessionID, eraseMutate(mutate)); err != nil {
		return errors.Wrap(err, "sessionstorage.OIDCStore.UpdateCustomSessionData()")
	}

	return nil
}

// CustomData returns the strongly typed custom session data for the current session
// from the context. A session with no custom data row yields a zero-value T.
func (p *TypedOIDCAzureAPI[T]) CustomData(ctx context.Context) (T, error) {
	data, err := sessioninfo.CustomDataFromCtx[*T](ctx)
	if err != nil {
		var zero T

		return zero, errors.Wrap(err, "sessioninfo.CustomDataFromCtx()")
	}

	return *data, nil
}
