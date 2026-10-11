package session

import (
	"context"
	"encoding/json"
	"net/http"

	"github.com/cccteam/ccc"
	"github.com/cccteam/ccc/accesstypes"
	"github.com/cccteam/ccc/tracer"
	"github.com/cccteam/httpio"
	"github.com/cccteam/logger"
	"github.com/cccteam/session/cookie"
	"github.com/cccteam/session/internal/azureoidc"
	"github.com/cccteam/session/internal/basesession"
	internalcookie "github.com/cccteam/session/internal/cookie"
	"github.com/cccteam/session/sessioninfo"
	"github.com/cccteam/session/sessionstorage"
	"github.com/go-playground/errors/v5"
)

// OIDCAzureOption defines the interface for functional options used when creating a new OIDCAzure.
type OIDCAzureOption interface {
	isOIDCAzureOption()
}

var _ OIDCAzureHandlers = &OIDCAzure[NoCustomData, NoCustomData]{}

// OIDCAzure implements the OIDCAzureHandlers interface for handling OIDC authentication
// with Azure, with custom session data typed as SessionData (populated by a resolver
// from the verified claims, read on every authenticated request) and custom user data
// typed as UserData (durable — it lives and dies with the OIDCUsers anchor record,
// maintained by the configured login hook and read on demand). Instantiate an unused
// axis with NoCustomData.
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
// A person's directory roles apply in every tenant alike: a global role is held in
// the global partition and a domain default role is held in every tenant domain, so
// the sync writes each membership once, where the role is held, and it reaches every
// tenant, the ones that exist today and the ones created later. A tenant-specific
// role (Admin in tenant A but Viewer in tenant B) is the application's business: a
// custom role and a membership held in one domain, written by the application. The
// sync removes any membership the directory does not name, a membership held in one
// domain included.
//
// Because the reconciliation removes roles absent from the token, application-side
// role assignment cannot coexist with this flow — any manually assigned role would be
// silently reverted at the user's next login. Role management must be either
// IdP-driven (this flow) or application-driven, never both for the same app.
//
// Role synchronization is configured through the required RoleSyncConfig
// constructor slot: RoleSync(manager) enables the flow above; DisableRoleSync()
// disables role maintenance during login entirely — no roles are read, written,
// or removed, and the at-least-one-role login gate does not apply
// (application-managed roles, or no roles at all).
type OIDCAzure[SessionData, UserData any] struct {
	roleSync    *roleSyncConfig
	oidc        azureoidc.Authenticator
	storage     sessionstorage.OIDCStore
	baseSession *basesession.BaseSession
}

// NewOIDCAzure creates a new OIDCAzure for the custom session data struct type
// SessionData and the custom user data struct type UserData; instantiate an unused axis
// with NoCustomData. The storage must carry a custom session data configuration built
// for the same SessionData (its resolver receives the raw verified ID-token claims via
// req.Claims) and a custom user data configuration built for the same UserData; a
// mismatch is a construction error. Custom user data on OIDC storage requires the OIDC
// user anchor (sessionstorage.WithOIDCUsers) — without it there is no durable user
// record to attach the data to.
// roleSync: role-synchronization configuration — session.RoleSync(manager) to
// enable, session.DisableRoleSync() to disable; see OIDCAzure for semantics.
// cookieKey: A Base64-encoded string representing at least 32 bytes
// of cryptographically secure random data.
func NewOIDCAzure[SessionData, UserData any](
	storage sessionstorage.OIDCStore, roleSync RoleSyncConfig,
	cookieKey string,
	issuerURL, clientID, clientSecret, redirectURL string,
	options ...OIDCAzureOption,
) (*OIDCAzure[SessionData, UserData], error) {
	if roleSync == nil {
		return nil, errors.New("roleSync is required: pass session.RoleSync(manager) or session.DisableRoleSync()")
	}
	roleSyncCfg := roleSync.config()
	if roleSyncCfg != nil && roleSyncCfg.manager == nil {
		return nil, errors.New("session.RoleSync() requires a non-nil UserRoleManager")
	}
	if err := verifyCustomDataType[SessionData](storage); err != nil {
		return nil, err
	}
	if err := verifyCustomUserDataType[UserData](storage); err != nil {
		return nil, err
	}
	if storage.CustomUserDataType() != nil && !storage.OIDCUsersEnabled() {
		return nil, errors.New("custom user data on OIDC storage requires the OIDC user anchor: pass sessionstorage.WithOIDCUsers() to the storage constructor")
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

	return &OIDCAzure[SessionData, UserData]{
		roleSync:    roleSyncCfg,
		oidc:        oidc,
		baseSession: baseSession,
		storage:     storage,
	}, nil
}

// Authenticated is the handler reports if the session is authenticated
func (o *OIDCAzure[T, U]) Authenticated() http.HandlerFunc {
	return o.baseSession.Authenticated()
}

// Logout destroys the current session
func (o *OIDCAzure[T, U]) Logout() http.HandlerFunc {
	return o.baseSession.Logout()
}

// SetXSRFToken sets the XSRF Token
func (o *OIDCAzure[T, U]) SetXSRFToken(next http.Handler) http.Handler {
	return o.baseSession.SetXSRFToken(next)
}

// StartSession initializes a session by restoring it from a cookie, or if that fails, initializing
// a new session. The session cookie is then updated and the sessionID is inserted into the context.
func (o *OIDCAzure[T, U]) StartSession(next http.Handler) http.Handler {
	return o.baseSession.StartSession(next)
}

// ValidateSession checks the sessionID in the database to validate that it has not expired and updates
// the last activity timestamp if it is still valid. StartSession handler must be called before
// calling ValidateSession
func (o *OIDCAzure[T, U]) ValidateSession(next http.Handler) http.Handler {
	return o.baseSession.ValidateSession(next)
}

// ValidateXSRFToken validates the XSRF Token
func (o *OIDCAzure[T, U]) ValidateXSRFToken(next http.Handler) http.Handler {
	return o.baseSession.ValidateXSRFToken(next)
}

// EnforceReadOnlyMask refuses non-safe requests from a read-only impersonated session
// with 403 Forbidden, evidenced as a WriteBlocked event; every other request passes.
// Place it after ValidateSession. See the "Impersonated sessions" section of the README.
func (o *OIDCAzure[T, U]) EnforceReadOnlyMask(next http.Handler) http.Handler {
	return o.baseSession.EnforceReadOnlyMask(next)
}

// EndImpersonation ends the impersonated session (record ended Released) and, for a
// local actor whose own session is still live, returns the browser to that session; the
// body's restored flag says whether it did. Route it inside the validated group. See the
// "Impersonated sessions" section of the README.
func (o *OIDCAzure[T, U]) EndImpersonation() http.HandlerFunc {
	return o.baseSession.EndImpersonation()
}

// Login initiates the OIDC login flow by redirecting the user to the authorization URL.
func (o *OIDCAzure[T, U]) Login() http.HandlerFunc {
	return o.baseSession.Handle(func(w http.ResponseWriter, r *http.Request) error {
		ctx, span := tracer.Start(r.Context())
		defer span.End()

		returnURL := r.URL.Query().Get("returnUrl")
		authCodeURL, err := o.oidc.AuthCodeURL(ctx, w, returnURL)
		if err != nil {
			redirectRefusedLogin(w, r, o.oidc.LoginURL(), err)

			return errors.Wrap(err, "azureoidc.Authenticator.AuthCodeURL()")
		}

		// authCodeURL is the identity provider's authorization address, built from the
		// configured issuer; the user's returnUrl rides in the OIDC cookie and is no part
		// of the redirect target.
		// nosemgrep: go.lang.security.injection.open-redirect.open-redirect
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
func (o *OIDCAzure[T, U]) CallbackOIDC() http.HandlerFunc {
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
			redirectRefusedLogin(w, r, o.oidc.LoginURL(), err)

			return errors.Wrap(err, "azureoidc.Authenticator.Verify()")
		}

		claims := &claims{}
		if err := json.Unmarshal(rawClaims, claims); err != nil {
			redirectRefusedLogin(w, r, o.oidc.LoginURL(), err)

			return errors.Wrap(err, "json.Unmarshal()")
		}

		// Reconcile roles BEFORE creating the session so a rejected login never
		// leaves a live session or auth cookie behind. With role sync disabled the
		// reconciliation and its at-least-one-role gate are skipped entirely.
		if o.roleSync != nil {
			hasRole, err := o.roleSync.reconcile(ctx, accesstypes.User(claims.Username), claims.Roles)
			if err != nil {
				redirectRefusedLogin(w, r, o.oidc.LoginURL(), err)

				return errors.Wrap(err, "roleSyncConfig.reconcile()")
			}
			if !hasRole {
				err := sessioninfo.NewLoginRefusal(sessioninfo.RefusedNoRoles, httpio.NewUnauthorizedMessage("Unauthorized: user has no roles"))
				redirectRefusedLogin(w, r, o.oidc.LoginURL(), err)

				return err
			}
		}

		// user is successfully authenticated and authorized, start a new session. A
		// configured custom session data resolver runs inside the session-insert
		// transaction; a resolver error aborts the login here, before any cookie is
		// written.
		sessionID, err := o.startNewSession(ctx, w, claims.Username, oidcSID, rawClaims)
		if err != nil {
			redirectRefusedLogin(w, r, o.oidc.LoginURL(), err)

			return errors.Wrap(err, "OIDCAzure.startNewSession()")
		}

		// Log the association between the sessionID and Username
		logger.FromCtx(ctx).AddRequestAttribute("Username", claims.Username).AddRequestAttribute(string(internalcookie.SessionID), sessionID)

		http.Redirect(w, r, returnURL, http.StatusFound)

		return nil
	})
}

// FrontChannelLogout is a handler which destroys the current session for a logout request initiated by the OIDC provider
func (o *OIDCAzure[T, U]) FrontChannelLogout() http.HandlerFunc {
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

// startNewSession starts a new session for the given username and returns the session ID.
// claims carries the raw verified ID-token claims into any configured custom session data
// resolver, which runs inside the session-insert transaction; a resolver error aborts the
// session creation and no cookies are written.
func (o *OIDCAzure[T, U]) startNewSession(ctx context.Context, w http.ResponseWriter, username, oidcSID string, claims json.RawMessage) (ccc.UUID, error) {
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
func (o *OIDCAzure[T, U]) API() *OIDCAzureAPI[T, U] {
	return newOIDCAzureAPI(o)
}

// OIDCAzureAPI provides programatic access to OIDCAzure handler internals
type OIDCAzureAPI[SessionData, UserData any] struct {
	oidc *OIDCAzure[SessionData, UserData]
}

func newOIDCAzureAPI[T, U any](oidc *OIDCAzure[T, U]) *OIDCAzureAPI[T, U] {
	return &OIDCAzureAPI[T, U]{
		oidc: oidc,
	}
}

// ValidateSession checks the session cookie and if it is valid, stores the session data into the context
func (p *OIDCAzureAPI[T, U]) ValidateSession(ctx context.Context) (context.Context, error) {
	ctx, err := p.oidc.baseSession.ValidateSessionAPI(ctx)
	if err != nil {
		return ctx, errors.Wrap(err, "basesession.BaseSession.ValidateSessionAPI()")
	}

	return ctx, nil
}

// Cookie returns the underlying cookie.Client
func (p *OIDCAzureAPI[T, U]) Cookie() *cookie.Client {
	return p.oidc.baseSession.CookieHandler.Cookie()
}

// UpdateCustomSessionData updates the custom session data for an active session via a
// transactional read-modify-write: mutate receives the current row (zero-value T when
// no row exists), and the full row is written back; a mutate error aborts with nothing
// written. It is intended for genuine mid-session updates only (e.g. a tenant switch
// the caller has authorized) — initial population belongs in the creation path (the
// configured resolver), which is atomic with the session insert. See the "Custom
// session data" section of the README for the full lifecycle.
func (p *OIDCAzureAPI[T, U]) UpdateCustomSessionData(ctx context.Context, sessionID ccc.UUID, mutate func(data *T) error) error {
	ctx, span := tracer.Start(ctx)
	defer span.End()

	if err := p.oidc.storage.UpdateCustomSessionData(ctx, sessionID, eraseMutate(mutate)); err != nil {
		return errors.Wrap(err, "sessionstorage.OIDCStore.UpdateCustomSessionData()")
	}

	return nil
}

// CustomData returns the strongly typed custom session data for the current session
// from the context. A session with no custom data row yields a zero-value T.
func (p *OIDCAzureAPI[T, U]) CustomData(ctx context.Context) (T, error) {
	data, err := sessioninfo.CustomDataFromCtx[*T](ctx)
	if err != nil {
		var zero T

		return zero, errors.Wrap(err, "sessioninfo.CustomDataFromCtx()")
	}

	return *data, nil
}

// OIDCUser returns the OIDC user anchor record for the given ID. It requires the OIDC
// user anchor (sessionstorage.WithOIDCUsers). See the "OIDC user anchor" section of the
// README.
func (p *OIDCAzureAPI[T, U]) OIDCUser(ctx context.Context, id ccc.UUID) (*sessionstorage.OIDCUser, error) {
	ctx, span := tracer.Start(ctx)
	defer span.End()

	user, err := p.oidc.storage.OIDCUser(ctx, id)
	if err != nil {
		return nil, errors.Wrap(err, "sessionstorage.OIDCStore.OIDCUser()")
	}

	return user, nil
}

// OIDCUserByKey returns the OIDC user anchor record for the given (tid, oid) claim
// pair — the identity comparison OIDC gives you (usernames are mutable and recyclable).
// It requires the OIDC user anchor (sessionstorage.WithOIDCUsers). See the "OIDC user
// anchor" section of the README.
func (p *OIDCAzureAPI[T, U]) OIDCUserByKey(ctx context.Context, tid, oid string) (*sessionstorage.OIDCUser, error) {
	ctx, span := tracer.Start(ctx)
	defer span.End()

	user, err := p.oidc.storage.OIDCUserByKey(ctx, tid, oid)
	if err != nil {
		return nil, errors.Wrap(err, "sessionstorage.OIDCStore.OIDCUserByKey()")
	}

	return user, nil
}

// CustomUserData returns the strongly typed custom user data for the given user (the
// OIDCUsers anchor record's ID, e.g. from the session's custom data or OIDCUserByKey).
// A user with no custom data row yields a zero-value U. Custom user data is durable —
// it lives and dies with the anchor record — and is read on demand, never from the
// session context.
func (p *OIDCAzureAPI[T, U]) CustomUserData(ctx context.Context, userID ccc.UUID) (U, error) {
	ctx, span := tracer.Start(ctx)
	defer span.End()

	var zero U
	data, err := p.oidc.storage.CustomUserData(ctx, userID)
	if err != nil {
		return zero, errors.Wrap(err, "sessionstorage.OIDCStore.CustomUserData()")
	}
	typed, ok := data.(*U)
	if !ok {
		return zero, errors.Newf("custom user data type mismatch: storage decoded %T, session type expects %T", data, (*U)(nil))
	}

	return *typed, nil
}

// UpdateCustomUserData updates the custom user data for an existing user via a
// transactional read-modify-write: mutate receives the current row (zero-value U when
// no row exists), and the full row is written back; a mutate error aborts with nothing
// written. Ongoing claims-driven maintenance belongs in the configured login hook; this
// is for genuine app-driven updates. See the "Custom user data" section of the README
// for the full lifecycle.
func (p *OIDCAzureAPI[T, U]) UpdateCustomUserData(ctx context.Context, userID ccc.UUID, mutate func(data *U) error) error {
	ctx, span := tracer.Start(ctx)
	defer span.End()

	if err := p.oidc.storage.UpdateCustomUserData(ctx, userID, eraseMutate(mutate)); err != nil {
		return errors.Wrap(err, "sessionstorage.OIDCStore.UpdateCustomUserData()")
	}

	return nil
}
