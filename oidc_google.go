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
	"github.com/cccteam/session/internal/basesession"
	internalcookie "github.com/cccteam/session/internal/cookie"
	"github.com/cccteam/session/internal/googleoidc"
	"github.com/cccteam/session/sessioninfo"
	"github.com/cccteam/session/sessionstorage"
	"github.com/go-playground/errors/v5"
)

// OIDCGoogleOption defines the interface for functional options used when creating a new OIDCGoogle.
type OIDCGoogleOption interface {
	isOIDCGoogleOption()
}

var _ OIDCGoogleHandlers = &OIDCGoogle[NoCustomData, NoCustomData]{}

// OIDCGoogle implements the OIDCGoogleHandlers interface for handling OIDC
// authentication with Google Workspace, with custom session data typed as SessionData
// (populated by a resolver from the verified claims, read on every authenticated
// request) and custom user data typed as UserData (durable — it lives and dies with the
// GoogleOIDCUsers anchor record, maintained by the configured login hook and read on
// demand). Instantiate an unused axis with NoCustomData.
//
// Hosted-domain restriction: the flow is restricted to a single Google Workspace
// domain. The configured hostedDomain is sent as the hd hint on the authorization
// request (account-chooser UX) and enforced against the verified ID token's hd claim —
// a consumer account carries no hd claim and fails closed. Pair it with an Internal
// OAuth consent screen so Google itself refuses outside accounts before they ever reach
// the callback.
//
// Identity: the username is the verified email claim (Google issues no
// preferred_username), and the durable identity key is the sub claim — globally unique
// and never reused — which keys the optional GoogleOIDCUsers anchor on its own.
//
// Role synchronization: Google Workspace has no equivalent of Azure App Roles and its
// ID tokens carry no roles claim, so the integrated flow sources role names from the
// directory itself: on every login the user's Google Groups are fetched through the
// configured GroupsProvider and mapped through a group naming convention
// (<prefix><role>@domain — see GoogleRoleSync). The reconciliation semantics then match
// the Azure flow exactly: mapped names for which a role exists are assigned (where a
// role of that name exists), any role the user currently holds that is NOT among them
// is removed, and the login is rejected as Unauthorized unless at least one recognized
// role results. A groups-lookup failure fails the login.
//
// DESIGN LIMITATION — role synchronization is domain-blind: the mapped roles are
// applied identically in every swept domain where the role name exists (the sweep
// covers the global scope plus the domains from the configured DomainsProvider — see
// GoogleRoleSync). The multi-tenancy guidance on OIDCAzure applies unchanged.
//
// Because the reconciliation removes roles absent from the directory, application-side
// role assignment cannot coexist with this flow — role management must be either
// directory-driven (this flow) or application-driven (DisableRoleSync), never both for
// the same app.
//
// Logout: Google supports no IdP-initiated logout (no end_session_endpoint, no sid
// claim), so there is no FrontChannelLogout handler — Logout destroys the local session
// only.
type OIDCGoogle[SessionData, UserData any] struct {
	roleSync    *googleRoleSyncConfig
	oidc        googleoidc.Authenticator
	storage     sessionstorage.GoogleOIDCStore
	baseSession *basesession.BaseSession
}

// NewOIDCGoogle creates a new OIDCGoogle for the custom session data struct type
// SessionData and the custom user data struct type UserData; instantiate an unused axis
// with NoCustomData. The storage must be Google OIDC storage
// (sessionstorage.NewSpannerGoogleOIDC / NewPostgresGoogleOIDC) carrying configurations
// built for the same SessionData and UserData; a mismatch is a construction error.
// Custom user data requires the OIDC user anchor (sessionstorage.WithOIDCUsers).
// roleSync: role-synchronization configuration — session.GoogleRoleSync(manager,
// domains, groupPrefix, groups) to enable, session.DisableRoleSync() to disable; see
// OIDCGoogle for semantics.
// cookieKey: A Base64-encoded string representing at least 32 bytes of
// cryptographically secure random data.
// hostedDomain: the Google Workspace domain logins are restricted to (the hd claim
// check); required.
func NewOIDCGoogle[SessionData, UserData any](
	storage sessionstorage.GoogleOIDCStore, roleSync GoogleRoleSyncConfig,
	cookieKey string,
	clientID, clientSecret, redirectURL, hostedDomain string,
	options ...OIDCGoogleOption,
) (*OIDCGoogle[SessionData, UserData], error) {
	if roleSync == nil {
		return nil, errors.New("roleSync is required: pass session.GoogleRoleSync(manager, domains, groupPrefix, groups) or session.DisableRoleSync()")
	}
	roleSyncCfg := roleSync.googleConfig()
	if roleSyncCfg != nil {
		if roleSyncCfg.manager == nil {
			return nil, errors.New("session.GoogleRoleSync() requires a non-nil UserRoleManager")
		}
		if roleSyncCfg.groupPrefix == "" {
			return nil, errors.New("session.GoogleRoleSync() requires a non-empty groupPrefix: it is the only filter separating role groups from the rest of the directory")
		}
		if roleSyncCfg.groups == nil {
			return nil, errors.New("session.GoogleRoleSync() requires a non-nil GroupsProvider")
		}
	}
	if hostedDomain == "" {
		return nil, errors.New("hostedDomain is required: it is enforced against the verified ID token's hd claim to restrict logins to the Workspace organization")
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

	oidc := googleoidc.New(cookieClient, clientID, clientSecret, redirectURL, hostedDomain)
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

	return &OIDCGoogle[SessionData, UserData]{
		roleSync:    roleSyncCfg,
		oidc:        oidc,
		baseSession: baseSession,
		storage:     storage,
	}, nil
}

// Authenticated is the handler reports if the session is authenticated
func (o *OIDCGoogle[T, U]) Authenticated() http.HandlerFunc {
	return o.baseSession.Authenticated()
}

// Logout destroys the current session
func (o *OIDCGoogle[T, U]) Logout() http.HandlerFunc {
	return o.baseSession.Logout()
}

// SetXSRFToken sets the XSRF Token
func (o *OIDCGoogle[T, U]) SetXSRFToken(next http.Handler) http.Handler {
	return o.baseSession.SetXSRFToken(next)
}

// StartSession initializes a session by restoring it from a cookie, or if that fails, initializing
// a new session. The session cookie is then updated and the sessionID is inserted into the context.
func (o *OIDCGoogle[T, U]) StartSession(next http.Handler) http.Handler {
	return o.baseSession.StartSession(next)
}

// ValidateSession checks the sessionID in the database to validate that it has not expired and updates
// the last activity timestamp if it is still valid. StartSession handler must be called before
// calling ValidateSession
func (o *OIDCGoogle[T, U]) ValidateSession(next http.Handler) http.Handler {
	return o.baseSession.ValidateSession(next)
}

// ValidateXSRFToken validates the XSRF Token
func (o *OIDCGoogle[T, U]) ValidateXSRFToken(next http.Handler) http.Handler {
	return o.baseSession.ValidateXSRFToken(next)
}

// Login initiates the OIDC login flow by redirecting the user to the authorization URL.
func (o *OIDCGoogle[T, U]) Login() http.HandlerFunc {
	return o.baseSession.Handle(func(w http.ResponseWriter, r *http.Request) error {
		ctx, span := tracer.Start(r.Context())
		defer span.End()

		returnURL := r.URL.Query().Get("returnUrl")
		authCodeURL, err := o.oidc.AuthCodeURL(ctx, w, returnURL)
		if err != nil {
			http.Redirect(w, r, fmt.Sprintf("%s?message=%s", o.oidc.LoginURL(), url.QueryEscape("Internal Server Error")), http.StatusFound)

			return errors.Wrap(err, "googleoidc.Authenticator.AuthCodeURL()")
		}

		http.Redirect(w, r, authCodeURL, http.StatusFound)

		return nil
	})
}

// CallbackOIDC is the handler for the callback from the OIDC auth provider.
//
// Besides completing authentication (including the hosted-domain and verified-email
// checks inside Verify), it reconciles the user's roles to the prefix-mapped Google
// Groups membership and rejects logins that yield no recognized role — see the
// OIDCGoogle type documentation for the role-synchronization semantics and their
// multi-tenancy limitations.
func (o *OIDCGoogle[T, U]) CallbackOIDC() http.HandlerFunc {
	type claims struct {
		Email string `json:"email"`
	}

	return o.baseSession.Handle(func(w http.ResponseWriter, r *http.Request) error {
		ctx, span := tracer.Start(r.Context())
		defer span.End()

		// Capture the full verified claims payload so a configured custom session data
		// resolver receives every claim, then decode the fields this handler needs.
		var rawClaims json.RawMessage
		returnURL, err := o.oidc.Verify(ctx, w, r, &rawClaims)
		if err != nil {
			http.Redirect(w, r, fmt.Sprintf("%s?message=%s", o.oidc.LoginURL(), url.QueryEscape(httpio.Message(err))), http.StatusFound)

			return errors.Wrap(err, "googleoidc.Authenticator.Verify()")
		}

		claims := &claims{}
		if err := json.Unmarshal(rawClaims, claims); err != nil {
			http.Redirect(w, r, fmt.Sprintf("%s?message=%s", o.oidc.LoginURL(), url.QueryEscape("Internal Server Error")), http.StatusFound)

			return errors.Wrap(err, "json.Unmarshal()")
		}
		if claims.Email == "" {
			err := httpio.NewUnauthorizedMessage("Unauthorized: token carries no email claim")
			http.Redirect(w, r, fmt.Sprintf("%s?message=%s", o.oidc.LoginURL(), url.QueryEscape(httpio.Message(err))), http.StatusFound)

			return err
		}

		// Reconcile roles BEFORE creating the session so a rejected login never
		// leaves a live session or auth cookie behind. With role sync disabled the
		// reconciliation and its at-least-one-role gate are skipped entirely.
		if o.roleSync != nil {
			roleNames, err := o.roleSync.roleNames(ctx, claims.Email)
			if err != nil {
				http.Redirect(w, r, fmt.Sprintf("%s?message=%s", o.oidc.LoginURL(), url.QueryEscape("Internal Server Error")), http.StatusFound)

				return errors.Wrap(err, "googleRoleSyncConfig.roleNames()")
			}
			hasRole, err := o.roleSync.reconcile(ctx, accesstypes.User(claims.Email), roleNames)
			if err != nil {
				http.Redirect(w, r, fmt.Sprintf("%s?message=%s", o.oidc.LoginURL(), url.QueryEscape("Internal Server Error")), http.StatusFound)

				return errors.Wrap(err, "roleSyncConfig.reconcile()")
			}
			if !hasRole {
				err := httpio.NewUnauthorizedMessage("Unauthorized: user has no roles")
				http.Redirect(w, r, fmt.Sprintf("%s?message=%s", o.oidc.LoginURL(), url.QueryEscape(httpio.Message(err))), http.StatusFound)

				return err
			}
		}

		// user is successfully authenticated and authorized, start a new session. A
		// configured custom session data resolver runs inside the session-insert
		// transaction; a resolver error aborts the login here, before any cookie is
		// written.
		sessionID, err := o.startNewSession(ctx, w, claims.Email, rawClaims)
		if err != nil {
			message := httpio.Message(err)
			if message == "" {
				message = "Internal Server Error"
			}
			http.Redirect(w, r, fmt.Sprintf("%s?message=%s", o.oidc.LoginURL(), url.QueryEscape(message)), http.StatusFound)

			return errors.Wrap(err, "OIDCGoogle.startNewSession()")
		}

		// Log the association between the sessionID and Username
		logger.FromCtx(ctx).AddRequestAttribute("Username", claims.Email).AddRequestAttribute(string(internalcookie.SessionID), sessionID)

		http.Redirect(w, r, returnURL, http.StatusFound)

		return nil
	})
}

// startNewSession starts a new session for the given username and returns the session ID.
// claims carries the raw verified ID-token claims into any configured custom session data
// resolver, which runs inside the session-insert transaction; a resolver error aborts the
// session creation and no cookies are written.
func (o *OIDCGoogle[T, U]) startNewSession(ctx context.Context, w http.ResponseWriter, username string, claims json.RawMessage) (ccc.UUID, error) {
	// Create new Session in database
	id, err := o.storage.NewSession(ctx, username, claims)
	if err != nil {
		return ccc.NilUUID, errors.Wrap(err, "sessionstorage.GoogleOIDCStore.NewSession()")
	}

	o.baseSession.CookieHandler.NewAuthCookie(w, false, id)

	// write new XSRF Token Cookie to match the new SessionID
	o.baseSession.CookieHandler.CreateXSRFTokenCookie(w, id)

	return id, nil
}

// API provides programatic access to OIDCGoogle
func (o *OIDCGoogle[T, U]) API() *OIDCGoogleAPI[T, U] {
	return newOIDCGoogleAPI(o)
}

// OIDCGoogleAPI provides programatic access to OIDCGoogle handler internals
type OIDCGoogleAPI[SessionData, UserData any] struct {
	oidc *OIDCGoogle[SessionData, UserData]
}

func newOIDCGoogleAPI[T, U any](oidc *OIDCGoogle[T, U]) *OIDCGoogleAPI[T, U] {
	return &OIDCGoogleAPI[T, U]{
		oidc: oidc,
	}
}

// ValidateSession checks the session cookie and if it is valid, stores the session data into the context
func (p *OIDCGoogleAPI[T, U]) ValidateSession(ctx context.Context) (context.Context, error) {
	ctx, err := p.oidc.baseSession.ValidateSessionAPI(ctx)
	if err != nil {
		return ctx, errors.Wrap(err, "basesession.BaseSession.ValidateSessionAPI()")
	}

	return ctx, nil
}

// Cookie returns the underlying cookie.Client
func (p *OIDCGoogleAPI[T, U]) Cookie() *cookie.Client {
	return p.oidc.baseSession.CookieHandler.Cookie()
}

// UpdateCustomSessionData updates the custom session data for an active session via a
// transactional read-modify-write: mutate receives the current row (zero-value T when
// no row exists), and the full row is written back; a mutate error aborts with nothing
// written. It is intended for genuine mid-session updates only (e.g. a tenant switch
// the caller has authorized) — initial population belongs in the creation path (the
// configured resolver), which is atomic with the session insert. See the "Custom
// session data" section of the README for the full lifecycle.
func (p *OIDCGoogleAPI[T, U]) UpdateCustomSessionData(ctx context.Context, sessionID ccc.UUID, mutate func(data *T) error) error {
	ctx, span := tracer.Start(ctx)
	defer span.End()

	if err := p.oidc.storage.UpdateCustomSessionData(ctx, sessionID, eraseMutate(mutate)); err != nil {
		return errors.Wrap(err, "sessionstorage.GoogleOIDCStore.UpdateCustomSessionData()")
	}

	return nil
}

// CustomData returns the strongly typed custom session data for the current session
// from the context. A session with no custom data row yields a zero-value T.
func (p *OIDCGoogleAPI[T, U]) CustomData(ctx context.Context) (T, error) {
	data, err := sessioninfo.CustomDataFromCtx[*T](ctx)
	if err != nil {
		var zero T

		return zero, errors.Wrap(err, "sessioninfo.CustomDataFromCtx()")
	}

	return *data, nil
}

// GoogleOIDCUser returns the Google OIDC user anchor record for the given ID. It
// requires the OIDC user anchor (sessionstorage.WithOIDCUsers). See the "OIDC user
// anchor" section of the README.
func (p *OIDCGoogleAPI[T, U]) GoogleOIDCUser(ctx context.Context, id ccc.UUID) (*sessionstorage.GoogleOIDCUser, error) {
	ctx, span := tracer.Start(ctx)
	defer span.End()

	user, err := p.oidc.storage.GoogleOIDCUser(ctx, id)
	if err != nil {
		return nil, errors.Wrap(err, "sessionstorage.GoogleOIDCStore.GoogleOIDCUser()")
	}

	return user, nil
}

// GoogleOIDCUserBySub returns the Google OIDC user anchor record for the given sub
// claim — the stable, never-reused identity key Google gives you (usernames and email
// addresses are mutable). It requires the OIDC user anchor
// (sessionstorage.WithOIDCUsers). See the "OIDC user anchor" section of the README.
func (p *OIDCGoogleAPI[T, U]) GoogleOIDCUserBySub(ctx context.Context, sub string) (*sessionstorage.GoogleOIDCUser, error) {
	ctx, span := tracer.Start(ctx)
	defer span.End()

	user, err := p.oidc.storage.GoogleOIDCUserBySub(ctx, sub)
	if err != nil {
		return nil, errors.Wrap(err, "sessionstorage.GoogleOIDCStore.GoogleOIDCUserBySub()")
	}

	return user, nil
}

// CustomUserData returns the strongly typed custom user data for the given user (the
// GoogleOIDCUsers anchor record's ID, e.g. from the session's custom data or
// GoogleOIDCUserBySub). A user with no custom data row yields a zero-value U. Custom
// user data is durable — it lives and dies with the anchor record — and is read on
// demand, never from the session context.
func (p *OIDCGoogleAPI[T, U]) CustomUserData(ctx context.Context, userID ccc.UUID) (U, error) {
	ctx, span := tracer.Start(ctx)
	defer span.End()

	var zero U
	data, err := p.oidc.storage.CustomUserData(ctx, userID)
	if err != nil {
		return zero, errors.Wrap(err, "sessionstorage.GoogleOIDCStore.CustomUserData()")
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
func (p *OIDCGoogleAPI[T, U]) UpdateCustomUserData(ctx context.Context, userID ccc.UUID, mutate func(data *U) error) error {
	ctx, span := tracer.Start(ctx)
	defer span.End()

	if err := p.oidc.storage.UpdateCustomUserData(ctx, userID, eraseMutate(mutate)); err != nil {
		return errors.Wrap(err, "sessionstorage.GoogleOIDCStore.UpdateCustomUserData()")
	}

	return nil
}
