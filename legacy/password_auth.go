package legacy

import (
	"context"
	"net/http"

	"github.com/cccteam/ccc"
	"github.com/cccteam/ccc/securehash"
	"github.com/cccteam/ccc/tracer"
	"github.com/cccteam/httpio"
	"github.com/cccteam/logger"
	"github.com/cccteam/session"
	"github.com/cccteam/session/cookie"
	"github.com/cccteam/session/internal/basesession"
	"github.com/cccteam/session/internal/sessioncore"
	"github.com/cccteam/session/sessioninfo"
	"github.com/cccteam/session/sessionstorage"
	"github.com/go-playground/errors/v5"
)

var _ PasswordAuthHandlers = &PasswordAuth[session.NoCustomData, session.NoCustomData]{}

// PasswordAuth implements the PasswordAuthHandlers interface for handling password
// authentication, with custom session data typed as SessionData (resolved or supplied
// at session creation, read on every authenticated request, reset on regeneration) and
// custom user data typed as UserData (durable — it lives and dies with the SessionUsers
// record, read on demand). Instantiate an unused axis with session.NoCustomData.
//
// Deprecated: the legacy username-and-password session; use session.Auth with session.PasswordSignIn, which shares the session, the user model and the middleware with every other sign-in method.
type PasswordAuth[SessionData, UserData any] struct {
	settings sessioncore.PasswordSettings

	storage     sessionstorage.PasswordAuthStore
	baseSession *basesession.BaseSession
}

// NewPasswordAuth creates a new PasswordAuth for the custom session data struct type
// SessionData and the custom user data struct type UserData; instantiate an unused axis
// with session.NoCustomData. The storage must carry a custom session data configuration built
// for the same SessionData (see sessionstorage.NewSpannerCustomSessionData /
// NewPostgresCustomSessionData) and a custom user data configuration built for the same
// UserData (see sessionstorage.NewSpannerCustomUserData / NewPostgresCustomUserData); a
// mismatch is a construction error, as are the OIDC-only storage features (the OIDC
// user anchor and the custom user data login hook).
// cookieKey: A Base64-encoded string representing at least 32 bytes
// of cryptographically secure random data.
//
// Deprecated: the legacy username-and-password session; use session.Auth with session.PasswordSignIn, which shares the session, the user model and the middleware with every other sign-in method.
func NewPasswordAuth[SessionData, UserData any](storage sessionstorage.PasswordAuthStore, cookieKey string, options ...PasswordOption) (*PasswordAuth[SessionData, UserData], error) {
	if err := sessioncore.VerifyCustomDataTypes[SessionData, UserData](storage); err != nil {
		return nil, err
	}
	if storage.UserDataLoginHookConfigured() {
		return nil, errors.New("the custom user data login hook is OIDC-only: password auth has no claims; pass initial data per call on CreateSessionUser instead")
	}
	if storage.OIDCUsersEnabled() {
		return nil, errors.New("the OIDC user anchor (WithOIDCUsers) is OIDC-only: password auth users are anchored by SessionUsers")
	}

	baseSession, _, err := sessioncore.NewBaseSession(storage, cookieKey, options)
	if err != nil {
		return nil, err
	}

	settings := sessioncore.DefaultPasswordSettings()
	for _, opt := range options {
		settings.Apply(opt)
	}
	logDeprecated("PasswordAuth", "session.Auth with session.PasswordSignIn")

	return &PasswordAuth[SessionData, UserData]{settings: settings, storage: storage, baseSession: baseSession}, nil
}

// Logout destroys the current session
func (p *PasswordAuth[T, U]) Logout() http.HandlerFunc {
	return p.baseSession.Logout()
}

// SetXSRFToken sets the XSRF Token
func (p *PasswordAuth[T, U]) SetXSRFToken(next http.Handler) http.Handler {
	return p.baseSession.SetXSRFToken(next)
}

// ValidateXSRFToken validates the XSRF Token
func (p *PasswordAuth[T, U]) ValidateXSRFToken(next http.Handler) http.Handler {
	return p.baseSession.ValidateXSRFToken(next)
}

// EnforceReadOnlyMask refuses non-safe requests from a read-only impersonated session
// with 403 Forbidden, evidenced as a WriteBlocked event; every other request passes.
// Place it after ValidateSession. See the "Impersonated sessions" section of the README.
func (p *PasswordAuth[T, U]) EnforceReadOnlyMask(next http.Handler) http.Handler {
	return p.baseSession.EnforceReadOnlyMask(next)
}

// EndImpersonation ends the impersonated session (record ended Released) and, for a
// local actor whose own session is still live, returns the browser to that session; the
// body's restored flag says whether it did. Route it inside the validated group. See the
// "Impersonated sessions" section of the README.
func (p *PasswordAuth[T, U]) EndImpersonation() http.HandlerFunc {
	return p.baseSession.EndImpersonation()
}

// StartSession initializes a session by restoring it from a cookie, or if that fails, initializing
// a new session. The session cookie is then updated and the sessionID is inserted into the context.
func (p *PasswordAuth[T, U]) StartSession(next http.Handler) http.Handler {
	return p.baseSession.StartSession(next)
}

// Login validates the username and password and establishes the session cookie.
func (p *PasswordAuth[T, U]) Login() http.HandlerFunc {
	type request struct {
		Username string `json:"username"`
		Password string `json:"password"`
	}

	decoder := sessioncore.NewDecoder[request]()

	return p.baseSession.Handle(func(w http.ResponseWriter, r *http.Request) error {
		ctx, span := tracer.Start(r.Context())
		defer span.End()

		// decode request
		req, err := decoder.Decode(r)
		if err != nil {
			return httpio.NewEncoder(w).ClientMessage(ctx, err)
		}

		if err := p.loginAPI(ctx, w, req.Username, req.Password); err != nil {
			return httpio.NewEncoder(w).ClientMessage(ctx, err)
		}

		return httpio.NewEncoder(w).Ok(nil)
	})
}

func (p *PasswordAuth[T, U]) loginAPI(ctx context.Context, w http.ResponseWriter, username, password string) error {
	// Validate credentials
	user, err := p.storage.UserByUserName(ctx, username)
	if err != nil {
		return httpio.NewUnauthorizedMessageWithError(err, "Invalid Credentials")
	}
	if err := p.validateCredentials(ctx, user, password); err != nil {
		return httpio.NewUnauthorizedMessageWithError(err, "Invalid Credentials")
	}

	// user is successfully authenticated, start a new session
	sessionID, err := p.startNewSession(ctx, w, sessioninfo.ReasonLogin, user.Username, user.ID, nil)
	if err != nil {
		return errors.Wrap(err, "PasswordAuth.startNewSession()")
	}

	sessioncore.LogSessionStarted(ctx, user.Username, sessionID)

	return nil
}

func (p *PasswordAuth[T, U]) validateCredentials(ctx context.Context, user *sessionstorage.SessionUser, password string) error {
	upgrade, err := p.comparePassword(user.PasswordHash, password)
	if err != nil {
		return httpio.NewUnauthorizedMessageWithError(err, "Invalid Credentials")
	}
	if upgrade && p.settings.AutoUpgrade {
		if err := p.setPasswordHash(ctx, user.ID, password); err != nil {
			logger.FromCtx(ctx).Error(err)
		} else {
			logger.FromCtx(ctx).Infof("auto-upgraded password hash for user %s, from %s to %s", user.Username, user.PasswordHash.KeyType(), p.settings.Hasher.KeyType())
		}
	}

	if user.Disabled {
		return httpio.NewUnauthorizedMessageWithError(err, "User disabled")
	}

	return nil
}

// comparePassword checks password against hash, reporting whether the hash should be
// upgraded. A nil hash never matches.
func (p *PasswordAuth[T, U]) comparePassword(hash *securehash.Hash, password string) (upgrade bool, err error) {
	return sessioncore.ComparePassword(p.settings.Hasher, hash, password)
}

// ValidateSession checks the sessionID in the database to validate that it has not expired
// and updates the last activity timestamp if it is still valid.
// StartSession handler must be called before calling ValidateSession
func (p *PasswordAuth[T, U]) ValidateSession(next http.Handler) http.Handler {
	return p.baseSession.Handle(func(w http.ResponseWriter, r *http.Request) error {
		ctx, span := tracer.Start(r.Context())
		defer span.End()

		ctx, err := p.baseSession.ValidateSessionAPI(ctx)
		if err != nil {
			return httpio.NewEncoder(w).ClientMessage(ctx, err)
		}

		sessInfo := sessioninfo.FromCtx(ctx)

		userInfo, err := sessioncore.SessionUserInfo(ctx, p.storage, sessInfo)
		if err != nil {
			return httpio.NewEncoder(w).ClientMessage(ctx, err)
		}

		// Store user info in context
		ctx = context.WithValue(ctx, sessioninfo.CtxUserInfo, userInfo)

		next.ServeHTTP(w, r.WithContext(ctx))

		return nil
	})
}

// Authenticated is the handler that reports if the session is authenticated
func (p *PasswordAuth[T, U]) Authenticated() http.HandlerFunc {
	type response struct {
		Authenticated bool                               `json:"authenticated"`
		Username      string                             `json:"username"`
		Impersonation *basesession.ImpersonationResponse `json:"impersonation,omitempty"`
	}

	return p.baseSession.Handle(func(w http.ResponseWriter, r *http.Request) error {
		ctx, span := tracer.Start(r.Context())
		defer span.End()

		ctx, err := p.baseSession.ValidateSessionAPI(ctx)
		if err != nil {
			if httpio.HasUnauthorized(err) {
				return httpio.NewEncoder(w).Ok(response{})
			}

			return httpio.NewEncoder(w).ClientMessage(ctx, err)
		}

		sessInfo := sessioninfo.FromCtx(ctx)

		if _, err := sessioncore.SessionUserInfo(ctx, p.storage, sessInfo); err != nil {
			return httpio.NewEncoder(w).ClientMessage(ctx, err)
		}

		imp, _ := sessioninfo.ImpersonationFromCtx(ctx)

		// set response values
		res := response{
			Authenticated: true,
			Username:      sessInfo.Username,
			Impersonation: basesession.NewImpersonationResponse(imp),
		}

		return httpio.NewEncoder(w).Ok(res)
	})
}

// ChangeUsername handles modifications to the username
func (p *PasswordAuth[T, U]) ChangeUsername() http.HandlerFunc {
	type request struct {
		Username string `json:"username"`
	}

	decoder := sessioncore.NewDecoder[request]()

	return p.baseSession.Handle(func(w http.ResponseWriter, r *http.Request) error {
		ctx, span := tracer.Start(r.Context())
		defer span.End()

		if err := sessioncore.RefuseImpersonated(ctx, p.baseSession, "ChangeUsername", true); err != nil {
			return httpio.NewEncoder(w).ClientMessage(ctx, err)
		}

		req, err := decoder.Decode(r)
		if err != nil {
			return httpio.NewEncoder(w).ClientMessage(ctx, err)
		}

		userInfo := sessioninfo.UserFromCtx(ctx)

		if err := p.changeSessionUserUsername(ctx, userInfo.ID, req.Username); err != nil {
			return httpio.NewEncoder(w).ClientMessage(ctx, err)
		}

		return httpio.NewEncoder(w).Ok(nil)
	})
}

// ChangeUserPassword handles modifications to a user password. All of the user's sessions
// are destroyed and a new session is started for the caller, so the caller remains
// authenticated under a new session ID.
func (p *PasswordAuth[T, U]) ChangeUserPassword() http.HandlerFunc {
	type request struct {
		OldPassword string `json:"oldPassword"`
		NewPassword string `json:"newPassword"`
	}

	decoder := sessioncore.NewDecoder[request]()

	return p.baseSession.Handle(func(w http.ResponseWriter, r *http.Request) error {
		ctx, span := tracer.Start(r.Context())
		defer span.End()

		if err := sessioncore.RefuseImpersonated(ctx, p.baseSession, "ChangeUserPassword", true); err != nil {
			return httpio.NewEncoder(w).ClientMessage(ctx, err)
		}

		req, err := decoder.Decode(r)
		if err != nil {
			return httpio.NewEncoder(w).ClientMessage(ctx, err)
		}

		userInfo := sessioninfo.UserFromCtx(ctx)

		if err := p.changeSessionUserPassword(ctx, w, userInfo.ID, (*session.ChangeSessionUserPasswordRequest)(req)); err != nil {
			return httpio.NewEncoder(w).ClientMessage(ctx, err)
		}

		return httpio.NewEncoder(w).Ok(nil)
	})
}

// CreateUser handles creating a user.
func (p *PasswordAuth[T, U]) CreateUser() http.HandlerFunc {
	type request struct {
		Username string  `json:"username"`
		Password *string `json:"password"`
		Disabled bool    `json:"disabled"`
	}

	type response struct {
		ID ccc.UUID `json:"id"`
	}

	decoder := sessioncore.NewDecoder[request]()

	return p.baseSession.Handle(func(w http.ResponseWriter, r *http.Request) error {
		ctx, span := tracer.Start(r.Context())
		defer span.End()

		if err := sessioncore.RefuseImpersonated(ctx, p.baseSession, "CreateUser", false); err != nil {
			return httpio.NewEncoder(w).ClientMessage(ctx, err)
		}

		req, err := decoder.Decode(r)
		if err != nil {
			return httpio.NewEncoder(w).ClientMessage(ctx, err)
		}

		id, err := p.createSessionUser(ctx, (*session.CreateUserRequest)(req), nil)
		if err != nil {
			return httpio.NewEncoder(w).ClientMessage(ctx, err)
		}

		return httpio.NewEncoder(w).Ok(response{ID: id})
	})
}

// DeactivateUser handles deactivating a user. The request is rejected with
// 400 Bad Request when the target is the session's own user, so a user cannot
// deactivate themselves.
func (p *PasswordAuth[T, U]) DeactivateUser() http.HandlerFunc {
	return p.baseSession.Handle(func(w http.ResponseWriter, r *http.Request) error {
		ctx, span := tracer.Start(r.Context())
		defer span.End()

		if err := sessioncore.RefuseImpersonated(ctx, p.baseSession, "DeactivateUser", false); err != nil {
			return httpio.NewEncoder(w).ClientMessage(ctx, err)
		}

		sessionUserID := httpio.Param[ccc.UUID](r, RouterSessionUserID)

		if sessionUserID == sessioninfo.UserFromCtx(ctx).ID {
			return httpio.NewEncoder(w).BadRequestMessage(ctx, "cannot deactivate yourself")
		}

		if err := p.deactivateSessionUser(ctx, sessionUserID); err != nil {
			return httpio.NewEncoder(w).ClientMessage(ctx, err)
		}

		return httpio.NewEncoder(w).Ok(nil)
	})
}

// DeleteUser handles deleting a user. The request is rejected with
// 400 Bad Request when the target is the session's own user, so a user cannot
// delete themselves.
func (p *PasswordAuth[T, U]) DeleteUser() http.HandlerFunc {
	return p.baseSession.Handle(func(w http.ResponseWriter, r *http.Request) error {
		ctx, span := tracer.Start(r.Context())
		defer span.End()

		if err := sessioncore.RefuseImpersonated(ctx, p.baseSession, "DeleteUser", false); err != nil {
			return httpio.NewEncoder(w).ClientMessage(ctx, err)
		}

		sessionUserID := httpio.Param[ccc.UUID](r, RouterSessionUserID)

		if sessionUserID == sessioninfo.UserFromCtx(ctx).ID {
			return httpio.NewEncoder(w).BadRequestMessage(ctx, "cannot delete yourself")
		}

		if err := p.deleteSessionUser(ctx, sessionUserID); err != nil {
			return httpio.NewEncoder(w).ClientMessage(ctx, err)
		}

		return httpio.NewEncoder(w).Ok(nil)
	})
}

// ActivateUser handles activating a user.
func (p *PasswordAuth[T, U]) ActivateUser() http.HandlerFunc {
	return p.baseSession.Handle(func(w http.ResponseWriter, r *http.Request) error {
		ctx, span := tracer.Start(r.Context())
		defer span.End()

		if err := sessioncore.RefuseImpersonated(ctx, p.baseSession, "ActivateUser", false); err != nil {
			return httpio.NewEncoder(w).ClientMessage(ctx, err)
		}

		sessionUserUUID := httpio.Param[ccc.UUID](r, RouterSessionUserID)
		if err := p.activateSessionUser(ctx, sessionUserUUID); err != nil {
			return httpio.NewEncoder(w).ClientMessage(ctx, err)
		}

		return httpio.NewEncoder(w).Ok(nil)
	})
}

// startNewSession starts a new session for the given username and returns the session ID.
// The reason is passed through to any configured custom session data resolver, which runs
// inside the session-insert transaction. When customData (*T, may be nil) is provided it
// is written atomically with the session insert and the configured resolver is skipped.
func (p *PasswordAuth[T, U]) startNewSession(
	ctx context.Context, w http.ResponseWriter, reason sessioninfo.NewSessionReason, username string, userID ccc.UUID, customData *T,
) (ccc.UUID, error) {
	req := &sessioninfo.NewSessionRequest{
		Reason:   reason,
		Username: username,
		UserID:   userID,
	}
	if customData != nil {
		req.CustomData = customData
	}

	return sessioncore.EstablishSession(ctx, w, p.baseSession, sessioncore.SameSiteStrict, func(ctx context.Context) (ccc.UUID, error) {
		id, err := p.storage.CreateSession(ctx, req)
		if err != nil {
			return ccc.NilUUID, errors.Wrap(err, "sessionstorage.PasswordAuthStore.CreateSession()")
		}

		return id, nil
	})
}

func (p *PasswordAuth[T, U]) setPasswordHash(ctx context.Context, userID ccc.UUID, password string) error {
	newHash, err := p.settings.Hasher.Hash(password)
	if err != nil {
		return errors.Wrap(err, "securehash.SecureHasher.Hash()")
	}

	if err := p.storage.SetUserPasswordHash(ctx, userID, newHash); err != nil {
		return errors.Wrap(err, "sessionstorage.PasswordAuthStore.SetUserPasswordHash()")
	}

	return nil
}

// changeSessionUserUsername handles modifications to a user username.
// The user record and every active session row for that user are updated atomically,
// preserving the acting session and any other sessions the user has open.
func (p *PasswordAuth[T, U]) changeSessionUserUsername(ctx context.Context, userID ccc.UUID, username string) error {
	if err := p.storage.SetUserUsername(ctx, userID, username); err != nil {
		return errors.Wrap(err, "sessionstorage.PasswordAuthStore.SetUserUsername()")
	}

	logger.FromCtx(ctx).AddRequestAttribute("Username", username)

	return nil
}

// changeSessionUserPassword handles modifications to a user password. A password change is a
// privilege level change, so every session for the user is destroyed and a new session is
// started for the caller. This regenerates the session ID and destroys the previous one, which
// is what protects against session fixation: an attacker holding a session ID that was fixed
// or captured before the password change cannot keep using it afterward.
//
// See the OWASP Session Management Cheat Sheet, "Renew the Session ID After Any Privilege
// Level Change", which names password changes explicitly.
func (p *PasswordAuth[T, U]) changeSessionUserPassword(ctx context.Context, w http.ResponseWriter, userID ccc.UUID, req *session.ChangeSessionUserPasswordRequest) error {
	// Validate credentials
	user, err := p.storage.User(ctx, userID)
	if err != nil {
		return errors.Wrap(err, "sessionstorage.PasswordAuthStore.User()")
	}
	if _, err := p.comparePassword(user.PasswordHash, req.OldPassword); err != nil {
		return httpio.NewBadRequestMessageWithError(err, "Old password incorrect")
	}

	if err := p.storage.DestroyAllUserSessions(ctx, user.Username); err != nil {
		return errors.Wrap(err, "sessionstorage.PasswordAuthStore.DestroyAllUserSessions()")
	}

	if err := p.setPasswordHash(ctx, user.ID, req.NewPassword); err != nil {
		return errors.Wrap(err, "PasswordAuth.setPasswordHash()")
	}

	// Start a new session so the caller remains authenticated under a new session ID.
	// Custom session data is resolved fresh for the new session; values previously set
	// via UpdateCustomSessionData do not carry over.
	sessionID, err := p.startNewSession(ctx, w, sessioninfo.ReasonRegeneration, user.Username, user.ID, nil)
	if err != nil {
		return errors.Wrap(err, "PasswordAuth.startNewSession()")
	}

	sessioncore.LogSessionStarted(ctx, user.Username, sessionID)

	return nil
}

// changeSessionUserHash handles modifications to a user hash. This can be used when
// users are being migrated, and passwords are not know, but the hash is compatible
func (p *PasswordAuth[T, U]) changeSessionUserHash(ctx context.Context, userID ccc.UUID, hash *securehash.Hash) error {
	if err := p.storage.SetUserPasswordHash(ctx, userID, hash); err != nil {
		return errors.Wrap(err, "sessionstorage.PasswordAuthStore.SetUserPasswordHash()")
	}

	return nil
}

// createSessionUser handles creating a user. When customData (*U, may be nil)
// is provided it is written atomically with the user insert.
func (p *PasswordAuth[T, U]) createSessionUser(ctx context.Context, req *session.CreateUserRequest, customData *U) (ccc.UUID, error) {
	var hash *securehash.Hash
	if req.Password != nil {
		var err error
		hash, err = p.settings.Hasher.Hash(*req.Password)
		if err != nil {
			return ccc.NilUUID, errors.Wrap(err, "securehash.SecureHasher.Hash()")
		}
	}

	insertUser := &sessionstorage.InsertSessionUser{
		Username:     req.Username,
		PasswordHash: hash,
		Disabled:     req.Disabled,
	}

	// Explicit conversion so a typed nil *U never crosses as a non-nil any.
	var data any
	if customData != nil {
		data = customData
	}

	user, err := p.storage.CreateUser(ctx, insertUser, data)
	if err != nil {
		return ccc.NilUUID, errors.Wrap(err, "sessionstorage.PasswordAuthStore.CreateUser()")
	}

	return user.ID, nil
}

// deleteSessionUser handles deleting a user. Performs no self-deletion
// check; that is the caller's responsibility.
func (p *PasswordAuth[T, U]) deleteSessionUser(ctx context.Context, sessionUserID ccc.UUID) error {
	user, err := p.storage.User(ctx, sessionUserID)
	if err != nil {
		return errors.Wrap(err, "sessionstorage.PasswordAuthStore.User()")
	}

	if err := p.storage.DeleteUser(ctx, user.ID); err != nil {
		return errors.Wrap(err, "sessionstorage.PasswordAuthStore.DeleteUser()")
	}

	if err := p.storage.DestroyAllUserSessions(ctx, user.Username); err != nil {
		return errors.Wrap(err, "sessionstorage.PasswordAuthStore.DestroyAllUserSessions()")
	}

	return nil
}

// deactivateSessionUser handles deactivating a user. Performs no
// self-deactivation check; that is the caller's responsibility.
func (p *PasswordAuth[T, U]) deactivateSessionUser(ctx context.Context, sessionUserID ccc.UUID) error {
	user, err := p.storage.User(ctx, sessionUserID)
	if err != nil {
		return errors.Wrap(err, "sessionstorage.PasswordAuthStore.User()")
	}

	if err := p.storage.DeactivateUser(ctx, user.ID); err != nil {
		return errors.Wrap(err, "sessionstorage.PasswordAuthStore.DeactivateUser()")
	}

	if err := p.storage.DestroyAllUserSessions(ctx, user.Username); err != nil {
		return errors.Wrap(err, "sessionstorage.PasswordAuthStore.DestroyAllUserSessions()")
	}

	return nil
}

// activateSessionUser handles activating a user.
func (p *PasswordAuth[T, U]) activateSessionUser(ctx context.Context, sessionUserUUID ccc.UUID) error {
	if err := p.storage.ActivateUser(ctx, sessionUserUUID); err != nil {
		return errors.Wrap(err, "sessionstorage.PasswordAuthStore.ActivateUser()")
	}

	return nil
}

// updateCustomSessionData updates the custom session data for an active session via a
// typed transactional read-modify-write.
func (p *PasswordAuth[T, U]) updateCustomSessionData(ctx context.Context, sessionID ccc.UUID, mutate func(data *T) error) error {
	return p.shared().UpdateCustomSessionData(ctx, sessionID, mutate)
}

// shared returns the API methods every session type shares, over this session's fields.
func (p *PasswordAuth[T, U]) shared() sessioncore.API[T, U] {
	return sessioncore.API[T, U]{Base: p.baseSession, Store: p.storage, Users: p.storage, StoreName: "PasswordAuthStore"}
}

// API provides programatic access to PasswordAuth handler internals
func (p *PasswordAuth[T, U]) API() *PasswordAuthAPI[T, U] {
	return newPasswordAuthAPI(p)
}

// PasswordAuthAPI provides programatic access to PasswordAuth handler internals
//
// Deprecated: the legacy username-and-password session; use session.Auth with session.PasswordSignIn, which shares the session, the user model and the middleware with every other sign-in method.
type PasswordAuthAPI[SessionData, UserData any] struct {
	passwordAuth *PasswordAuth[SessionData, UserData]
}

func newPasswordAuthAPI[T, U any](passwordAuth *PasswordAuth[T, U]) *PasswordAuthAPI[T, U] {
	return &PasswordAuthAPI[T, U]{
		passwordAuth: passwordAuth,
	}
}

// ValidateCredentials validates the username and password, without creating a session.
func (p *PasswordAuthAPI[T, U]) ValidateCredentials(ctx context.Context, username, password string) error {
	user, err := p.passwordAuth.storage.UserByUserName(ctx, username)
	if err != nil {
		return httpio.NewUnauthorizedMessageWithError(err, "Invalid Credentials")
	}

	return p.passwordAuth.validateCredentials(ctx, user, password)
}

// Login validates the username and password and creates a new session for the user.
func (p *PasswordAuthAPI[T, U]) Login(ctx context.Context, w http.ResponseWriter, username, password string) error {
	return p.passwordAuth.loginAPI(ctx, w, username, password)
}

// StartAuthenticatedSession creates a new authenticated session for the given username,
// bypassing the login process. This is intended for scenarios where the user has
// already been authenticated by an external system.
//
// It requires an existing, non-disabled user record and participates fully in custom
// session data (the resolver receives ReasonExternalAuth). For a trust-the-caller
// stepping-stone session with no user record — e.g. an MFA-pending flow — use
// Preauth.API().Login() instead.
//
// Optional customData (at most one *T) is written atomically with the session insert —
// the session and its custom data row land together or not at all. When customData is
// provided, the configured custom session data resolver is NOT invoked for this
// creation (per-call data wins); it requires a custom session data configuration on
// the storage. When no customData is provided the configured resolver (if any) runs as
// usual. See the "Custom session data" section of the README for the full lifecycle.
func (p *PasswordAuthAPI[T, U]) StartAuthenticatedSession(ctx context.Context, w http.ResponseWriter, username string, customData ...*T) (ccc.UUID, error) {
	ctx, span := tracer.Start(ctx)
	defer span.End()

	if len(customData) > 1 {
		return ccc.NilUUID, errors.New("at most one customData value may be provided; it is the complete custom session data row")
	}
	var data *T
	if len(customData) == 1 {
		data = customData[0]
	}

	user, err := p.passwordAuth.storage.UserByUserName(ctx, username)
	if err != nil {
		return ccc.NilUUID, errors.Wrap(err, "sessionstorage.PasswordAuthStore.UserByUserName()")
	}

	if user.Disabled {
		return ccc.NilUUID, httpio.NewUnauthorizedMessage("User disabled")
	}

	sessionID, err := p.passwordAuth.startNewSession(ctx, w, sessioninfo.ReasonExternalAuth, user.Username, user.ID, data)
	if err != nil {
		return ccc.NilUUID, errors.Wrap(err, "PasswordAuth.startNewSession()")
	}

	sessioncore.LogSessionStarted(ctx, user.Username, sessionID)

	return sessionID, nil
}

// Logout destroys the current session
func (p *PasswordAuthAPI[T, U]) Logout(ctx context.Context) error {
	return p.passwordAuth.shared().Logout(ctx)
}

// StartSession initializes a session by restoring it from a cookie, or if
// that fails, initializing a new session. The session cookie is then updated and
// the sessionID is inserted into the context.
func (p *PasswordAuthAPI[T, U]) StartSession(ctx context.Context, w http.ResponseWriter, r *http.Request) (context.Context, error) {
	return p.passwordAuth.shared().StartSession(ctx, w, r)
}

// ValidateSession checks the sessionID in the database to validate that it has not expired
// and updates the last activity timestamp if it is still valid.
// StartSession handler must be called before calling ValidateSession
func (p *PasswordAuthAPI[T, U]) ValidateSession(ctx context.Context) (context.Context, error) {
	return p.passwordAuth.shared().ValidateSession(ctx)
}

// ChangeSessionUserUsername handles modifications to a user username.
// The user record and every active session row for that user are updated atomically,
// preserving the acting session and any other sessions the user has open.
func (p *PasswordAuthAPI[T, U]) ChangeSessionUserUsername(ctx context.Context, userID ccc.UUID, username string) error {
	return p.passwordAuth.changeSessionUserUsername(ctx, userID, username)
}

// ChangeSessionUserPassword handles modifications to a user password. All of the user's
// sessions are destroyed and a new session is started for the caller, so the caller remains
// authenticated under a new session ID. Requires the ResponseWriter for the new session cookies.
func (p *PasswordAuthAPI[T, U]) ChangeSessionUserPassword(ctx context.Context, w http.ResponseWriter, userID ccc.UUID, req *session.ChangeSessionUserPasswordRequest) error {
	return p.passwordAuth.changeSessionUserPassword(ctx, w, userID, req)
}

// ChangeSessionUserHash handles modifications to a user hash.
func (p *PasswordAuthAPI[T, U]) ChangeSessionUserHash(ctx context.Context, userID ccc.UUID, hash *securehash.Hash) error {
	return p.passwordAuth.changeSessionUserHash(ctx, userID, hash)
}

// CreateSessionUser handles creating a user.
//
// Optional customData (at most one *U) is the user's initial custom user data, written
// atomically with the user insert — the user record and its custom data row land
// together or not at all. It requires a custom user data configuration on the storage.
// See the "Custom user data" section of the README for the full lifecycle.
func (p *PasswordAuthAPI[T, U]) CreateSessionUser(ctx context.Context, req *session.CreateUserRequest, customData ...*U) (ccc.UUID, error) {
	if len(customData) > 1 {
		return ccc.NilUUID, errors.New("at most one customData value may be provided; it is the complete custom user data row")
	}
	var data *U
	if len(customData) == 1 {
		data = customData[0]
	}

	return p.passwordAuth.createSessionUser(ctx, req, data)
}

// CustomUserData returns the strongly typed custom user data for the given user. A user
// with no custom data row yields a zero-value U. Custom user data is durable — it lives
// and dies with the user record — and is read on demand, never from the session context.
func (p *PasswordAuthAPI[T, U]) CustomUserData(ctx context.Context, userID ccc.UUID) (U, error) {
	return p.passwordAuth.shared().CustomUserData(ctx, userID)
}

// UpdateCustomUserData updates the custom user data for an existing user via a
// transactional read-modify-write: mutate receives the current row (zero-value U when
// no row exists), and the full row is written back; a mutate error aborts with nothing
// written. Initial population belongs in the creation path (per-call custom data on
// CreateSessionUser), which is atomic with the user insert. See the "Custom user data"
// section of the README for the full lifecycle.
func (p *PasswordAuthAPI[T, U]) UpdateCustomUserData(ctx context.Context, userID ccc.UUID, mutate func(data *U) error) error {
	return p.passwordAuth.shared().UpdateCustomUserData(ctx, userID, mutate)
}

// DeleteSessionUser handles deleting a user. The user record is deleted
// and all of the user's active sessions are destroyed.
//
// No self-deletion guard is applied here: this method does not read the acting
// user from the context, so callers that need to prevent a user from deleting
// themselves must enforce that check. The HTTP handler DeleteUser() applies it.
func (p *PasswordAuthAPI[T, U]) DeleteSessionUser(ctx context.Context, sessionUserID ccc.UUID) error {
	return p.passwordAuth.deleteSessionUser(ctx, sessionUserID)
}

// DeactivateSessionUser handles deactivating a user. The user record is
// deactivated and all of the user's active sessions are destroyed.
//
// No self-deactivation guard is applied here: this method does not read the acting
// user from the context, so callers that need to prevent a user from deactivating
// themselves must enforce that check. The HTTP handler DeactivateUser() applies it.
func (p *PasswordAuthAPI[T, U]) DeactivateSessionUser(ctx context.Context, sessionUserID ccc.UUID) error {
	return p.passwordAuth.deactivateSessionUser(ctx, sessionUserID)
}

// ActivateSessionUser handles activating a user
func (p *PasswordAuthAPI[T, U]) ActivateSessionUser(ctx context.Context, sessionUserUUID ccc.UUID) error {
	return p.passwordAuth.activateSessionUser(ctx, sessionUserUUID)
}

// DestroyAllUserSessions destroys all sessions for a given user
func (p *PasswordAuthAPI[T, U]) DestroyAllUserSessions(ctx context.Context, username string) error {
	if err := p.passwordAuth.storage.DestroyAllUserSessions(ctx, username); err != nil {
		return errors.Wrap(err, "sessionstorage.PreauthStore.DestroyAllUserSessions()")
	}

	return nil
}

// UpdateCustomSessionData updates the custom session data for an active session via a
// transactional read-modify-write: mutate receives the current row (zero-value T when
// no row exists), and the full row is written back; a mutate error aborts with nothing
// written. It is intended for genuine mid-session updates only — initial population
// belongs in the creation path (the configured resolver, or per-call custom data on
// StartAuthenticatedSession), which is atomic with the session insert. See the
// "Custom session data" section of the README for the full lifecycle.
func (p *PasswordAuthAPI[T, U]) UpdateCustomSessionData(ctx context.Context, sessionID ccc.UUID, mutate func(data *T) error) error {
	return p.passwordAuth.updateCustomSessionData(ctx, sessionID, mutate)
}

// CustomData returns the strongly typed custom session data for the current session
// from the context. A session with no custom data row yields a zero-value T.
func (p *PasswordAuthAPI[T, U]) CustomData(ctx context.Context) (T, error) {
	return p.passwordAuth.shared().CustomData(ctx)
}

// Cookie returns the underlying cookie.Client
func (p *PasswordAuthAPI[T, U]) Cookie() *cookie.Client {
	return p.passwordAuth.shared().Cookie()
}
