package session

import (
	"context"
	"net/http"

	"github.com/cccteam/ccc"
	"github.com/cccteam/ccc/resource"
	"github.com/cccteam/ccc/securehash"
	"github.com/cccteam/httpio"
	"github.com/cccteam/logger"
	"github.com/cccteam/session/internal/basesession"
	"github.com/cccteam/session/internal/cookie"
	"github.com/cccteam/session/internal/dbtype"
	"github.com/cccteam/session/internal/types"
	"github.com/cccteam/session/sessioninfo"
	"github.com/cccteam/session/sessionstorage"
	"github.com/go-playground/errors/v5"
	"github.com/gorilla/securecookie"
)

const (
	// RouterSessionUserID is a constant used for matching the SessionUserID in the router path
	RouterSessionUserID = "sessionUserID"
)

// PasswordOption defines the interface for functional options used when creating a new Password.
type PasswordOption interface {
	isPasswordOption()
}

var _ PasswordAuthHandlers = &PasswordAuth{}

// PasswordAuth implements the PasswordHandlers interface for handling password authentication.
type PasswordAuth struct {
	storage     sessionstorage.PasswordAuthStore
	hasher      *securehash.SecureHasher
	autoUpgrade bool
	baseSession *basesession.BaseSession
}

// NewPasswordAuth creates a new PasswordAuth.
func NewPasswordAuth(storage sessionstorage.PasswordAuthStore, secureCookie *securecookie.SecureCookie, options ...PasswordOption) *PasswordAuth {
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
		}
	}

	p := &PasswordAuth{
		storage:     storage,
		hasher:      securehash.New(securehash.Argon2()),
		autoUpgrade: true,
		baseSession: baseSession,
	}

	for _, opt := range options {
		switch o := any(opt).(type) {
		case passwordOption:
			o(p)
		default:
		}
	}

	return p
}

// Logout destroys the current session
func (p *PasswordAuth) Logout() http.HandlerFunc {
	return p.baseSession.Logout()
}

// SetXSRFToken sets the XSRF Token
func (p *PasswordAuth) SetXSRFToken(next http.Handler) http.Handler {
	return p.baseSession.SetXSRFToken(next)
}

// ValidateXSRFToken validates the XSRF Token
func (p *PasswordAuth) ValidateXSRFToken(next http.Handler) http.Handler {
	return p.baseSession.ValidateXSRFToken(next)
}

// StartSession initializes a session by restoring it from a cookie, or if that fails, initializing
// a new session. The session cookie is then updated and the sessionID is inserted into the context.
func (p *PasswordAuth) StartSession(next http.Handler) http.Handler {
	return p.baseSession.StartSession(next)
}

// Login validates the username and password and establishes the sessoin cookie.
func (p *PasswordAuth) Login() http.HandlerFunc {
	type request struct {
		Username string `json:"username"`
		Password string `json:"password"`
	}

	decoder := newDecoder[request]()

	return p.baseSession.Handle(func(w http.ResponseWriter, r *http.Request) error {
		ctx, span := ccc.StartTrace(r.Context())
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

func (p *PasswordAuth) loginAPI(ctx context.Context, w http.ResponseWriter, username, password string) error {
	// Validate credentials
	user, err := p.storage.UserByUserName(ctx, username)
	if err != nil {
		return httpio.NewUnauthorizedMessageWithError(err, "Invalid Credentials")
	}
	upgrade, err := p.hasher.Compare(user.PasswordHash, password)
	if err != nil {
		return httpio.NewUnauthorizedMessageWithError(err, "Invalid Credentials")
	}
	if upgrade && p.autoUpgrade {
		if err := p.setPasswordHash(ctx, user.ID, password); err != nil {
			logger.FromCtx(ctx).Error(err)
		} else {
			logger.FromCtx(ctx).Infof("auto-upgraded password hash for user %s, from %s to %s", user.Username, user.PasswordHash.KeyType(), p.hasher.KeyType())
		}
	}

	if user.Disabled {
		return httpio.NewUnauthorizedMessageWithError(err, "Account disabled")
	}

	// user is successfully authenticated, start a new session
	sessionID, err := p.startNewSession(ctx, w, user.Username)
	if err != nil {
		return errors.Wrap(err, "PasswordAuth.startNewSession()")
	}

	// Log the association between the sessionID and Username
	logger.FromCtx(ctx).AddRequestAttribute("Username", user.Username).AddRequestAttribute(string(types.SCSessionID), sessionID)

	return nil
}

// ValidateSession checks the sessionID in the database to validate that it has not expired
// and updates the last activity timestamp if it is still valid.
// StartSession handler must be called before calling ValidateSession
func (p *PasswordAuth) ValidateSession(next http.Handler) http.Handler {
	return p.baseSession.Handle(func(w http.ResponseWriter, r *http.Request) error {
		ctx, span := ccc.StartTrace(r.Context())
		defer span.End()

		ctx, err := p.baseSession.ValidateSessionAPI(ctx)
		if err != nil {
			return httpio.NewEncoder(w).ClientMessage(ctx, err)
		}

		sessInfo := sessioninfo.FromCtx(ctx)

		user, err := p.storage.UserByUserName(ctx, sessInfo.Username)
		if err != nil {
			return httpio.NewEncoder(w).InternalServerErrorWithError(ctx, err)
		}

		if user.Disabled {
			return httpio.NewEncoder(w).UnauthorizedMessage(ctx, "Session Expired")
		}

		// Store user info in context
		ctx = context.WithValue(ctx, sessioninfo.CtxUserInfo, &sessioninfo.UserInfo{
			ID:       user.ID,
			Username: user.Username,
			Disabled: user.Disabled,
		})

		next.ServeHTTP(w, r.WithContext(ctx))

		return nil
	})
}

// Authenticated is the handler that reports if the session is authenticated
func (p *PasswordAuth) Authenticated() http.HandlerFunc {
	type response struct {
		Authenticated bool   `json:"authenticated"`
		Username      string `json:"username"`
	}

	return p.baseSession.Handle(func(w http.ResponseWriter, r *http.Request) error {
		ctx, span := ccc.StartTrace(r.Context())
		defer span.End()

		ctx, err := p.baseSession.ValidateSessionAPI(ctx)
		if err != nil {
			if httpio.HasUnauthorized(err) {
				return httpio.NewEncoder(w).Ok(response{})
			}

			return httpio.NewEncoder(w).ClientMessage(ctx, err)
		}

		sessInfo := sessioninfo.FromCtx(ctx)

		user, err := p.storage.UserByUserName(ctx, sessInfo.Username)
		if err != nil {
			return httpio.NewEncoder(w).InternalServerErrorWithError(ctx, err)
		}

		if user.Disabled {
			return httpio.NewEncoder(w).UnauthorizedMessage(ctx, "Session Expired")
		}

		// set response values
		res := response{
			Authenticated: true,
			Username:      sessInfo.Username,
		}

		return httpio.NewEncoder(w).Ok(res)
	})
}

// ChangeUserPassword handles modifications to a user password
func (p *PasswordAuth) ChangeUserPassword() http.HandlerFunc {
	type request struct {
		OldPassword string `json:"oldPassword"`
		NewPassword string `json:"newPassword"`
	}

	decoder := newDecoder[request]()

	return p.baseSession.Handle(func(w http.ResponseWriter, r *http.Request) error {
		ctx, span := ccc.StartTrace(r.Context())
		defer span.End()

		req, err := decoder.Decode(r)
		if err != nil {
			return httpio.NewEncoder(w).ClientMessage(ctx, err)
		}

		userInfo := sessioninfo.UserFromCtx(ctx)

		if err := p.changeSessionUserPassword(ctx, userInfo.ID, (*ChangeSessionUserPasswordRequest)(req)); err != nil {
			return httpio.NewEncoder(w).ClientMessage(ctx, err)
		}

		return httpio.NewEncoder(w).Ok(nil)
	})
}

// CreateUser handles creating a user account.
func (p *PasswordAuth) CreateUser() http.HandlerFunc {
	type request struct {
		Username string  `json:"username"`
		Password *string `json:"password"`
		Disabled bool    `json:"disabled"`
	}

	type response struct {
		ID ccc.UUID `json:"id"`
	}

	decoder := newDecoder[request]()

	return p.baseSession.Handle(func(w http.ResponseWriter, r *http.Request) error {
		ctx, span := ccc.StartTrace(r.Context())
		defer span.End()

		req, err := decoder.Decode(r)
		if err != nil {
			return httpio.NewEncoder(w).ClientMessage(ctx, err)
		}

		id, err := p.createSessionUser(ctx, (*CreateUserRequest)(req))
		if err != nil {
			return httpio.NewEncoder(w).ClientMessage(ctx, err)
		}

		return httpio.NewEncoder(w).Ok(response{ID: id})
	})
}

// DeactivateUser handles deactivating a user account.
func (p *PasswordAuth) DeactivateUser() http.HandlerFunc {
	return p.baseSession.Handle(func(w http.ResponseWriter, r *http.Request) error {
		ctx, span := ccc.StartTrace(r.Context())
		defer span.End()

		sessionUserID := httpio.Param[ccc.UUID](r, RouterSessionUserID)
		if err := p.deactivateSessionUser(ctx, sessionUserID); err != nil {
			return httpio.NewEncoder(w).ClientMessage(ctx, err)
		}

		return httpio.NewEncoder(w).Ok(nil)
	})
}

// DeleteUser handles deleting a user account.
func (p *PasswordAuth) DeleteUser() http.HandlerFunc {
	return p.baseSession.Handle(func(w http.ResponseWriter, r *http.Request) error {
		ctx, span := ccc.StartTrace(r.Context())
		defer span.End()

		sessionUserID := httpio.Param[ccc.UUID](r, RouterSessionUserID)
		if err := p.deleteSessionUser(ctx, sessionUserID); err != nil {
			return httpio.NewEncoder(w).ClientMessage(ctx, err)
		}

		return httpio.NewEncoder(w).Ok(nil)
	})
}

// ActivateUser handles activating a user account.
func (p *PasswordAuth) ActivateUser() http.HandlerFunc {
	return p.baseSession.Handle(func(w http.ResponseWriter, r *http.Request) error {
		ctx, span := ccc.StartTrace(r.Context())
		defer span.End()

		sessionUserUUID := httpio.Param[ccc.UUID](r, RouterSessionUserID)
		if err := p.activateSessionUser(ctx, sessionUserUUID); err != nil {
			return httpio.NewEncoder(w).ClientMessage(ctx, err)
		}

		return httpio.NewEncoder(w).Ok(nil)
	})
}

// startNewSession starts a new session for the given username and returns the session ID
func (p *PasswordAuth) startNewSession(ctx context.Context, w http.ResponseWriter, username string) (ccc.UUID, error) {
	// Create new Session in database
	id, err := p.storage.NewSession(ctx, username)
	if err != nil {
		return ccc.NilUUID, errors.Wrap(err, "sessionstorage.PreauthStore.NewSession()")
	}

	if _, err := p.baseSession.NewAuthCookie(w, false, id); err != nil {
		return ccc.NilUUID, errors.Wrap(err, "cookie.CookieHandler.NewAuthCookie()")
	}

	// write new XSRF Token Cookie to match the new SessionID
	if err := p.baseSession.CreateXSRFTokenCookie(w, id, types.XSRFCookieLife); err != nil {
		return ccc.NilUUID, errors.Wrap(err, "session.BaseSession.SetXSRFTokenCookie()")
	}

	return id, nil
}

func (p *PasswordAuth) setPasswordHash(ctx context.Context, userID ccc.UUID, password string) error {
	newHash, err := p.hasher.Hash(password)
	if err != nil {
		return errors.Wrap(err, "securehash.SecureHasher.Hash()")
	}

	if err := p.storage.SetUserPasswordHash(ctx, userID, newHash); err != nil {
		return errors.Wrap(err, "sessionstorage.PasswordAuthStore.SetUserPasswordHash()")
	}

	return nil
}

// newDecoder returns an httpio.Decoder to simplify the validator call to a single location
func newDecoder[T any]() *resource.StructDecoder[T] {
	decoder, err := resource.NewStructDecoder[T]()
	if err != nil {
		panic(err)
	}

	return decoder
}

// changeSessionUserPassword handles modifications to a user password
func (p *PasswordAuth) changeSessionUserPassword(ctx context.Context, userID ccc.UUID, req *ChangeSessionUserPasswordRequest) error {
	// Validate credentials
	user, err := p.storage.User(ctx, userID)
	if err != nil {
		return errors.Wrap(err, "sessionstorage.PasswordAuthStore.User()")
	}
	if _, err := p.hasher.Compare(user.PasswordHash, req.OldPassword); err != nil {
		return httpio.NewBadRequestMessageWithError(err, "Old password incorrect")
	}

	if err := p.setPasswordHash(ctx, user.ID, req.NewPassword); err != nil {
		return errors.Wrap(err, "setPasswordHash()")
	}

	return nil
}

// changeSessionUserHash handles modifications to a user hash. This can be used when
// users are being migrated, and passwords are not know, but the hash is compatible
func (p *PasswordAuth) changeSessionUserHash(ctx context.Context, userID ccc.UUID, hash *securehash.Hash) error {
	if err := p.storage.SetUserPasswordHash(ctx, userID, hash); err != nil {
		return errors.Wrap(err, "sessionstorage.PasswordAuthStore.SetUserPasswordHash()")
	}

	return nil
}

// createSessionUser handles creating a user account.
func (p *PasswordAuth) createSessionUser(ctx context.Context, req *CreateUserRequest) (ccc.UUID, error) {
	var hash *securehash.Hash
	if req.Password != nil {
		var err error
		hash, err = p.hasher.Hash(*req.Password)
		if err != nil {
			return ccc.NilUUID, errors.Wrap(err, "securehash.SecureHasher.Hash()")
		}
	}

	insertUser := &dbtype.InsertSessionUser{
		Username:     req.Username,
		PasswordHash: hash,
		Disabled:     req.Disabled,
	}

	user, err := p.storage.CreateUser(ctx, insertUser)
	if err != nil {
		return ccc.NilUUID, errors.Wrap(err, "sessionstorage.PasswordAuthStore.CreateUser()")
	}

	return user.ID, nil
}

// deleteSessionUser handles deleting a user account.
func (p *PasswordAuth) deleteSessionUser(ctx context.Context, sessionUserID ccc.UUID) error {
	user, err := p.storage.User(ctx, sessionUserID)
	if err != nil {
		return errors.Wrap(err, "sessionstorage.PasswordAuthStore.User()")
	}

	if user.ID == sessioninfo.UserFromCtx(ctx).ID {
		return httpio.NewBadRequestMessage("cannot delete yourself")
	}

	if err := p.storage.DeleteUser(ctx, user.ID); err != nil {
		return errors.Wrap(err, "sessionstorage.PasswordAuthStore.DeleteUser()")
	}

	if err := p.storage.DestroyAllUserSessions(ctx, user.Username); err != nil {
		return errors.Wrap(err, "sessionstorage.PasswordAuthStore.DestroyAllUserSessions()")
	}

	return nil
}

// deactivateSessionUser handles deactivating a user account.
func (p *PasswordAuth) deactivateSessionUser(ctx context.Context, sessionUserID ccc.UUID) error {
	user, err := p.storage.User(ctx, sessionUserID)
	if err != nil {
		return errors.Wrap(err, "sessionstorage.PasswordAuthStore.User()")
	}

	if user.ID == sessioninfo.UserFromCtx(ctx).ID {
		return httpio.NewBadRequestMessage("cannot deactivate yourself")
	}

	if err := p.storage.DeactivateUser(ctx, user.ID); err != nil {
		return errors.Wrap(err, "sessionstorage.PasswordAuthStore.DeactivateUser()")
	}

	if err := p.storage.DestroyAllUserSessions(ctx, user.Username); err != nil {
		return errors.Wrap(err, "sessionstorage.PasswordAuthStore.DestroyAllUserSessions()")
	}

	return nil
}

// activateSessionUser handles activating a user account.
func (p *PasswordAuth) activateSessionUser(ctx context.Context, sessionUserUUID ccc.UUID) error {
	if err := p.storage.ActivateUser(ctx, sessionUserUUID); err != nil {
		return errors.Wrap(err, "sessionstorage.PasswordAuthStore.ActivateUser()")
	}

	return nil
}

// API provides programatic access to PasswordAuth handler internals
func (p *PasswordAuth) API() *PasswordAuthAPI {
	return newPasswordAuthAPI(p)
}

// ChangeSessionUserPasswordRequest takes in the user information for changing a SessionUser password
type ChangeSessionUserPasswordRequest struct {
	OldPassword string
	NewPassword string
}

// CreateUserRequest takes in the user information for creating a new SessionUser
type CreateUserRequest struct {
	Username string  `json:"username"`
	Password *string `json:"password"`
	Disabled bool    `json:"disabled"`
}

// PasswordAuthAPI provides programatic access to PasswordAuth handler internals
type PasswordAuthAPI struct {
	passwordAuth *PasswordAuth
}

func newPasswordAuthAPI(passwordAuth *PasswordAuth) *PasswordAuthAPI {
	return &PasswordAuthAPI{
		passwordAuth: passwordAuth,
	}
}

// Login validates the username and password.
func (p *PasswordAuthAPI) Login(ctx context.Context, w http.ResponseWriter, username, password string) error {
	return p.passwordAuth.loginAPI(ctx, w, username, password)
}

// Logout destroys the current session
func (p *PasswordAuthAPI) Logout(ctx context.Context) error {
	// Destroy session in database
	if err := p.passwordAuth.baseSession.Storage.DestroySession(ctx, sessioninfo.IDFromCtx(ctx)); err != nil {
		return errors.Wrap(err, "PreauthSession.DestroySession()")
	}

	return nil
}

// StartSession initializes a session by restoring it from a cookie, or if
// that fails, initializing a new session. The session cookie is then updated and
// the sessionID is inserted into the context.
func (p *PasswordAuthAPI) StartSession(ctx context.Context, w http.ResponseWriter, r *http.Request) (context.Context, error) {
	ctx, err := p.passwordAuth.baseSession.StartSessionAPI(ctx, w, r)
	if err != nil {
		return ctx, errors.Wrap(err, "PreauthSession.StartSessionAPI()")
	}

	return ctx, nil
}

// ValidateSession checks the sessionID in the database to validate that it has not expired
// and updates the last activity timestamp if it is still valid.
// StartSession handler must be called before calling ValidateSession
func (p *PasswordAuthAPI) ValidateSession(ctx context.Context) (context.Context, error) {
	ctx, err := p.passwordAuth.baseSession.ValidateSessionAPI(ctx)
	if err != nil {
		return ctx, errors.Wrap(err, "PreauthSession.CheckSessionAPI()")
	}

	return ctx, nil
}

// ChangeSessionUserPassword handles modifications to a user password
func (p *PasswordAuthAPI) ChangeSessionUserPassword(ctx context.Context, userID ccc.UUID, req *ChangeSessionUserPasswordRequest) error {
	return p.passwordAuth.changeSessionUserPassword(ctx, userID, req)
}

// ChangeSessionUserHash handles modifications to a user hash.
func (p *PasswordAuthAPI) ChangeSessionUserHash(ctx context.Context, userID ccc.UUID, hash *securehash.Hash) error {
	return p.passwordAuth.changeSessionUserHash(ctx, userID, hash)
}

// CreateSessionUser handles creating a user account
func (p *PasswordAuthAPI) CreateSessionUser(ctx context.Context, req *CreateUserRequest) (ccc.UUID, error) {
	return p.passwordAuth.createSessionUser(ctx, req)
}

// DeleteSessionUser handles deleting a user account
func (p *PasswordAuthAPI) DeleteSessionUser(ctx context.Context, sessionUserID ccc.UUID) error {
	return p.passwordAuth.deleteSessionUser(ctx, sessionUserID)
}

// DeactivateSessionUser handles deactivating a user account
func (p *PasswordAuthAPI) DeactivateSessionUser(ctx context.Context, sessionUserID ccc.UUID) error {
	return p.passwordAuth.deactivateSessionUser(ctx, sessionUserID)
}

// ActivateSessionUser handles activating a user
func (p *PasswordAuthAPI) ActivateSessionUser(ctx context.Context, sessionUserUUID ccc.UUID) error {
	return p.passwordAuth.activateSessionUser(ctx, sessionUserUUID)
}
