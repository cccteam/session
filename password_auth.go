package session

import (
	"context"
	"net/http"

	"github.com/cccteam/ccc"
	"github.com/cccteam/ccc/accesstypes"
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
	*basesession.BaseSession
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
		BaseSession: baseSession,
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

// Login validates the username and password.
func (p *PasswordAuth) Login() http.HandlerFunc {
	type request struct {
		Username string `json:"username"`
		Password string `json:"password"`
	}

	decoder := newDecoder[request]()

	return p.Handle(func(w http.ResponseWriter, r *http.Request) error {
		ctx, span := ccc.StartTrace(r.Context())
		defer span.End()

		// decode request
		req, err := decoder.Decode(r)
		if err != nil {
			return httpio.NewEncoder(w).ClientMessage(ctx, err)
		}

		// Validate credentials
		user, err := p.storage.UserByUserName(ctx, req.Username)
		if err != nil {
			return httpio.NewEncoder(w).UnauthorizedMessageWithError(ctx, err, "Invalid Credentials")
		}
		upgrade, err := p.hasher.Compare(user.PasswordHash, req.Password)
		if err != nil {
			return httpio.NewEncoder(w).UnauthorizedMessageWithError(ctx, err, "Invalid Credentials")
		}
		if upgrade && p.autoUpgrade {
			if err := p.setPasswordHash(ctx, user.ID, req.Password); err != nil {
				logger.FromCtx(ctx).Error(err)
			} else {
				logger.FromCtx(ctx).Infof("auto-upgraded password hash for user %s, from %s to %s", user.Username, user.PasswordHash.KeyType(), p.hasher.KeyType())
			}
		}

		if user.Disabled {
			return httpio.NewEncoder(w).UnauthorizedMessageWithError(ctx, err, "Account disabled")
		}

		// user is successfully authenticated, start a new session
		sessionID, err := p.startNewSession(ctx, w, r, user.Username)
		if err != nil {
			return httpio.NewEncoder(w).ClientMessage(ctx, err)
		}

		// Log the association between the sessionID and Username
		logger.FromCtx(ctx).AddRequestAttribute("Username", user.Username).AddRequestAttribute(string(types.SCSessionID), sessionID)

		return httpio.NewEncoder(w).Ok(nil)
	})
}

// ValidateSession checks the sessionID in the database to validate that it has not expired
// and updates the last activity timestamp if it is still valid.
// StartSession handler must be called before calling ValidateSession
func (p *PasswordAuth) ValidateSession(next http.Handler) http.Handler {
	return p.Handle(func(w http.ResponseWriter, r *http.Request) error {
		ctx, span := ccc.StartTrace(r.Context())
		defer span.End()

		ctx, err := p.CheckSession(ctx)
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

	return p.Handle(func(w http.ResponseWriter, r *http.Request) error {
		ctx, span := ccc.StartTrace(r.Context())
		defer span.End()

		ctx, err := p.CheckSession(ctx)
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

	return p.Handle(func(w http.ResponseWriter, r *http.Request) error {
		ctx, span := ccc.StartTrace(r.Context())
		defer span.End()

		req, err := decoder.Decode(r)
		if err != nil {
			return httpio.NewEncoder(w).ClientMessage(ctx, err)
		}

		userInfo := sessioninfo.UserFromCtx(ctx)

		if err := p.ChangeSessionUserPassword(ctx, userInfo.ID, (*ChangeSessionUserPasswordRequest)(req)); err != nil {
			return httpio.NewEncoder(w).ClientMessage(ctx, err)
		}

		return httpio.NewEncoder(w).Ok(nil)
	})
}

// CreateUser handles creating a user account.
func (p *PasswordAuth) CreateUser() http.HandlerFunc {
	type request struct {
		Username string             `json:"username"`
		Password *string            `json:"password"`
		Domain   accesstypes.Domain `json:"domain"`
		Disabled bool               `json:"disabled"`
	}

	type response struct {
		ID ccc.UUID `json:"id"`
	}

	decoder := newDecoder[request]()

	return p.Handle(func(w http.ResponseWriter, r *http.Request) error {
		ctx, span := ccc.StartTrace(r.Context())
		defer span.End()

		req, err := decoder.Decode(r)
		if err != nil {
			return httpio.NewEncoder(w).ClientMessage(ctx, err)
		}

		id, err := p.CreateSessionUser(ctx, (*CreateUserRequest)(req))
		if err != nil {
			return httpio.NewEncoder(w).ClientMessage(ctx, err)
		}

		return httpio.NewEncoder(w).Ok(response{ID: id})
	})
}

// DeactivateUser handles deactivating a user account.
func (p *PasswordAuth) DeactivateUser() http.HandlerFunc {
	return p.Handle(func(w http.ResponseWriter, r *http.Request) error {
		ctx, span := ccc.StartTrace(r.Context())
		defer span.End()

		sessionUserID := httpio.Param[ccc.UUID](r, RouterSessionUserID)
		if err := p.DeactivateSessionUser(ctx, sessionUserID); err != nil {
			return httpio.NewEncoder(w).ClientMessage(ctx, err)
		}

		return httpio.NewEncoder(w).Ok(nil)
	})
}

// DeleteUser handles deleting a user account.
func (p *PasswordAuth) DeleteUser() http.HandlerFunc {
	return p.Handle(func(w http.ResponseWriter, r *http.Request) error {
		ctx, span := ccc.StartTrace(r.Context())
		defer span.End()

		sessionUserID := httpio.Param[ccc.UUID](r, RouterSessionUserID)
		if err := p.DeleteSessionUser(ctx, sessionUserID); err != nil {
			return httpio.NewEncoder(w).ClientMessage(ctx, err)
		}

		return httpio.NewEncoder(w).Ok(nil)
	})
}

// ActivateUser handles activating a user account.
func (p *PasswordAuth) ActivateUser() http.HandlerFunc {
	return p.Handle(func(w http.ResponseWriter, r *http.Request) error {
		ctx, span := ccc.StartTrace(r.Context())
		defer span.End()

		sessionUserUUID := httpio.Param[ccc.UUID](r, RouterSessionUserID)
		if err := p.ActivateSessionUser(ctx, sessionUserUUID); err != nil {
			return httpio.NewEncoder(w).ClientMessage(ctx, err)
		}

		return httpio.NewEncoder(w).Ok(nil)
	})
}

// startNewSession starts a new session for the given username and returns the session ID
func (p *PasswordAuth) startNewSession(ctx context.Context, w http.ResponseWriter, r *http.Request, username string) (ccc.UUID, error) {
	// Create new Session in database
	id, err := p.storage.NewSession(ctx, username)
	if err != nil {
		return ccc.NilUUID, errors.Wrap(err, "sessionstorage.PreauthStore.NewSession()")
	}

	if _, err := p.NewAuthCookie(w, false, id); err != nil {
		return ccc.NilUUID, errors.Wrap(err, "cookie.CookieHandler.NewAuthCookie()")
	}

	// write new XSRF Token Cookie to match the new SessionID
	p.SetXSRFTokenCookie(w, r, id, types.XSRFCookieLife)

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

// ChangeSessionUserPassword handles modifications to a user password
func (p *PasswordAuth) ChangeSessionUserPassword(ctx context.Context, userID ccc.UUID, req *ChangeSessionUserPasswordRequest) error {
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

// CreateSessionUser handles creating a user account.
func (p *PasswordAuth) CreateSessionUser(ctx context.Context, req *CreateUserRequest) (ccc.UUID, error) {
	if req.Domain == "" {
		req.Domain = accesstypes.GlobalDomain
	}

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
		Domain:       req.Domain,
		PasswordHash: hash,
		Disabled:     req.Disabled,
	}

	user, err := p.storage.CreateUser(ctx, insertUser)
	if err != nil {
		return ccc.NilUUID, errors.Wrap(err, "sessionstorage.PasswordAuthStore.CreateUser()")
	}

	return user.ID, nil
}

// DeleteSessionUser handles deleting a user account.
func (p *PasswordAuth) DeleteSessionUser(ctx context.Context, sessionUserID ccc.UUID) error {
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

// DeactivateSessionUser handles deactivating a user account.
func (p *PasswordAuth) DeactivateSessionUser(ctx context.Context, sessionUserID ccc.UUID) error {
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

// ActivateSessionUser handles activating a user account.
func (p *PasswordAuth) ActivateSessionUser(ctx context.Context, sessionUserUUID ccc.UUID) error {
	if err := p.storage.ActivateUser(ctx, sessionUserUUID); err != nil {
		return errors.Wrap(err, "sessionstorage.PasswordAuthStore.ActivateUser()")
	}

	return nil
}

// ChangeSessionUserPasswordRequest takes in the user information for changing a SessionUser password
type ChangeSessionUserPasswordRequest struct {
	OldPassword string
	NewPassword string
}

// CreateUserRequest takes in the user information for creating a new SessionUser
type CreateUserRequest struct {
	Username string             `json:"username"`
	Password *string            `json:"password"`
	Domain   accesstypes.Domain `json:"domain"`
	Disabled bool               `json:"disabled"`
}
