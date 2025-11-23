package session

import (
	"context"
	"net/http"

	"github.com/cccteam/ccc"
	"github.com/cccteam/ccc/resource"
	"github.com/cccteam/ccc/securehash"
	"github.com/cccteam/httpio"
	"github.com/cccteam/logger"
	"github.com/cccteam/session/internal/azureoidc"
	"github.com/cccteam/session/internal/basesession"
	"github.com/cccteam/session/internal/cookie"
	"github.com/cccteam/session/internal/types"
	"github.com/cccteam/session/sessionstorage"
	"github.com/go-playground/errors/v5"
	"github.com/gorilla/securecookie"
)

// PasswordOption defines the interface for functional options used when creating a new Password.
type PasswordOption interface {
	isPasswordOption()
}

var _ PasswordHandlers = &Password{}

// Password implements the PasswordHandlers interface for handling OIDC authentication with Azure.
type Password struct {
	userRoleManager UserRoleManager
	oidc            azureoidc.Authenticator
	storage         sessionstorage.PasswordStore
	hasher          *securehash.SecureHasher
	autoUpgrade     bool
	*basesession.BaseSession
}

// NewPassword creates a new Password.
func NewPassword(
	storage sessionstorage.PasswordStore, userRoleManager UserRoleManager,
	secureCookie *securecookie.SecureCookie,
	issuerURL, clientID, clientSecret, redirectURL string,
	options ...PasswordOption,
) *Password {
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

	p := &Password{
		userRoleManager: userRoleManager,
		oidc:            oidc,
		storage:         storage,
		hasher:          securehash.New(securehash.Argon2()),
		autoUpgrade:     true,
		BaseSession:     baseSession,
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

// Login initiates the OIDC login flow by redirecting the user to the authorization URL.
func (p *Password) Login() http.HandlerFunc {
	type request struct {
		Username string `json:"username" validate:"required"`
		Password string `json:"password" validate:"required"`
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
			newHash, err := p.hasher.Hash(req.Password)
			if err != nil {
				logger.Ctx(ctx).Error(err)
			} else {
				// TODO(jwatson): Implement storage of new hash. Shared with update password handlers
				_ = newHash
			}
		}

		if user.Disabled {
			return httpio.NewEncoder(w).UnauthorizedMessageWithError(ctx, err, "Invalid Account")
		}

		// user is successfully authenticated, start a new session
		sessionID, err := p.startNewSession(ctx, w, r, user.Username)
		if err != nil {
			return httpio.NewEncoder(w).ClientMessage(ctx, err)
		}

		// Log the association between the sessionID and Username
		logger.Ctx(ctx).AddRequestAttribute("Username", user.Username).AddRequestAttribute(string(types.SCSessionID), sessionID)

		return httpio.NewEncoder(w).Ok(nil)
	})
}

// startNewSession starts a new session for the given username and returns the session ID
func (p *Password) startNewSession(ctx context.Context, w http.ResponseWriter, r *http.Request, username string) (ccc.UUID, error) {
	// Create new Session in database
	id, err := p.storage.NewSession(ctx, username)
	if err != nil {
		return ccc.NilUUID, errors.Wrap(err, "OIDCAzureSessionStorage.NewSession()")
	}

	if _, err := p.NewAuthCookie(w, false, id); err != nil {
		return ccc.NilUUID, errors.Wrap(err, "OIDCAzureSession.NewAuthCookie()")
	}

	// write new XSRF Token Cookie to match the new SessionID
	p.SetXSRFTokenCookie(w, r, id, types.XSRFCookieLife)

	return id, nil
}

// newDecoder returns an httpio.Decoder to simplify the validator call to a single location
func newDecoder[T any]() *resource.StructDecoder[T] {
	decoder, err := resource.NewStructDecoder[T]()
	if err != nil {
		panic(err)
	}

	return decoder
}
