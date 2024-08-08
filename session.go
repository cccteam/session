package session

import (
	"context"
	"net/http"
	"strconv"
	"strings"
	"time"

	"session/access"
	"session/dbx"
	"session/oidc"

	"github.com/cccteam/httpio"
	"github.com/cccteam/logger"
	"github.com/go-playground/errors/v5"
	"github.com/gofrs/uuid"
	"github.com/gorilla/securecookie"
	"go.opentelemetry.io/otel"
)

type (
	ctxKey string
)

const (
	ErrUnauthorized = "ErrUnauthorized"
	// Keys used within the request Context
	ctxSessionID                 ctxKey = "sessionID"
	ctxSessionInfo               ctxKey = "sessionInfo"
	ctxSessionExpirationDuration ctxKey = "sessionExpirationDuration"
)

type iSession interface {
	Authenticated() http.HandlerFunc
	Login() http.HandlerFunc
	Logout() http.HandlerFunc
	SetTimeout(next http.Handler) http.Handler
	Start(next http.Handler) http.Handler
	Validate(next http.Handler) http.Handler
	SetXSRFToken(next http.Handler) http.Handler      //specific to angular; needs refactor
	ValidateXSRFToken(next http.Handler) http.Handler // probably specific to angular too; need refactor

	StartNew(ctx context.Context, w http.ResponseWriter, username, oidcSID string) (string, error)
	NewAuthCookie(w http.ResponseWriter, sameSiteStrict bool, idGen func() (uuid.UUID, error)) (map[scKey]string, error)
	ReadAuthCookie(r *http.Request) (map[scKey]string, bool)
	WriteAuthCookie(w http.ResponseWriter, sameSiteStrict bool, cookieValue map[scKey]string) error
	SetXSRFTokenCookie(w http.ResponseWriter, r *http.Request, sessionID string, cookieExpiration time.Duration) (set bool)

	Handle(handler func(w http.ResponseWriter, r *http.Request) error) http.HandlerFunc
}

type session struct {
	storage        sessionStorage
	sessionTimeout time.Duration
	oidc           oidc.Authenticator
	appName        string
	cookieManager
}

func NewSession(
	sessionTimeout time.Duration,
	secureCookie *securecookie.SecureCookie,
	appName string,
	storage sessionStorage) *session {
	return &session{sessionTimeout: sessionTimeout, cookieManager: newCookieClient(secureCookie), appName: appName, storage: sessionStorage{}} // TODO: Validate theres not a better way when we try to implement this into one of our apps
}

// SetTimeout is a Handler to set the session timeout
func (s *session) SetTimeout(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		r = r.WithContext(context.WithValue(r.Context(), ctxSessionExpirationDuration, s.sessionTimeout))

		next.ServeHTTP(w, r)
	})
}

// Start establishes a session cookie if none exists
//
// It also stores the sessionID in the request context.
func (s *session) Start(next http.Handler) http.Handler {
	return s.Handle(func(w http.ResponseWriter, r *http.Request) error {
		ctx, span := otel.Tracer(s.appName).Start(r.Context(), "session.StartSession()")
		defer span.End()

		// Read Auth Cookie
		cookieValue, ok := s.readAuthCookie(r)
		if !ok || !validSessionID(cookieValue[scSessionID]) {
			var err error
			cookieValue, err = s.newAuthCookie(w, true, uuid.NewV4)
			if err != nil {
				return httpio.NewEncoder(w).ClientMessage(ctx, err)
			}
		}

		// Upgrade cookie to SameSite=Strict
		// since CallbackOIDC() sets it to None to allow OAuth flow to work
		if cookieValue[scSameSiteStrict] != strconv.FormatBool(true) {
			if err := s.writeAuthCookie(w, true, cookieValue); err != nil {
				return httpio.NewEncoder(w).ClientMessage(ctx, err)
			}
		}

		// Store sessionID in context
		r = r.WithContext(context.WithValue(r.Context(), ctxSessionID, cookieValue[scSessionID]))

		// Add session ID to logging context
		logger.Req(r).AddRequestAttribute("session ID", cookieValue[scSessionID])
		l := logger.Req(r).WithAttributes().AddAttribute("session ID", cookieValue[scSessionID]).Logger()
		r = r.WithContext(logger.NewCtx(r.Context(), l))

		next.ServeHTTP(w, r)

		return nil
	})
}

// Validate checks the sessionID in the database to validate that it has not expired
// and updates the last activity timestamp if it is still valid.
func (s *session) Validate(next http.Handler) http.Handler {
	return s.Handle(func(w http.ResponseWriter, r *http.Request) error {
		ctx, span := otel.Tracer(s.appName).Start(r.Context(), "session.Validate()")
		defer span.End()

		r, err := s.check(r)
		if err != nil {
			return httpio.NewEncoder(w).ClientMessage(ctx, err)
		}

		next.ServeHTTP(w, r)

		return nil
	})
}

// StartNew starts a new session for the given username and returns the session ID
func (s *session) StartNew(ctx context.Context, w http.ResponseWriter, username, oidcSID string) (string, error) {
	cookieValue, err := s.newAuthCookie(w, false, uuid.NewV4)
	if err != nil {
		return "", err
	}

	dbSess := &dbx.SessionInfo{
		ID:        cookieValue[scSessionID],
		OidcSID:   oidcSID,
		Username:  username,
		CreatedAt: time.Now(),
		UpdatedAt: time.Now(),
	}

	// Create new Session in database
	sessInfo, err := s.storage.NewSession(ctx, dbSess) //TODO: this isn't really hooked up to anything but an interface that we don't even have an implementation struct of. Swap it with a real sessionManager
	if err != nil {
		return "", errors.Wrap(err, "users.NewSession()")
	}

	return sessInfo.ID, nil
}

// Authenticated is the handler reports if the session is authenticated
func (s *session) Authenticated() http.HandlerFunc {
	type response struct {
		Authenticated bool                                  `json:"authenticated"`
		Username      string                                `json:"username"`
		Permissions   map[access.Domain][]access.Permission `json:"permissions"`
	}

	return s.Handle(func(w http.ResponseWriter, r *http.Request) error {
		ctx, span := otel.Tracer(s.appName).Start(r.Context(), "session.Authenticated()")
		defer span.End()

		r, err := s.check(r.WithContext(ctx))
		if err != nil {
			if httpio.HasUnauthorized(err) {
				return httpio.NewEncoder(w).Ok(response{})
			}

			return httpio.NewEncoder(w).ClientMessage(ctx, err)
		}

		sessInfo := sessionInfoFromRequest(r)

		// set response values
		res := response{
			Authenticated: true,
			Username:      sessInfo.Username,
			Permissions:   sessInfo.Permissions,
		}

		return httpio.NewEncoder(w).Ok(res)
	})
}

func (s *session) Login() http.HandlerFunc {
	return s.Handle(func(w http.ResponseWriter, r *http.Request) error {
		ctx, span := otel.Tracer(s.appName).Start(r.Context(), "session.Login()")
		defer span.End()

		returnURL := r.URL.Query().Get("returnUrl")
		authCodeURL, err := s.oidc.AuthCodeURL(w, returnURL)
		if err != nil {
			return httpio.NewEncoder(w).ClientMessage(ctx, err)
		}

		http.Redirect(w, r, authCodeURL, http.StatusFound)

		return nil
	})
}

// Logout is a handler which destroys the current session
func (s *session) Logout() http.HandlerFunc {
	return s.Handle(func(w http.ResponseWriter, r *http.Request) error {
		ctx, span := otel.Tracer(s.appName).Start(r.Context(), "session.Logout()")
		defer span.End()

		// Destroy session in database
		if err := s.storage.DestroySession(ctx, sessionIDFromRequest(r)); err != nil {
			return httpio.NewEncoder(w).ClientMessage(ctx, err)
		}

		return httpio.NewEncoder(w).Ok(nil)
	})
}

// handle returns a handler that logs any error coming from our custom handlers
func (s *session) Handle(handler func(w http.ResponseWriter, r *http.Request) error) http.HandlerFunc {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if err := handler(w, r); err != nil {
			if httpio.CauseIsError(err) {
				logger.Req(r).Error(err)
			} else {
				logger.Req(r).Infof("['%s']", strings.Join(httpio.Messages(err), "', '"))
			}
		}
	})
}

func (s *session) check(r *http.Request) (req *http.Request, err error) {
	ctx, span := otel.Tracer(s.appName).Start(r.Context(), "session.checkSession()")
	defer span.End()

	// Validate that the sessionID is in database
	sessInfo, err := s.storage.Session(ctx, sessionIDFromRequest(r)) //Todo: Check that the return type works, we changed it
	if err != nil {
		return r, httpio.NewUnauthorizedMessageWithError(err, "invalid session")
	}

	// Check for expiration
	if sessInfo.Expired || time.Since(sessInfo.UpdatedAt) > sessionExpirationFromRequest(r) {
		return r, httpio.NewUnauthorizedMessage("session expired")
	}

	// Update Activity
	if err := s.storage.UpdateSessionActivity(ctx, sessInfo.ID); err != nil {
		return r, errors.Wrap(err, "users.SessionManager.UpdateSessionActivity()")
	}

	// Store session info in context
	r = r.WithContext(context.WithValue(ctx, ctxSessionInfo, sessInfo))

	// Add user to logging context
	logger.Req(r).AddRequestAttribute("username", sessInfo.Username)
	l := logger.Req(r).WithAttributes().AddAttribute("username", sessInfo.Username).Logger()
	r = r.WithContext(logger.NewCtx(r.Context(), l))

	return r, nil
}

// sessionIDFromRequest extracts the Session ID from the Request Context
func sessionIDFromRequest(r *http.Request) string {
	id, ok := r.Context().Value(ctxSessionID).(string)
	if !ok {
		logger.Req(r).Errorf("failed to find %s in request context", ctxSessionID)
	}

	return id
}

// sessionInfoFromRequest extracts session information from the Request Context
func sessionInfoFromRequest(r *http.Request) *access.SessionInfo {
	sessionInfo, ok := r.Context().Value(ctxSessionInfo).(*access.SessionInfo)
	if !ok {
		logger.Req(r).Errorf("failed to find %s in request context", ctxSessionInfo)
	}

	return sessionInfo
}

// sessionExpirationFromRequest extracts the session timeout from the Request Context
func sessionExpirationFromRequest(r *http.Request) time.Duration {
	d, ok := r.Context().Value(ctxSessionExpirationDuration).(time.Duration)
	if !ok {
		logger.Req(r).Errorf("failed to find %s in request context", ctxSessionExpirationDuration)
	}

	return d
}

// validSessionID checks that the sessionID is a valid uuid
func validSessionID(sessionID string) bool {
	if _, err := uuid.FromString(sessionID); err != nil {
		return false
	}

	return true
}
