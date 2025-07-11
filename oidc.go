package session

import (
	"context"
	"fmt"
	"net/http"
	"net/url"
	"time"

	"github.com/cccteam/ccc"
	"github.com/cccteam/ccc/accesstypes"
	"github.com/cccteam/httpio"
	"github.com/cccteam/logger"
	"github.com/cccteam/session/oidc"
	"github.com/cccteam/session/roles" // Added roles import
	"github.com/go-playground/errors/v5"
	"github.com/gorilla/securecookie"
	"go.opentelemetry.io/otel"
)

type OIDCAzureOption interface {
	isOIDCAzureOption()
}

var _ OIDCAzureHandlers = &OIDCAzureSession{}

type OIDCAzureSession struct {
	userManager  UserManager
	oidc         oidc.Authenticator
	storage      OIDCAzureSessionStorage
	roleAssigner roles.RoleAssigner
	session
}

func NewOIDCAzure(
	oidcAuthenticator oidc.Authenticator, oidcSession OIDCAzureSessionStorage, userManager UserManager,
	roleAssigner roles.RoleAssigner, // Added roleAssigner
	logHandler LogHandler, secureCookie *securecookie.SecureCookie, sessionTimeout time.Duration,
	options ...OIDCAzureOption,
) *OIDCAzureSession {
	cookieOpts := make([]CookieOption, 0, len(options))
	for _, opt := range options {
		if o, ok := any(opt).(CookieOption); ok {
			cookieOpts = append(cookieOpts, o)
		}
	}

	return &OIDCAzureSession{
		userManager:  userManager,
		oidc:         oidcAuthenticator,
		roleAssigner: roleAssigner, // Store roleAssigner
		session: session{
			perms:          userManager,
			handle:         logHandler,
			cookieManager:  newCookieClient(secureCookie, cookieOpts...),
			sessionTimeout: sessionTimeout,
			storage:        oidcSession,
		},
		storage: oidcSession,
	}
}

func (o *OIDCAzureSession) Login() http.HandlerFunc {
	return o.handle(func(w http.ResponseWriter, r *http.Request) error {
		ctx, span := otel.Tracer(name).Start(r.Context(), "OIDCAzureSession.Login()")
		defer span.End()

		returnURL := r.URL.Query().Get("returnUrl")
		authCodeURL, err := o.oidc.AuthCodeURL(r.Context(), w, returnURL)
		if err != nil {
			return httpio.NewEncoder(w).ClientMessage(ctx, err)
		}

		http.Redirect(w, r, authCodeURL, http.StatusFound)

		return nil
	})
}

// CallbackOIDC is the handler for the callback from the OIDC auth provider
func (o *OIDCAzureSession) CallbackOIDC() http.HandlerFunc {
	type claims struct {
		Username string   `json:"preferred_username"`
		Roles    []string `json:"roles"`
	}

	return o.handle(func(w http.ResponseWriter, r *http.Request) error {
		ctx, span := otel.Tracer(name).Start(r.Context(), "OIDCAzureSession.CallbackOIDC()")
		defer span.End()

		claims := &claims{}
		returnURL, oidcSID, err := o.oidc.Verify(ctx, w, r, claims)
		if err != nil {
			http.Redirect(w, r, fmt.Sprintf("%s?message=%s", o.oidc.LoginURL(), url.QueryEscape(httpio.Message(err))), http.StatusFound)

			return errors.Wrap(err, "oidc.Verify()")
		}

		// user is successfully authenticated, start a new session
		sessionID, err := o.startNewSession(ctx, w, claims.Username, oidcSID)
		if err != nil {
			http.Redirect(w, r, fmt.Sprintf("%s?message=%s", o.oidc.LoginURL(), url.QueryEscape("Internal Server Error")), http.StatusFound)

			return errors.Wrap(err, "OIDCAzureSession.startNewSession()")
		}

		// write new XSRF Token Cookie to match the new SessionID
		o.setXSRFTokenCookie(w, r, sessionID, xsrfCookieLife)

		hasRole, err := o.roleAssigner.AssignRoles(ctx, accesstypes.User(claims.Username), claims.Roles)
		if err != nil {
			http.Redirect(w, r, fmt.Sprintf("%s?message=%s", o.oidc.LoginURL(), url.QueryEscape("Internal Server Error")), http.StatusFound)

			return errors.Wrap(err, "roleAssigner.AssignRoles()")
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
func (o *OIDCAzureSession) FrontChannelLogout() http.HandlerFunc {
	return o.handle(func(w http.ResponseWriter, r *http.Request) error {
		ctx, span := otel.Tracer(name).Start(r.Context(), "OIDCAzureSession.FrontChannelLogout()")
		defer span.End()

		sid := r.URL.Query().Get("sid")
		if sid == "" {
			return httpio.NewEncoder(w).BadRequestMessage(ctx, "missing sid query parameter")
		}

		if err := o.storage.DestroySessionOIDC(ctx, sid); err != nil {
			logger.Req(r).Error("failed to destroy session in db via OIDC sid")
		}

		return httpio.NewEncoder(w).Ok(nil)
	})
}

// startNewSession starts a new session for the given username and returns the session ID
func (o *OIDCAzureSession) startNewSession(ctx context.Context, w http.ResponseWriter, username, oidcSID string) (ccc.UUID, error) {
	// Create new Session in database
	id, err := o.storage.NewSession(ctx, username, oidcSID)
	if err != nil {
		return ccc.NilUUID, errors.Wrap(err, "OIDCAzureSessionStorage.NewSession()")
	}

	if _, err := o.newAuthCookie(w, false, id); err != nil {
		return ccc.NilUUID, err
	}

	return id, nil
}
