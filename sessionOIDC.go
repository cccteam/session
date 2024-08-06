package session

import (
	"fmt"
	"net/http"
	"net/url"
	"session/oidc"

	"github.com/cccteam/httpio"
	"github.com/pkg/errors"
	"go.opentelemetry.io/otel"
)

type SessionOIDC struct {
	appName string
	oidc    oidc.Authenticator
	session iSession // this is doing the heavier lifting
}

func NewSessionOIDC(appName string, session iSession, oidcAuth oidc.Authenticator) *SessionOIDC {
	return &SessionOIDC{appName: appName, session: session, oidc: oidcAuth}
}

// CallbackOIDC is the handler for the callback from the OIDC auth provider
func (s *SessionOIDC) CallbackOIDC() http.HandlerFunc {
	type claims struct {
		Username string   `json:"preferred_username"`
		Roles    []string `json:"roles"`
	}

	return s.session.Handle(func(w http.ResponseWriter, r *http.Request) error {
		ctx, span := otel.Tracer(s.appName).Start(r.Context(), "session.CallbackOIDC()")
		defer span.End()

		claims := &claims{}
		returnURL, oidcSID, err := s.oidc.Verify(ctx, w, r, claims)
		if err != nil {
			http.Redirect(w, r, fmt.Sprintf("/login?message=%s", url.QueryEscape(httpio.Message(err))), http.StatusFound)

			return errors.Wrap(err, "oidc.Verify")
		}

		// user is successfully authenticated, start a new session
		sessionID, err := s.session.StartNew(ctx, w, claims.Username, oidcSID)
		if err != nil {
			http.Redirect(w, r, fmt.Sprintf("/login?message=%s", url.QueryEscape("Internal Server Error")), http.StatusFound)

			return errors.Wrap(err, "session.startNewSession()")
		}

		// write new XSRF Token Cookie to match the new SessionID
		if ok := s.session.SetXSRFTokenCookie(w, r, sessionID, xsrfCookieLife); !ok {
			http.Redirect(w, r, fmt.Sprintf("/login?message=%s", url.QueryEscape("Internal Server Error")), http.StatusFound)

			return errors.New("Failed to set XSRF Token Cookie")
		}

		// hasRole, err := s.assignUserRoles(ctx, access.User(claims.Username), claims.Roles)
		// if err != nil {
		// 	http.Redirect(w, r, fmt.Sprintf("/login?message=%s", url.QueryEscape("Internal Server Error")), http.StatusFound)

		// 	return errors.Wrap(err, "session.assignUserRoles()")
		// }
		// if !hasRole {
		// 	err := httpio.NewUnauthorizedMessage("Unauthorized: user has no roles")
		// 	http.Redirect(w, r, fmt.Sprintf("/login?message=%s", url.QueryEscape(httpio.Message(err))), http.StatusFound)

		// 	return err
		// }

		http.Redirect(w, r, returnURL, http.StatusFound)

		return nil
	})
}

func (s *SessionOIDC) FrontChannelLogout() {
	//front channel logout specific to OIDC
}

func (s *SessionOIDC) Authenticated() {
	s.session.Authenticated()
}

func (s *SessionOIDC) Login() {
	s.session.Login()
}

func (s *SessionOIDC) Logout() {
	s.session.Logout()
}

func (s *SessionOIDC) SetTimeout(next http.Handler) {
	s.session.SetTimeout(next)
}

func (s *SessionOIDC) Start(next http.Handler) {
	s.session.Start(next)
}

func (s *SessionOIDC) Validate(next http.Handler) {
	s.session.Validate(next)
}

func (s *SessionOIDC) SetXSRFToken(next http.Handler) {
	s.session.SetXSRFToken(next)
}

func (s *SessionOIDC) ValidateXSRFToken(next http.Handler) {
	s.session.ValidateXSRFToken(next)
}
