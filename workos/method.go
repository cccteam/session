package workos

import (
	"context"
	"net/http"

	"github.com/cccteam/session/sessioninfo"
	"github.com/cccteam/session/signin"
	"github.com/go-playground/errors/v5"
)

// Config configures the WorkOS SSO sign-in method.
type Config struct {
	// APIKey is the secret API key, used only for the code exchange.
	APIKey string
	// ClientID is the WorkOS client ID.
	ClientID string
	// RedirectURL is where WorkOS sends the browser back: the Callback route.
	RedirectURL string
	// BaseURL is the WorkOS API. (default: https://api.workos.com)
	BaseURL string
	// LoginURL is where refused and pending sign-ins are sent. (default: /login)
	LoginURL string
	// Authenticator replaces the client built from the fields above. Tests inject a
	// fake through it; production leaves it nil.
	Authenticator Authenticator
}

// Method holds the handlers of the WorkOS SSO sign-in method.
type Method struct {
	login    http.HandlerFunc
	callback http.HandlerFunc
}

// SignIn registers WorkOS SSO sign-in on auth and returns its handlers. The login
// handler reads the "organization" query parameter. The identity key is
// (connection_id, idp_id). Roles are never synchronized from WorkOS.
//
// It panics when the method is already registered on auth, when auth has served a
// request, or when auth's storage has no identities configuration
// (sessionstorage.ErrIdentitiesNotConfigured).
func SignIn(auth signin.Core, cfg *Config) *Method {
	if cfg == nil {
		cfg = &Config{}
	}
	h := signin.Register(auth, &signin.Registration{
		Method: sessioninfo.MethodWorkOS,
		Build: func(cookies signin.StateCookies) (*signin.Method, error) {
			authn := cfg.Authenticator
			if authn == nil {
				c := NewClient(cookies, cfg.APIKey, cfg.ClientID, cfg.RedirectURL)
				if cfg.BaseURL != "" {
					c.SetBaseURL(cfg.BaseURL)
				}
				if cfg.LoginURL != "" {
					c.SetLoginURL(cfg.LoginURL)
				}
				authn = c
			}

			return method(authn), nil
		},
	})

	return &Method{login: h.Login, callback: h.Callback}
}

// Login redirects to WorkOS. It requires ?organization= and accepts ?returnUrl=, which
// must be a path in this application; any other value is refused with 400.
func (m *Method) Login() http.HandlerFunc { return m.login }

// Callback completes the provider round trip and redirects as the Azure method's
// Callback does.
func (m *Method) Callback() http.HandlerFunc { return m.callback }

// method is the WorkOS SSO method over authn. The identity is (connection_id, idp_id),
// and the full profile is its claims. WorkOS only relays the upstream IdP's email, so
// EmailVerified is false and the user resolver decides what the email is worth. Roles
// are never synchronized.
func method(authn Authenticator) *signin.Method {
	return &signin.Method{
		Name:     sessioninfo.MethodWorkOS,
		LoginURL: authn.LoginURL,
		Begin: func(ctx context.Context, w http.ResponseWriter, r *http.Request, returnURL string) (string, error) {
			return authn.AuthorizationURL(ctx, w, r.URL.Query().Get("organization"), returnURL)
		},
		Complete: func(ctx context.Context, w http.ResponseWriter, r *http.Request) (*signin.Verified, error) {
			returnURL, profile, rawProfile, err := authn.Verify(ctx, w, r)
			if err != nil {
				return nil, errors.Wrap(err, "workos.Authenticator.Verify()")
			}

			return &signin.Verified{
				Identity: &sessioninfo.Identity{
					Method: sessioninfo.MethodWorkOS, Connection: profile.ConnectionID, Subject: profile.IDPID, Email: profile.Email, Claims: rawProfile,
				},
				ReturnURL: returnURL,
			}, nil
		},
	}
}
