package workos

import (
	"context"
	"encoding/json"
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

// Identity is a verified WorkOS SSO identity as the user resolver receives it: the
// profile WorkOS returned, keyed by its connection and the upstream IdP's identifier
// (ConnectionID, IDPID). WorkOS only relays the upstream IdP's email, so the resolver
// decides what it is worth.
type Identity struct {
	Profile
	// Raw is the profile exactly as WorkOS returned it, for what Profile does not
	// carry, such as raw_attributes.
	Raw json.RawMessage
}

// UserResolver decides a WorkOS identity that is not linked to any user yet. It is the
// application's rule, given to SignIn; see signin.UserResolver for when it runs and
// what it may do. Tx is the Auth's storage transaction type.
type UserResolver[Tx any] func(ctx context.Context, tx Tx, identity *Identity) (*signin.Resolution, error)

// Method holds the handlers of the WorkOS SSO sign-in method.
type Method struct {
	login    http.HandlerFunc
	callback http.HandlerFunc
}

// SignIn registers WorkOS SSO sign-in on auth under name and returns its handlers.
// name identifies the registration on auth. The login handler reads the "organization"
// query parameter. The identity key is (connection_id, idp_id); resolve decides an
// identity that is not linked yet. Roles are never synchronized from WorkOS.
//
// It panics when name is empty or already used on auth, when auth has served a
// request, or when resolve is nil.
func SignIn[Tx any](auth signin.Core[Tx], name string, resolve UserResolver[Tx], cfg *Config) *Method {
	if cfg == nil {
		cfg = &Config{}
	}
	reg := &signin.Registration[Tx]{
		Name:    name,
		Method:  sessioninfo.MethodWorkOS,
		Resolve: resolver(resolve),
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
	}
	if resolve == nil {
		reg.Err = errors.New("resolve is required: it decides every WorkOS identity that is not linked yet")
	}
	h := signin.Register(auth, reg)

	return &Method{login: h.Login, callback: h.Callback}
}

// Login redirects to WorkOS. It requires ?organization= and accepts ?returnUrl=, which
// must be a path in this application; any other value is refused with 400.
func (m *Method) Login() http.HandlerFunc { return m.login }

// Callback completes the provider round trip and redirects as the Azure method's
// Callback does.
func (m *Method) Callback() http.HandlerFunc { return m.callback }

// resolver adapts the application's resolver to the contract: the identity the core
// resolves is decoded from the profile the sign-in verified.
func resolver[Tx any](resolve UserResolver[Tx]) signin.UserResolver[Tx] {
	return func(ctx context.Context, tx Tx, req *sessioninfo.NewSessionRequest) (*signin.Resolution, error) {
		identity := &Identity{Raw: req.Identity.Claims}
		if err := json.Unmarshal(req.Identity.Claims, &identity.Profile); err != nil {
			return nil, errors.Wrap(err, "json.Unmarshal()")
		}

		return resolve(ctx, tx, identity)
	}
}

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
