package google

import (
	"context"
	"encoding/json"
	"net/http"

	"github.com/cccteam/ccc/accesstypes"
	"github.com/cccteam/httpio"
	"github.com/cccteam/session/oidc"
	"github.com/cccteam/session/sessioninfo"
	"github.com/cccteam/session/signin"
	"github.com/go-playground/errors/v5"
)

// Config configures the Google Workspace sign-in method.
type Config struct {
	// ClientID and ClientSecret are the OAuth client's.
	ClientID     string
	ClientSecret string
	// RedirectURL is where Google sends the browser back: the Callback route.
	RedirectURL string
	// HostedDomain is required: the Google Workspace domain sign-in is restricted to,
	// checked against the verified hd claim.
	HostedDomain string
	// RoleSync is required: RoleSync(manager, groupPrefix, lookup) reconciles the
	// user's roles to the person's groups whenever a Google sign-in establishes a
	// session, and refuses the sign-in (no_roles) when no recognized role results;
	// DisableRoleSync() leaves roles to the application.
	RoleSync RoleSyncConfig
	// LoginURL is where refused and pending sign-ins are sent. (default: /login)
	LoginURL string
	// Authenticator replaces the verifier built from the fields above. Tests inject a
	// fake identity provider through it; production leaves it nil.
	Authenticator Authenticator
}

// Method holds the handlers of the Google Workspace sign-in method.
type Method struct {
	login    http.HandlerFunc
	callback http.HandlerFunc
}

// SignIn registers Google Workspace OpenID Connect sign-in on auth and returns its
// handlers. The identity key is sub.
//
// It panics when the method is already registered on auth, when auth has served a
// request, when auth's storage has no identities configuration
// (sessionstorage.ErrIdentitiesNotConfigured), or when cfg.RoleSync or
// cfg.HostedDomain is missing.
func SignIn(auth signin.Core, cfg *Config) *Method {
	if cfg == nil {
		cfg = &Config{}
	}
	h := signin.Register(auth, &signin.Registration{
		Method: sessioninfo.MethodGoogle,
		Build: func(cookies signin.StateCookies) (*signin.Method, error) {
			groups, err := groupSyncOf(cfg.RoleSync, cfg.HostedDomain)
			if err != nil {
				return nil, err
			}
			authn := cfg.Authenticator
			if authn == nil {
				// Role sync reads the person's groups, which needs the groups scope.
				var scopes []string
				if groups != nil {
					scopes = []string{cloudIdentityScope}
				}
				o := NewOIDC(cookies, cfg.ClientID, cfg.ClientSecret, cfg.RedirectURL, cfg.HostedDomain, scopes...)
				if cfg.LoginURL != "" {
					o.SetLoginURL(cfg.LoginURL)
				}
				authn = o
			}

			return method(authn, groups), nil
		},
	})

	return &Method{login: h.Login, callback: h.Callback}
}

// Login redirects to Google. It accepts ?returnUrl=, which must be a path in this
// application; any other value is refused with 400.
func (m *Method) Login() http.HandlerFunc { return m.login }

// Callback completes the provider round trip and redirects as the Azure method's
// Callback does.
func (m *Method) Callback() http.HandlerFunc { return m.callback }

// method is the Google Workspace method over authn. The identity is sub. The
// authenticator checks the hosted domain and the verified email. When groups is set,
// the callback maps the person's directory groups to role names using the access
// token, which is used once and never stored.
func method(authn Authenticator, groups *groupSync) *signin.Method {
	type claims struct {
		Sub           string   `json:"sub"`
		Email         string   `json:"email"`
		EmailVerified bool     `json:"email_verified"`
		Amr           []string `json:"amr"`
	}

	m := &signin.Method{
		Name:     sessioninfo.MethodGoogle,
		LoginURL: authn.LoginURL,
		Begin: func(ctx context.Context, w http.ResponseWriter, _ *http.Request, returnURL string) (string, error) {
			return authn.AuthCodeURL(ctx, w, returnURL)
		},
		Complete: func(ctx context.Context, w http.ResponseWriter, r *http.Request) (*signin.Verified, error) {
			var rawClaims json.RawMessage
			returnURL, accessToken, err := authn.Verify(ctx, w, r, &rawClaims)
			if err != nil {
				return nil, errors.Wrap(err, "google.Authenticator.Verify()")
			}
			c, err := oidc.DecodeClaims[claims](rawClaims)
			if err != nil {
				return nil, sessioninfo.NewLoginRefusal(sessioninfo.RefusedClaimsParse, httpio.NewUnauthorizedMessageWithError(err, "Failed to parse ID token claims"))
			}
			if c.Email == "" {
				return nil, sessioninfo.NewLoginRefusal(sessioninfo.RefusedNoEmailClaim, httpio.NewUnauthorizedMessage("Unauthorized: token carries no email claim"))
			}
			if c.Sub == "" {
				return nil, sessioninfo.NewLoginRefusal(sessioninfo.RefusedClaimsParse, httpio.NewUnauthorizedMessage("ID token carries no sub"))
			}

			v := &signin.Verified{
				Identity: &sessioninfo.Identity{
					Method: sessioninfo.MethodGoogle, Subject: c.Sub, Email: c.Email, EmailVerified: c.EmailVerified, Claims: rawClaims, IDPAMR: c.Amr,
				},
				ReturnURL: returnURL,
			}
			if groups != nil {
				roleNames, err := groups.roleNames(ctx, c.Email, accessToken)
				if err != nil {
					return nil, errors.Wrap(err, "groupSync.roleNames()")
				}
				v.RoleNames = signin.RoleNames(roleNames)
			}

			return v, nil
		},
	}
	if groups != nil {
		m.SyncRoles = func(ctx context.Context, username string, roleNames []string) error {
			return groups.roles.RequireRoles(ctx, accesstypes.User(username), roleNames)
		}
	}

	return m
}
