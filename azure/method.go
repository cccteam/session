package azure

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

// Config configures the Microsoft Entra ID (Azure) sign-in method.
type Config struct {
	// IssuerURL is the tenant's OpenID Connect issuer.
	IssuerURL string
	// ClientID and ClientSecret are the application registration's.
	ClientID     string
	ClientSecret string
	// RedirectURL is where Microsoft sends the browser back: the Callback route.
	RedirectURL string
	// RoleSync is required: signin.RoleSync(manager) reconciles the user's roles to
	// the token's roles claim whenever an Azure sign-in establishes a session, and
	// refuses the sign-in (no_roles) when no recognized role results;
	// signin.DisableRoleSync() leaves roles to the application.
	RoleSync signin.RoleSyncConfig
	// LoginURL is where refused and pending sign-ins are sent. (default: /login)
	LoginURL string
	// Authenticator replaces the verifier built from the fields above. Tests inject a
	// fake identity provider through it; production leaves it nil.
	Authenticator Authenticator
}

// Method holds the handlers of the Microsoft Entra ID (Azure) sign-in method.
type Method struct {
	login              http.HandlerFunc
	callback           http.HandlerFunc
	frontChannelLogout http.HandlerFunc
}

// SignIn registers Microsoft Entra ID (Azure) OpenID Connect sign-in on auth and
// returns its handlers. The identity key is (tid, oid).
//
// It panics when the method is already registered on auth, when auth has served a
// request, when auth's storage has no identities configuration
// (sessionstorage.ErrIdentitiesNotConfigured), or when cfg.RoleSync is missing.
func SignIn(auth signin.Core, cfg *Config) *Method {
	if cfg == nil {
		cfg = &Config{}
	}
	h := signin.Register(auth, &signin.Registration{
		Method:             sessioninfo.MethodAzure,
		FrontChannelLogout: true,
		Build: func(cookies signin.StateCookies) (*signin.Method, error) {
			roles, err := signin.ReconcilerOf(cfg.RoleSync)
			if err != nil {
				return nil, errors.Wrap(err, "signin.ReconcilerOf()")
			}
			authn := cfg.Authenticator
			if authn == nil {
				o := NewOIDC(cookies, cfg.IssuerURL, cfg.ClientID, cfg.ClientSecret, cfg.RedirectURL)
				if cfg.LoginURL != "" {
					o.SetLoginURL(cfg.LoginURL)
				}
				authn = o
			}

			return method(authn, roles), nil
		},
	})

	return &Method{login: h.Login, callback: h.Callback, frontChannelLogout: h.FrontChannelLogout}
}

// Login redirects to Microsoft. It accepts ?returnUrl=, which must be a path in this
// application; any other value is refused with 400.
func (m *Method) Login() http.HandlerFunc { return m.login }

// Callback completes the provider round trip, resolves the identity and applies the
// sign-in policy. It then redirects:
//   - to returnUrl (default "/") when the session is established;
//   - to <LoginURL>?pending=<reason>[&returnUrl=<path>], or where a PendingHook sends
//     it, when the sign-in waits for confirmation or MFA;
//   - to <LoginURL>?code=<LoginRefusalCode> when it is refused.
func (m *Method) Callback() http.HandlerFunc { return m.callback }

// FrontChannelLogout handles Microsoft-initiated logout. Auth sessions do not record the
// provider's session ID yet, so it answers 501 Not Implemented.
func (m *Method) FrontChannelLogout() http.HandlerFunc { return m.frontChannelLogout }

// method is the Azure method over authn. The identity is (tid, oid). When roles is set,
// the token's roles claim is reconciled.
func method(authn Authenticator, roles *signin.RoleReconciler) *signin.Method {
	type claims struct {
		Tid   string   `json:"tid"`
		Oid   string   `json:"oid"`
		Email string   `json:"email"`
		Roles []string `json:"roles"`
		Amr   []string `json:"amr"`
	}

	m := &signin.Method{
		Name:     sessioninfo.MethodAzure,
		LoginURL: authn.LoginURL,
		Begin: func(ctx context.Context, w http.ResponseWriter, _ *http.Request, returnURL string) (string, error) {
			return authn.AuthCodeURL(ctx, w, returnURL)
		},
		Complete: func(ctx context.Context, w http.ResponseWriter, r *http.Request) (*signin.Verified, error) {
			// Auth sessions do not record the provider's session ID (sid) yet.
			var rawClaims json.RawMessage
			returnURL, _, err := authn.Verify(ctx, w, r, &rawClaims)
			if err != nil {
				return nil, errors.Wrap(err, "azure.Authenticator.Verify()")
			}
			c, err := oidc.DecodeClaims[claims](rawClaims)
			if err != nil {
				return nil, sessioninfo.NewLoginRefusal(sessioninfo.RefusedClaimsParse, httpio.NewUnauthorizedMessageWithError(err, "Failed to parse ID token claims"))
			}
			if c.Tid == "" || c.Oid == "" {
				return nil, sessioninfo.NewLoginRefusal(sessioninfo.RefusedClaimsParse, httpio.NewUnauthorizedMessage("ID token carries no tid and oid"))
			}

			v := &signin.Verified{
				Identity: &sessioninfo.Identity{
					Method: sessioninfo.MethodAzure, Connection: c.Tid, Subject: c.Oid, Email: c.Email, Claims: rawClaims, IDPAMR: c.Amr,
				},
				ReturnURL: returnURL,
			}
			if roles != nil {
				v.RoleNames = signin.RoleNames(c.Roles)
			}

			return v, nil
		},
	}
	if roles != nil {
		m.SyncRoles = func(ctx context.Context, username string, roleNames []string) error {
			return roles.RequireRoles(ctx, accesstypes.User(username), roleNames)
		}
	}

	return m
}
