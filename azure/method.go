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

// Identity is a verified Microsoft Entra ID identity as the user resolver receives it.
type Identity struct {
	// TenantID and ObjectID key the identity: the tid and oid claims.
	TenantID string
	ObjectID string
	// Email is the email claim. Microsoft does not verify it.
	Email string
	// PreferredUsername and Name are the preferred_username and name claims.
	PreferredUsername string
	Name              string
	// Roles are the application roles the token asserts (the roles claim).
	Roles []string
	// AMR are the authentication methods the token asserts (the amr claim).
	AMR []string
	// SessionID is the sid claim: Entra's session id, which its front-channel logout
	// names.
	SessionID string
	// Claims are the ID token's claims as issued, for anything the fields above do not
	// carry.
	Claims json.RawMessage
}

// UserResolver decides an Entra ID identity that is not linked to any user yet. It is
// the application's rule, given to SignIn; see signin.UserResolver for when it runs and
// what it may do. Tx is the Auth's storage transaction type.
type UserResolver[Tx any] func(ctx context.Context, tx Tx, identity *Identity) (*signin.Resolution, error)

// Method holds the handlers of the Microsoft Entra ID (Azure) sign-in method.
type Method struct {
	login              http.HandlerFunc
	callback           http.HandlerFunc
	frontChannelLogout http.HandlerFunc
}

// SignIn registers Microsoft Entra ID (Azure) OpenID Connect sign-in on auth under
// name and returns its handlers. name identifies the registration on auth, so one Auth
// can offer several Entra tenants as several registrations. The identity key is (tid,
// oid); resolve decides an identity that is not linked yet.
//
// It panics when name is empty or already used on auth, when auth has served a
// request, when resolve is nil, or when cfg.RoleSync is missing.
func SignIn[Tx any](auth signin.Core[Tx], name string, resolve UserResolver[Tx], cfg *Config) *Method {
	if cfg == nil {
		cfg = &Config{}
	}
	reg := &signin.Registration[Tx]{
		Name:               name,
		Method:             sessioninfo.MethodAzure,
		Resolve:            resolver(resolve),
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
	}
	if resolve == nil {
		reg.Err = errors.New("resolve is required: it decides every Entra ID identity that is not linked yet")
	}
	h := signin.Register(auth, reg)

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

// FrontChannelLogout handles Microsoft-initiated logout. It ends every session whose
// sign-in carried the sid the request names (?sid=), answers 200, and 400 without a
// sid. Register its URL as the application's front-channel logout URL in Entra. Route it
// without ValidateSession: Entra calls it in a frame, with no session of its own.
func (m *Method) FrontChannelLogout() http.HandlerFunc { return m.frontChannelLogout }

// claims are the ID token's claims the method reads.
type claims struct {
	Tid               string   `json:"tid"`
	Oid               string   `json:"oid"`
	Email             string   `json:"email"`
	PreferredUsername string   `json:"preferred_username"`
	Name              string   `json:"name"`
	Roles             []string `json:"roles"`
	Amr               []string `json:"amr"`
	Sid               string   `json:"sid"`
}

// identityOf decodes the ID token's claims into the identity. A token without tid and
// oid, or whose claims do not decode, is refused (claims_parse).
func identityOf(rawClaims json.RawMessage) (*Identity, error) {
	c, err := oidc.DecodeClaims[claims](rawClaims)
	if err != nil {
		return nil, sessioninfo.NewLoginRefusal(sessioninfo.RefusedClaimsParse, httpio.NewUnauthorizedMessageWithError(err, "Failed to parse ID token claims"))
	}
	if c.Tid == "" || c.Oid == "" {
		return nil, sessioninfo.NewLoginRefusal(sessioninfo.RefusedClaimsParse, httpio.NewUnauthorizedMessage("ID token carries no tid and oid"))
	}

	return &Identity{
		TenantID: c.Tid, ObjectID: c.Oid, Email: c.Email, PreferredUsername: c.PreferredUsername, Name: c.Name,
		Roles: c.Roles, AMR: c.Amr, SessionID: c.Sid, Claims: rawClaims,
	}, nil
}

// resolver adapts the application's resolver to the contract: the identity the core
// resolves is decoded from the claims the sign-in verified.
func resolver[Tx any](resolve UserResolver[Tx]) signin.UserResolver[Tx] {
	return func(ctx context.Context, tx Tx, req *sessioninfo.NewSessionRequest) (*signin.Resolution, error) {
		identity, err := identityOf(req.Identity.Claims)
		if err != nil {
			return nil, errors.Wrap(err, "azure.identityOf()")
		}

		return resolve(ctx, tx, identity)
	}
}

// method is the Azure method over authn. The identity is (tid, oid). When roles is set,
// the token's roles claim is reconciled.
func method(authn Authenticator, roles *signin.RoleReconciler) *signin.Method {
	m := &signin.Method{
		Name:     sessioninfo.MethodAzure,
		LoginURL: authn.LoginURL,
		Begin: func(ctx context.Context, w http.ResponseWriter, _ *http.Request, returnURL string) (string, error) {
			return authn.AuthCodeURL(ctx, w, returnURL)
		},
		Complete: func(ctx context.Context, w http.ResponseWriter, r *http.Request) (*signin.Verified, error) {
			var rawClaims json.RawMessage
			returnURL, _, err := authn.Verify(ctx, w, r, &rawClaims)
			if err != nil {
				return nil, errors.Wrap(err, "azure.Authenticator.Verify()")
			}
			id, err := identityOf(rawClaims)
			if err != nil {
				return nil, err
			}

			v := &signin.Verified{
				Identity: &sessioninfo.Identity{
					Method: sessioninfo.MethodAzure, Connection: id.TenantID, Subject: id.ObjectID, Email: id.Email, Claims: rawClaims, IDPAMR: id.AMR,
				},
				ReturnURL:         returnURL,
				ProviderSessionID: id.SessionID,
			}
			if roles != nil {
				v.RoleNames = signin.RoleNames(id.Roles)
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
