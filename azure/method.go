package azure

import (
	"context"
	"encoding/json"
	"net/http"
	"strings"

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
	// Accounts is the standard account rule for a member of the tenant who signs in
	// for the first time: signin.MembersOfDirectory (the default) provisions an
	// account under the user principal name, signin.InvitedUsersOnly links only a
	// pre-created user under that name and refuses anyone else. A guest of the tenant
	// is refused by either (guest_account). signin.OpenSignUp is refused at
	// registration: this registration serves one tenant. A rule given to SignIn runs
	// first and may leave the decision to this one with signin.Standard.
	Accounts signin.StandardAccountRule
	// LoginURL is where refused and pending sign-ins are sent. (default: /login)
	LoginURL string
	// Authenticator replaces the verifier built from the fields above. Tests inject a
	// fake identity provider through it; production leaves it nil.
	Authenticator Authenticator
}

// Identity is a verified Microsoft Entra ID identity as the account rule receives it.
type Identity struct {
	// TenantID and ObjectID key the identity: the tid and oid claims.
	TenantID string
	ObjectID string
	// Email is the email claim. Microsoft does not verify it.
	Email string
	// PreferredUsername and Name are the preferred_username and name claims. The
	// preferred username is the user principal name of a member of the tenant, which
	// the standard account rules use as the username; a guest's is an address the
	// tenant did not verify.
	PreferredUsername string
	Name              string
	// Guest reports that the account is a guest of the tenant (B2B), not a member: the
	// idp claim names another identity provider than the token's issuer, or the
	// preferred username carries the #EXT# marker of a guest's user principal name.
	Guest bool
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

// AccountRule is the application's own rule for an Entra ID identity that is not
// linked to any user yet, given to SignIn; nil leaves every such identity to the
// standard rule in Config.Accounts. See signin.AccountRule for when it runs and what it
// may do. Tx is the Auth's storage transaction type.
type AccountRule[Tx any] func(ctx context.Context, tx Tx, identity *Identity) (*signin.Resolution, error)

// Method holds the handlers of the Microsoft Entra ID (Azure) sign-in method.
type Method struct {
	login              http.HandlerFunc
	callback           http.HandlerFunc
	frontChannelLogout http.HandlerFunc
}

// SignIn registers Microsoft Entra ID (Azure) OpenID Connect sign-in on auth under
// name and returns its handlers. name identifies the registration on auth, so one Auth
// can offer several Entra tenants as several registrations. The identity key is (tid,
// oid). An identity that is not linked yet is decided by rule when one is given and by
// the standard rule in cfg.Accounts otherwise, or when rule answers signin.Standard;
// nil is the usual value.
//
// It panics when name is empty or already used on auth, when auth has served a
// request, when cfg.RoleSync is missing, or when cfg.Accounts is open sign-up or no
// standard rule.
func SignIn[Tx any](auth signin.Core[Tx], name string, rule AccountRule[Tx], cfg *Config) *Method {
	if cfg == nil {
		cfg = &Config{}
	}
	accounts := cfg.Accounts
	if accounts == "" {
		accounts = signin.MembersOfDirectory
	}
	reg := &signin.Registration[Tx]{
		Name:               name,
		Method:             sessioninfo.MethodAzure,
		StandardRule:       accounts,
		AccountRule:        accountRule(rule),
		FrontChannelLogout: true,
		Issuers:            signin.IssuerList(cfg.IssuerURL),
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
	if accounts == signin.OpenSignUp {
		reg.Err = errors.New("Accounts: open sign-up is for any organization or personal accounts; this registration serves one tenant, which takes members of the directory or invited users only")
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
// A request whose iss names another issuer than Config.IssuerURL is refused with 400;
// a known sid is the request's only credential, as the front-channel logout design
// has it.
func (m *Method) FrontChannelLogout() http.HandlerFunc { return m.frontChannelLogout }

// claims are the ID token's claims the method reads.
type claims struct {
	Iss               string   `json:"iss"`
	Idp               string   `json:"idp"`
	Tid               string   `json:"tid"`
	Oid               string   `json:"oid"`
	Email             string   `json:"email"`
	PreferredUsername string   `json:"preferred_username"`
	Name              string   `json:"name"`
	Roles             []string `json:"roles"`
	Amr               []string `json:"amr"`
	Sid               string   `json:"sid"`
}

// guestMarker is the marker Entra puts in a guest's user principal name.
const guestMarker = "#EXT#"

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
		Guest: c.guest(), Roles: c.Roles, AMR: c.Amr, SessionID: c.Sid, Claims: rawClaims,
	}, nil
}

// guest reports whether the token's account is a guest of the tenant: Entra sets idp
// to the identity provider that authenticated the person when it is not the issuer,
// as it is for a guest, and a guest's user principal name carries the #EXT# marker.
func (c *claims) guest() bool {
	return (c.Idp != "" && c.Idp != c.Iss) || strings.Contains(c.PreferredUsername, guestMarker)
}

// accountRule adapts the application's rule to the contract: the identity the core
// decides is decoded from the claims the sign-in verified. A nil rule stays nil, so the
// standard rule applies.
func accountRule[Tx any](rule AccountRule[Tx]) signin.AccountRule[Tx] {
	if rule == nil {
		return nil
	}

	return func(ctx context.Context, tx Tx, req *sessioninfo.NewSessionRequest) (*signin.Resolution, error) {
		identity, err := identityOf(req.Identity.Claims)
		if err != nil {
			return nil, errors.Wrap(err, "azure.identityOf()")
		}

		return rule(ctx, tx, identity)
	}
}

// method is the Azure method over authn. The identity is (tid, oid), its sign-in name
// the preferred username. When roles is set, the token's roles claim is reconciled.
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
			iss, err := oidc.Issuer(rawClaims)
			if err != nil {
				return nil, errors.Wrap(err, "oidc.Issuer()")
			}

			v := &signin.Verified{
				Identity: &sessioninfo.Identity{
					Method: sessioninfo.MethodAzure, Connection: id.TenantID, Subject: id.ObjectID, Email: id.Email, Claims: rawClaims, IDPAMR: id.AMR,
					SignInName: id.PreferredUsername, Guest: id.Guest,
				},
				ReturnURL:         returnURL,
				ProviderSessionID: id.SessionID,
				Issuer:            iss,
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
