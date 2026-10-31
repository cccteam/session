package oidc

import (
	"context"
	"encoding/json"
	"net/http"
	"net/url"
	"slices"

	"github.com/cccteam/ccc/accesstypes"
	"github.com/cccteam/httpio"
	"github.com/cccteam/session/sessioninfo"
	"github.com/cccteam/session/signin"
	gooidc "github.com/coreos/go-oidc/v3/oidc"
	"github.com/go-playground/errors/v5"
)

// Config configures the generic OpenID Connect sign-in method: a provider with nothing
// vendor-specific about it, known by its issuer alone. The Entra, Google and WorkOS
// methods have packages of their own because their tokens carry a tenant, a Workspace
// or a connection the method must check; a provider that carries none, such as an
// identity gateway, Okta or Keycloak, is this one.
type Config struct {
	// Issuer is required: the provider's issuer URL. Its configuration is read at
	// <Issuer>/.well-known/openid-configuration, and every ID token must carry it.
	Issuer string
	// ClientID is the application's client identifier at the provider.
	ClientID string
	// ClientSecret is the client's secret, or empty for a public client: the code
	// exchange then carries the client ID alone, in the request body, and PKCE, which
	// every round trip of this library runs, binds the code to the login that asked
	// for it.
	ClientSecret string
	// RedirectURL is where the provider sends the browser back: the Callback route.
	RedirectURL string
	// Scopes are asked for beside openid; email and profile when empty.
	Scopes []string
	// Connection is what every identity link made through this registration carries
	// as its connection, the application's own name for the provider; the issuer URL
	// when empty. It is a key: renaming it makes every sign-in from the provider
	// arrive as an unknown identity until the links are re-keyed.
	Connection string
	// RoleSync is required: signin.RoleSync(manager) reconciles the user's roles to
	// the token's roles claim whenever a sign-in establishes a session, and refuses
	// the sign-in (no_roles) when no recognized role results;
	// signin.DisableRoleSync() leaves roles to the application.
	RoleSync signin.RoleSyncConfig
	// Accounts is the standard account rule for an account that signs in for the first
	// time: signin.MembersOfDirectory (the default) provisions an account under the
	// sign-in name, signin.InvitedUsersOnly links only a pre-created user under that
	// name and refuses anyone else, signin.OpenSignUp provisions anyone. The provider
	// is the directory: whoever it authenticates is a member of it. A rule given to
	// SignIn runs first and may leave the decision to this one with signin.Standard.
	Accounts signin.StandardAccountRule
	// Attesting declares that the provider enforces a second factor at every sign-in,
	// so a sign-in through it carries the attestation by declaration and is never
	// held for the library's code; a token whose amr claim names mfa attests by
	// evidence whatever the declaration. See "The second factor" in the README.
	Attesting bool
	// LoginURL is where refused and pending sign-ins are sent. (default: /login)
	LoginURL string
	// Authenticator replaces the verifier built from the fields above. Tests inject a
	// fake identity provider through it; production leaves it nil.
	Authenticator Authenticator
}

// Identity is a verified OpenID Connect identity as the account rule receives it.
type Identity struct {
	// Issuer is the iss claim: the provider the identity came from, the registration's.
	Issuer string
	// Subject keys the identity: the sub claim, unique among the provider's identities.
	Subject string
	// Email is the email claim, and EmailVerified whether the provider says it
	// verified the address (email_verified).
	Email         string
	EmailVerified bool
	// PreferredUsername is the preferred_username claim, the name the person signs in
	// with at the provider. The standard account rules use it as the username, and the
	// email when the provider sends none.
	PreferredUsername string
	// Name is the name claim.
	Name string
	// Roles are the role names the token asserts (the roles claim), nil when it
	// carries none.
	Roles []string
	// AMR are the authentication methods the token asserts (the amr claim).
	AMR []string
	// Claims are the ID token's claims as issued, for anything the fields above do not
	// carry.
	Claims json.RawMessage
}

// SignInName is the name the standard account rules use as the username: the
// preferred username, or the email when the provider sends none.
func (id *Identity) SignInName() string {
	if id.PreferredUsername != "" {
		return id.PreferredUsername
	}

	return id.Email
}

// AccountRule is the application's own rule for an identity of the provider that is not
// linked to any user yet, given to SignIn; nil leaves every such identity to the
// standard rule in Config.Accounts. See signin.AccountRule for when it runs and what it
// may do. Tx is the Auth's storage transaction type.
type AccountRule[Tx any] func(ctx context.Context, tx Tx, identity *Identity) (*signin.Resolution, error)

// Method holds the handlers of a generic OpenID Connect sign-in method.
type Method struct {
	login    http.HandlerFunc
	callback http.HandlerFunc
}

// SignIn registers OpenID Connect sign-in with the provider cfg.Issuer names on auth
// under name and returns its handlers. name identifies the registration on auth, so one
// Auth can offer several providers, each a registration of this method. The identity key
// is (cfg.Connection, sub). An identity that is not linked yet is decided by rule when
// one is given and by the standard rule in cfg.Accounts otherwise, or when rule answers
// signin.Standard; nil is the usual value.
//
// It panics when name is empty or already used on auth, when auth has served a
// request, when cfg.Issuer is missing or not an absolute URL, and when cfg.RoleSync is
// missing or malformed.
func SignIn[Tx any](auth signin.Core[Tx], name string, rule AccountRule[Tx], cfg *Config) *Method {
	if cfg == nil {
		cfg = &Config{}
	}
	accounts := cfg.Accounts
	if accounts == "" {
		accounts = signin.MembersOfDirectory
	}
	connection := cfg.Connection
	if connection == "" {
		connection = cfg.Issuer
	}
	reg := &signin.Registration[Tx]{
		Name:         name,
		Method:       sessioninfo.MethodOIDC,
		StandardRule: accounts,
		AccountRule:  accountRule(rule),
		Issuers:      signin.IssuerList(cfg.Issuer),
		Err:          refuseShape(cfg),
		Build: func(cookies signin.StateCookies) (*signin.Method, error) {
			roles, err := signin.ReconcilerOf(cfg.RoleSync)
			if err != nil {
				return nil, errors.Wrap(err, "signin.ReconcilerOf()")
			}
			authn := cfg.Authenticator
			if authn == nil {
				v := NewVerifier(cookies, cfg.Issuer, cfg.ClientID, cfg.ClientSecret, cfg.RedirectURL, cfg.Scopes)
				v.simulateAs(name)
				if cfg.LoginURL != "" {
					v.SetLoginURL(cfg.LoginURL)
				}
				authn = v
			}

			return method(authn, roles, cfg.Issuer, connection, cfg.Attesting), nil
		},
	}
	h := signin.Register(auth, reg)

	return &Method{login: h.Login, callback: h.Callback}
}

// refuseShape is the registration's startup check of its configuration, each refusal
// naming its field: an issuer that is not an absolute URL, and the role sync slot's
// own rules.
func refuseShape(cfg *Config) error {
	if err := validIssuer(cfg.Issuer); err != nil {
		return err
	}
	if _, err := signin.ReconcilerOf(cfg.RoleSync); err != nil {
		return errors.Wrap(err, "signin.ReconcilerOf()")
	}

	return nil
}

// validIssuer refuses an issuer that is not an absolute http or https URL without a
// query or fragment, the shape OpenID Connect discovery requires.
func validIssuer(issuer string) error {
	u, err := url.Parse(issuer)
	switch {
	case issuer == "":
		return errors.New("Issuer: the provider's issuer URL is required; discovery reads <Issuer>/.well-known/openid-configuration")
	case err != nil:
		return errors.Wrapf(err, "Issuer: %q is not a URL", issuer)
	case u.Scheme != "https" && u.Scheme != "http", u.Host == "", u.RawQuery != "", u.Fragment != "":
		return errors.Newf("Issuer: %q is not an absolute http or https URL without a query or fragment", issuer)
	default:
		return nil
	}
}

// scopesOf is the scope set the authorization request asks for: openid, then scopes,
// or email and profile when none are given.
func scopesOf(scopes []string) []string {
	if len(scopes) == 0 {
		scopes = []string{"email", "profile"}
	}
	set := make([]string, 0, len(scopes)+1)
	set = append(set, gooidc.ScopeOpenID)
	for _, s := range scopes {
		if s != "" && !slices.Contains(set, s) {
			set = append(set, s)
		}
	}

	return set
}

// Login redirects to the provider. It accepts ?returnUrl=, which must be a path in this
// application; any other value is refused with 400. It also accepts ?login_hint=,
// passed to the provider as its login_hint: the account it is asked to pick, or
// whatever else the provider reads from the hint (an identity gateway reads the persona
// it signs in). It is a hint and is never read back; the identity comes from the
// verified ID token. A hint longer than an email address can be (254 characters), or
// carrying spaces or control characters, is refused with 400. And it accepts
// ?prompt=select_account, passed to the provider as its prompt so it shows its account
// chooser even when it holds one signed-in account it would otherwise take without
// asking. Any other prompt value is refused with 400.
func (m *Method) Login() http.HandlerFunc { return m.login }

// Callback completes the provider round trip and redirects as the Azure method's
// Callback does.
func (m *Method) Callback() http.HandlerFunc { return m.callback }

// claims are the ID token's claims the method reads.
type claims struct {
	Iss               string   `json:"iss"`
	Sub               string   `json:"sub"`
	Email             string   `json:"email"`
	EmailVerified     bool     `json:"email_verified"`
	PreferredUsername string   `json:"preferred_username"`
	Name              string   `json:"name"`
	Roles             []string `json:"roles"`
	Amr               []string `json:"amr"`
}

// identityOf decodes the ID token's claims into the identity. A token without sub, or
// whose claims do not decode, is refused (claims_parse).
func identityOf(rawClaims json.RawMessage) (*Identity, error) {
	c, err := DecodeClaims[claims](rawClaims)
	if err != nil {
		return nil, sessioninfo.NewLoginRefusal(sessioninfo.RefusedClaimsParse, httpio.NewUnauthorizedMessageWithError(err, "Failed to parse ID token claims"))
	}
	if c.Sub == "" {
		return nil, sessioninfo.NewLoginRefusal(sessioninfo.RefusedClaimsParse, httpio.NewUnauthorizedMessage("ID token carries no sub"))
	}

	return &Identity{
		Issuer: c.Iss, Subject: c.Sub, Email: c.Email, EmailVerified: c.EmailVerified, PreferredUsername: c.PreferredUsername,
		Name: c.Name, Roles: c.Roles, AMR: c.Amr, Claims: rawClaims,
	}, nil
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
			return nil, errors.Wrap(err, "oidc.identityOf()")
		}

		return rule(ctx, tx, identity)
	}
}

// method is the generic method over authn. The identity is (connection, sub) and its
// sign-in name the preferred username, else the email. The authenticator verifies the
// token against the provider's discovered configuration; the issuer is checked here
// again, so an authenticator that did not cannot admit another provider's token. When
// roles is set, the token's roles claim is reconciled. The method cannot tell which
// addresses the provider admits, so it admits every one for an invitation.
func method(authn Authenticator, roles *signin.RoleReconciler, issuer, connection string, attesting bool) *signin.Method {
	m := &signin.Method{
		Name:     sessioninfo.MethodOIDC,
		LoginURL: authn.LoginURL,
		Begin: func(ctx context.Context, w http.ResponseWriter, r *http.Request, returnURL string) (string, error) {
			hint, err := signin.LoginHint(r)
			if err != nil {
				return "", errors.Wrap(err, "signin.LoginHint()")
			}
			chooser, err := signin.SelectAccount(r)
			if err != nil {
				return "", errors.Wrap(err, "signin.SelectAccount()")
			}

			return authn.AuthCodeURL(ctx, w, returnURL, signin.LoginOptions{LoginHint: hint, SelectAccount: chooser})
		},
		Complete: func(ctx context.Context, w http.ResponseWriter, r *http.Request) (*signin.Verified, error) {
			var rawClaims json.RawMessage
			returnURL, err := authn.Verify(ctx, w, r, &rawClaims)
			if err != nil {
				return nil, errors.Wrap(err, "oidc.Authenticator.Verify()")
			}
			id, err := identityOf(rawClaims)
			if err != nil {
				return nil, err
			}
			if id.Issuer != issuer {
				return nil, sessioninfo.NewLoginRefusal(sessioninfo.RefusedIDTokenVerification, httpio.NewUnauthorizedMessage("the ID token's issuer is not the registration's"))
			}

			v := &signin.Verified{
				Identity: &sessioninfo.Identity{
					Method: sessioninfo.MethodOIDC, Connection: connection, Subject: id.Subject, Email: id.Email, EmailVerified: id.EmailVerified, Claims: rawClaims,
					IDPAMR: id.AMR, SignInName: id.SignInName(), Organization: connection, Attestation: sessioninfo.AttestationOf(id.AMR, attesting),
				},
				ReturnURL: returnURL,
				Issuer:    id.Issuer,
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
		m.RecognizesRoles = func(ctx context.Context, roleNames []string) (bool, error) {
			return roles.RecognizesAny(ctx, roleNames)
		}
	}

	return m
}
