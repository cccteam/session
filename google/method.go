package google

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

// Config configures the Google Workspace sign-in method.
type Config struct {
	// ClientID and ClientSecret are the OAuth client's.
	ClientID     string
	ClientSecret string
	// RedirectURL is where Google sends the browser back: the Callback route.
	RedirectURL string
	// Workspaces is required: which Google accounts may sign in, and the connection
	// each identity link carries (Method google, Connection, Subject sub). One
	// Workspace, Workspace(name, domains...), is the application that belongs to one
	// organization; Workspaces(...) names several; AnyWorkspace() admits any Workspace
	// account and AnyGoogleAccount() any Google account. The verified hd claim selects
	// the entry at the callback, before the account rules run, so an account the slot
	// does not admit never reaches a row (not_workspace_member). With one domain the
	// login hints it to Google's account chooser; with several or any Workspace it
	// hints any Workspace account; with any Google account it hints nothing, and a
	// login hint (see Method.Login) picks the account outright.
	Workspaces WorkspaceSet
	// RoleSync is required: RoleSync(manager, groupPrefix, lookup) reconciles the
	// user's roles to the person's groups whenever a Google sign-in establishes a
	// session, and refuses the sign-in (no_roles) when no recognized role results;
	// DisableRoleSync() leaves roles to the application. Role synchronization reads
	// the groups of one Workspace: it is refused with several Workspaces, any
	// Workspace or any Google account.
	RoleSync RoleSyncConfig
	// Accounts is the standard account rule for an account that signs in for the first
	// time: signin.MembersOfDirectory (the default) provisions an account under the
	// verified email, signin.InvitedUsersOnly links only a pre-created user under that
	// email and refuses anyone else, signin.OpenSignUp provisions anyone. With one or
	// several named Workspaces open sign-up is refused at registration; with any
	// Workspace or any Google account members of the directory is refused unless a
	// rule is given to SignIn, since it would sign up the world. A rule given to
	// SignIn runs first and may leave the decision to this one with signin.Standard.
	Accounts signin.StandardAccountRule
	// LoginURL is where refused and pending sign-ins are sent. (default: /login)
	LoginURL string
	// Authenticator replaces the verifier built from the fields above. Tests inject a
	// fake identity provider through it; production leaves it nil.
	Authenticator Authenticator
}

// Identity is a verified Google Workspace identity as the account rule receives it.
type Identity struct {
	// Subject keys the identity: the sub claim, unique among all Google identities.
	Subject string
	// Email is the email claim; the sign-in refused it unless Google verified it. The
	// standard account rules use it as the username.
	Email string
	// HostedDomain is the hd claim: the domain of the Workspace the account is on, ""
	// for a Google account outside a Workspace, which only AnyGoogleAccount admits.
	HostedDomain string
	// Workspace is the connection the identity's link carries, as Config.Workspaces
	// selected it: the application's name for a named Workspace, the account's domain
	// under AnyWorkspace, AnyAccountConnection under AnyGoogleAccount.
	Workspace string
	// Name is the name claim.
	Name string
	// AMR are the authentication methods the token asserts (the amr claim).
	AMR []string
	// Claims are the ID token's claims as issued, for anything the fields above do not
	// carry.
	Claims json.RawMessage
}

// AccountRule is the application's own rule for a Google identity that is not linked
// to any user yet, given to SignIn; nil leaves every such identity to the standard rule
// in Config.Accounts. See signin.AccountRule for when it runs and what it may do. Tx is
// the Auth's storage transaction type.
type AccountRule[Tx any] func(ctx context.Context, tx Tx, identity *Identity) (*signin.Resolution, error)

// Method holds the handlers of the Google Workspace sign-in method.
type Method struct {
	login    http.HandlerFunc
	callback http.HandlerFunc
}

// SignIn registers Google Workspace OpenID Connect sign-in on auth under name and
// returns its handlers. name identifies the registration on auth. The identity key is
// (connection, sub), the connection being what cfg.Workspaces selects for the account.
// An identity that is not linked yet is decided by rule when one is given and by the
// standard rule in cfg.Accounts otherwise, or when rule answers signin.Standard; nil is
// the usual value.
//
// It panics when name is empty or already used on auth, when auth has served a
// request, when cfg.RoleSync or cfg.Workspaces is missing or malformed, when role
// synchronization is asked for with other than one Workspace, and when cfg.Accounts
// does not fit the slot: open sign-up with named Workspaces only, members of the
// directory with any Workspace or any Google account and no rule, or no standard rule.
func SignIn[Tx any](auth signin.Core[Tx], name string, rule AccountRule[Tx], cfg *Config) *Method {
	if cfg == nil {
		cfg = &Config{}
	}
	accounts := cfg.Accounts
	if accounts == "" {
		accounts = signin.MembersOfDirectory
	}
	reg := &signin.Registration[Tx]{
		Name:         name,
		Method:       sessioninfo.MethodGoogle,
		StandardRule: accounts,
		AccountRule:  accountRule(rule),
		Issuers:      signin.IssuerList(IssuerURL),
		Err:          refuseShape(cfg.Workspaces, cfg.RoleSync, accounts, rule == nil),
		Build: func(cookies signin.StateCookies) (*signin.Method, error) {
			groups, err := groupSyncOf(cfg.RoleSync)
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
				o := NewOIDC(cookies, cfg.ClientID, cfg.ClientSecret, cfg.RedirectURL, cfg.Workspaces, scopes...)
				o.simulateAs(name)
				if cfg.LoginURL != "" {
					o.SetLoginURL(cfg.LoginURL)
				}
				authn = o
			}

			return method(authn, groups, cfg.Workspaces), nil
		},
	}
	h := signin.Register(auth, reg)

	return &Method{login: h.Login, callback: h.Callback}
}

// refuseShape is the registration's startup check of the organization slot against the
// role sync slot and the account rules, each refusal naming its field: the slot's own
// rules (validate), role synchronization with other than one Workspace, open sign-up
// with named Workspaces only, and members of the directory with an open slot and no
// rule of the application's own.
func refuseShape(workspaces WorkspaceSet, roleSync RoleSyncConfig, accounts signin.StandardAccountRule, noRule bool) error {
	if err := workspaces.validate(); err != nil {
		return err
	}
	if _, one := workspaces.one(); !one && roleSync != nil && roleSync.groupSync() != nil {
		return errors.New("RoleSync: role synchronization reads the groups of one Workspace; a registration serving several Workspaces, any Workspace or any Google account takes google.DisableRoleSync()")
	}
	switch {
	case accounts == signin.OpenSignUp && !workspaces.open():
		return errors.New("Accounts: open sign-up is for any Workspace or any Google account; a registration naming its Workspaces takes members of the directory or invited users only")
	case accounts == signin.MembersOfDirectory && workspaces.open() && noRule:
		return errors.New("Accounts: members of the directory with any Workspace or any Google account would sign up the world; " +
			"use signin.InvitedUsersOnly, signin.OpenSignUp, or give SignIn a rule of the application's own")
	}

	return nil
}

// Login redirects to Google. It accepts ?returnUrl=, which must be a path in this
// application; any other value is refused with 400. It also accepts ?login_hint=, the
// person's email address (or Google account id), passed to Google as its login_hint so
// Google picks that account when it is signed in and skips its account chooser, or
// pre-fills the sign-in form otherwise: an identifier-first login page, where the
// person types their email before choosing how to sign in, skips the chooser whatever
// the registration's domain count. It is a hint and is never read back; the identity
// comes from the verified ID token. A hint longer than an email address can be (254
// characters), or carrying spaces or control characters, is refused with 400.
func (m *Method) Login() http.HandlerFunc { return m.login }

// Callback completes the provider round trip and redirects as the Azure method's
// Callback does.
func (m *Method) Callback() http.HandlerFunc { return m.callback }

// claims are the ID token's claims the method reads.
type claims struct {
	Sub           string   `json:"sub"`
	Email         string   `json:"email"`
	EmailVerified bool     `json:"email_verified"`
	Hd            string   `json:"hd"`
	Name          string   `json:"name"`
	Amr           []string `json:"amr"`
}

// identityOf decodes the ID token's claims into the identity. A token without sub or
// email, or whose claims do not decode, is refused.
func identityOf(rawClaims json.RawMessage) (*Identity, bool, error) {
	c, err := oidc.DecodeClaims[claims](rawClaims)
	if err != nil {
		return nil, false, sessioninfo.NewLoginRefusal(sessioninfo.RefusedClaimsParse, httpio.NewUnauthorizedMessageWithError(err, "Failed to parse ID token claims"))
	}
	if c.Email == "" {
		return nil, false, sessioninfo.NewLoginRefusal(sessioninfo.RefusedNoEmailClaim, httpio.NewUnauthorizedMessage("Unauthorized: token carries no email claim"))
	}
	if c.Sub == "" {
		return nil, false, sessioninfo.NewLoginRefusal(sessioninfo.RefusedClaimsParse, httpio.NewUnauthorizedMessage("ID token carries no sub"))
	}

	return &Identity{Subject: c.Sub, Email: c.Email, HostedDomain: c.Hd, Name: c.Name, AMR: c.Amr, Claims: rawClaims}, c.EmailVerified, nil
}

// accountRule adapts the application's rule to the contract: the identity the core
// decides is decoded from the claims the sign-in verified. A nil rule stays nil, so the
// standard rule applies.
func accountRule[Tx any](rule AccountRule[Tx]) signin.AccountRule[Tx] {
	if rule == nil {
		return nil
	}

	return func(ctx context.Context, tx Tx, req *sessioninfo.NewSessionRequest) (*signin.Resolution, error) {
		identity, _, err := identityOf(req.Identity.Claims)
		if err != nil {
			return nil, errors.Wrap(err, "google.identityOf()")
		}
		identity.Workspace = req.Identity.Connection

		return rule(ctx, tx, identity)
	}
}

// method is the Google method over authn. The identity is (connection, sub), the
// connection being what workspaces selects for the account's hd claim, and its sign-in
// name the verified email. The authenticator checks the slot and the verified email;
// the slot is checked here again, so an authenticator that did not cannot admit an
// account outside it. When groups is set, the callback maps the person's directory
// groups to role names using the access token, which is used once and never stored.
func method(authn Authenticator, groups *groupSync, workspaces WorkspaceSet) *signin.Method {
	m := &signin.Method{
		Name:     sessioninfo.MethodGoogle,
		LoginURL: authn.LoginURL,
		Begin: func(ctx context.Context, w http.ResponseWriter, r *http.Request, returnURL string) (string, error) {
			hint, err := loginHint(r)
			if err != nil {
				return "", err
			}

			return authn.AuthCodeURL(ctx, w, returnURL, hint)
		},
		Complete: func(ctx context.Context, w http.ResponseWriter, r *http.Request) (*signin.Verified, error) {
			var rawClaims json.RawMessage
			returnURL, accessToken, err := authn.Verify(ctx, w, r, &rawClaims)
			if err != nil {
				return nil, errors.Wrap(err, "google.Authenticator.Verify()")
			}
			id, emailVerified, err := identityOf(rawClaims)
			if err != nil {
				return nil, err
			}
			iss, err := oidc.Issuer(rawClaims)
			if err != nil {
				return nil, errors.Wrap(err, "oidc.Issuer()")
			}
			connection, ok := workspaces.connectionFor(id.HostedDomain)
			if !ok {
				return nil, errNotWorkspaceMember()
			}

			v := &signin.Verified{
				Identity: &sessioninfo.Identity{
					Method: sessioninfo.MethodGoogle, Connection: connection, Subject: id.Subject, Email: id.Email, EmailVerified: emailVerified, Claims: rawClaims, IDPAMR: id.AMR,
					Organization: connection,
				},
				ReturnURL: returnURL,
				Issuer:    iss,
			}
			if emailVerified {
				v.Identity.SignInName = id.Email
			}
			if groups != nil {
				roleNames, err := groups.roleNames(ctx, id.Email, accessToken)
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

// errNotWorkspaceMember is the refusal of an account the registration's Workspaces do
// not admit: a Workspace outside the named ones without AnyWorkspace, or an account
// outside any Workspace without AnyGoogleAccount.
func errNotWorkspaceMember() error {
	return sessioninfo.NewLoginRefusal(sessioninfo.RefusedNotWorkspaceMember, httpio.NewForbiddenMessage("User is not in a Google Workspace this sign-in admits"))
}

// maxLoginHint bounds ?login_hint=: an email address is at most 254 characters.
const maxLoginHint = 254

// loginHint reads ?login_hint=, the account Google is asked to pick, or "" when the
// login page gave none. A hint longer than an email address can be, or carrying spaces
// or control characters, is a login page's mistake and is refused.
func loginHint(r *http.Request) (string, error) {
	hint := r.URL.Query().Get("login_hint")
	if len(hint) > maxLoginHint || strings.ContainsFunc(hint, func(c rune) bool { return c <= ' ' || c == 0x7f }) {
		return "", httpio.NewBadRequestMessage("login_hint must be an email address or account id without spaces")
	}

	return hint, nil
}
