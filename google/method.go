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
	// Connection is required: the application's own name for this Google Workspace
	// organization. It is written into every Google identity link as the identity's
	// connection (Method google, Connection, Subject sub) and onto the sign-in events,
	// so a policy tells Workspaces apart by it. Google puts no stable organization id
	// in the ID token, and one Workspace answers for every domain it owns, so the
	// application names the Workspace rather than the library keying on a domain.
	//
	// It is a key. Changing it makes every Google sign-in arrive as an unknown
	// identity until the links are re-keyed:
	//
	//	UPDATE SessionIdentities SET "Connection" = 'new' WHERE "Method" = 'google' AND "Connection" = 'old'
	Connection string
	// HostedDomains is required: the Google Workspace domains sign-in is restricted
	// to, one or more, checked against the verified hd claim. With one domain the
	// login hints it to Google's account chooser; with several it hints any Workspace
	// account, and a login hint (see Method.Login) picks the account outright.
	HostedDomains []string
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

// Identity is a verified Google Workspace identity as the user resolver receives it.
type Identity struct {
	// Subject keys the identity: the sub claim, unique among all Google identities.
	Subject string
	// Email is the email claim; the sign-in refused it unless Google verified it.
	Email string
	// HostedDomain is the hd claim: the Workspace domain the person's account is on,
	// one of the registration's HostedDomains.
	HostedDomain string
	// Name is the name claim.
	Name string
	// AMR are the authentication methods the token asserts (the amr claim).
	AMR []string
	// Claims are the ID token's claims as issued, for anything the fields above do not
	// carry.
	Claims json.RawMessage
}

// UserResolver decides a Google identity that is not linked to any user yet. It is the
// application's rule, given to SignIn; see signin.UserResolver for when it runs and
// what it may do. Tx is the Auth's storage transaction type.
type UserResolver[Tx any] func(ctx context.Context, tx Tx, identity *Identity) (*signin.Resolution, error)

// Method holds the handlers of the Google Workspace sign-in method.
type Method struct {
	login    http.HandlerFunc
	callback http.HandlerFunc
}

// SignIn registers Google Workspace OpenID Connect sign-in on auth under name and
// returns its handlers. name identifies the registration on auth. The identity key is
// (cfg.Connection, sub); resolve decides an identity that is not linked yet.
//
// It panics when name is empty or already used on auth, when auth has served a
// request, when resolve is nil, or when cfg.RoleSync, cfg.Connection or
// cfg.HostedDomains is missing.
func SignIn[Tx any](auth signin.Core[Tx], name string, resolve UserResolver[Tx], cfg *Config) *Method {
	if cfg == nil {
		cfg = &Config{}
	}
	reg := &signin.Registration[Tx]{
		Name:    name,
		Method:  sessioninfo.MethodGoogle,
		Resolve: resolver(resolve),
		Build: func(cookies signin.StateCookies) (*signin.Method, error) {
			if strings.TrimSpace(cfg.Connection) == "" {
				return nil, errors.New("connection is required: the application's name for the Workspace, which keys every Google identity link; see google.Config.Connection")
			}
			groups, err := groupSyncOf(cfg.RoleSync, cfg.HostedDomains)
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
				o := NewOIDC(cookies, cfg.ClientID, cfg.ClientSecret, cfg.RedirectURL, cfg.HostedDomains, scopes...)
				if cfg.LoginURL != "" {
					o.SetLoginURL(cfg.LoginURL)
				}
				authn = o
			}

			return method(authn, groups, cfg.Connection), nil
		},
	}
	if resolve == nil {
		reg.Err = errors.New("resolve is required: it decides every Google identity that is not linked yet")
	}
	h := signin.Register(auth, reg)

	return &Method{login: h.Login, callback: h.Callback}
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

// resolver adapts the application's resolver to the contract: the identity the core
// resolves is decoded from the claims the sign-in verified.
func resolver[Tx any](resolve UserResolver[Tx]) signin.UserResolver[Tx] {
	return func(ctx context.Context, tx Tx, req *sessioninfo.NewSessionRequest) (*signin.Resolution, error) {
		identity, _, err := identityOf(req.Identity.Claims)
		if err != nil {
			return nil, errors.Wrap(err, "google.identityOf()")
		}

		return resolve(ctx, tx, identity)
	}
}

// method is the Google Workspace method over authn. The identity is (connection, sub),
// connection being the registration's name for the Workspace. The authenticator checks
// the hosted domains and the verified email. When groups is set, the callback maps the
// person's directory groups to role names using the access token, which is used once
// and never stored.
func method(authn Authenticator, groups *groupSync, connection string) *signin.Method {
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

			v := &signin.Verified{
				Identity: &sessioninfo.Identity{
					Method: sessioninfo.MethodGoogle, Connection: connection, Subject: id.Subject, Email: id.Email, EmailVerified: emailVerified, Claims: rawClaims, IDPAMR: id.AMR,
				},
				ReturnURL: returnURL,
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
