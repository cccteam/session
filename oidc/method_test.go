package oidc

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/cccteam/session/internal/oidctest"
	"github.com/cccteam/session/mock/mock_signin"
	"github.com/cccteam/session/sessioninfo"
	"github.com/cccteam/session/signin"
	"github.com/go-playground/errors/v5"
	"github.com/google/go-cmp/cmp"
	"go.uber.org/mock/gomock"
)

const (
	issuer      = "https://id.example.com"
	redirectURL = "https://app.example.com/api/user/gateway/callback"
)

// fakeCore stands in for the Auth: it keeps the registration SignIn asks for, so a test
// reads what was registered and builds the method itself.
type fakeCore struct {
	reg *signin.Registration[struct{}]
}

func (c *fakeCore) RegisterExternal(reg *signin.Registration[struct{}]) signin.Handlers {
	c.reg = reg

	return signin.Handlers{}
}

// fakeAuthenticator answers the round trip from memory: it records the login options
// it was asked for, and its callback produces the claims the test gives it.
type fakeAuthenticator struct {
	options signin.LoginOptions
	claims  map[string]any
}

func (f *fakeAuthenticator) AuthCodeURL(_ context.Context, _ http.ResponseWriter, returnURL string, options signin.LoginOptions) (string, error) {
	f.options = options

	return issuer + "/authorize?return=" + returnURL, nil
}

func (f *fakeAuthenticator) Verify(_ context.Context, _ http.ResponseWriter, _ *http.Request, claims any) (string, error) {
	raw, err := json.Marshal(f.claims)
	if err != nil {
		return "", errors.Wrap(err, "json.Marshal()")
	}
	if err := json.Unmarshal(raw, claims); err != nil {
		return "", errors.Wrap(err, "json.Unmarshal()")
	}

	return "/home", nil
}

func (*fakeAuthenticator) LoginURL() string { return "/login" }

func baseConfig(authn Authenticator) *Config {
	return &Config{Issuer: issuer, ClientID: "lanterns", RedirectURL: redirectURL, RoleSync: signin.DisableRoleSync(), Authenticator: authn}
}

// register registers cfg on a fake core under "gateway" and returns the registration.
func register(t *testing.T, rule AccountRule[struct{}], cfg *Config) *signin.Registration[struct{}] {
	t.Helper()

	core := &fakeCore{}
	SignIn[struct{}](core, "gateway", rule, cfg)
	if core.reg == nil {
		t.Fatal("SignIn() registered nothing")
	}

	return core.reg
}

// build registers cfg and builds its method, as the core does at registration.
func build(t *testing.T, cfg *Config) *signin.Method {
	t.Helper()

	reg := register(t, nil, cfg)
	if reg.Err != nil {
		t.Fatalf("registration refused: %v", reg.Err)
	}
	m, err := reg.Build(oidctest.NewCookieClient(t).ForRegistration("gateway"))
	if err != nil {
		t.Fatalf("Registration.Build() error = %v", err)
	}

	return m
}

func claimsOf(t *testing.T, c map[string]any) json.RawMessage {
	t.Helper()

	raw, err := json.Marshal(c)
	if err != nil {
		t.Fatalf("json.Marshal() error = %v", err)
	}

	return raw
}

// TestSignIn_registration proves what SignIn asks the core to register: the method, the
// standard rule with its default, the issuer, no front-channel logout, and no account
// rule unless the application gave one.
func TestSignIn_registration(t *testing.T) {
	t.Parallel()

	reg := register(t, nil, baseConfig(nil))
	if reg.Err != nil {
		t.Fatalf("registration refused: %v", reg.Err)
	}
	if reg.Name != "gateway" || reg.Method != sessioninfo.MethodOIDC || reg.StandardRule != signin.MembersOfDirectory || reg.AccountRule != nil || reg.FrontChannelLogout {
		t.Errorf("registration = {Name %q, Method %q, StandardRule %q, AccountRule nil %v, FrontChannelLogout %v}", reg.Name, reg.Method, reg.StandardRule, reg.AccountRule == nil, reg.FrontChannelLogout)
	}
	if only, ok := reg.Issuers.Only(); !ok || only != issuer || !reg.Issuers.Contains(issuer) || reg.Issuers.Contains("https://other.example.com") {
		t.Errorf("Issuers = %v, want exactly %q", reg.Issuers, issuer)
	}

	cfg := baseConfig(nil)
	cfg.Accounts = signin.InvitedUsersOnly
	if reg := register(t, nil, cfg); reg.StandardRule != signin.InvitedUsersOnly {
		t.Errorf("StandardRule = %q, want the configured %q", reg.StandardRule, signin.InvitedUsersOnly)
	}
}

// TestSignIn_refusals proves the misuses the registration reports at startup, each naming
// its field.
func TestSignIn_refusals(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name    string
		cfg     *Config
		wantHas string
	}{
		{name: "no issuer", cfg: &Config{RoleSync: signin.DisableRoleSync()}, wantHas: "Issuer: the provider's issuer URL is required"},
		{name: "an issuer without a scheme", cfg: &Config{Issuer: "id.example.com", RoleSync: signin.DisableRoleSync()}, wantHas: "Issuer: \"id.example.com\" is not an absolute http or https URL"},
		{name: "an issuer with a query", cfg: &Config{Issuer: "https://id.example.com/?tenant=1", RoleSync: signin.DisableRoleSync()}, wantHas: "Issuer: \"https://id.example.com/?tenant=1\" is not an absolute http or https URL"},
		{name: "an issuer with a fragment", cfg: &Config{Issuer: "https://id.example.com/#x", RoleSync: signin.DisableRoleSync()}, wantHas: "is not an absolute http or https URL"},
		{name: "no role sync slot", cfg: &Config{Issuer: issuer}, wantHas: "RoleSync"},
		{name: "a nil config", cfg: nil, wantHas: "Issuer: the provider's issuer URL is required"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			reg := register(t, nil, tt.cfg)
			if reg.Err == nil || !strings.Contains(reg.Err.Error(), tt.wantHas) {
				t.Errorf("registration Err = %v, want one containing %q", reg.Err, tt.wantHas)
			}
		})
	}
}

// TestSignIn_accountRule proves the application's rule receives the identity decoded
// from the claims the sign-in verified, and that a nil rule leaves the standard rule in
// charge.
func TestSignIn_accountRule(t *testing.T) {
	t.Parallel()

	var got *Identity
	stop := errors.New("the rule decided")
	rule := func(_ context.Context, _ struct{}, identity *Identity) (*signin.Resolution, error) {
		got = identity

		return nil, stop
	}
	reg := register(t, rule, baseConfig(nil))
	if reg.AccountRule == nil {
		t.Fatal("AccountRule is nil, want the application's rule adapted")
	}
	raw := claimsOf(t, map[string]any{"iss": issuer, "sub": "cadet", "email": "cadet@example.com", "email_verified": true, "preferred_username": "cadet", "name": "Cadet Example", "roles": []string{"Cadet"}})
	_, err := reg.AccountRule(t.Context(), struct{}{}, &sessioninfo.NewSessionRequest{Identity: &sessioninfo.Identity{Claims: raw}})
	if !errors.Is(err, stop) {
		t.Fatalf("AccountRule() error = %v, want the rule's own", err)
	}
	want := &Identity{Issuer: issuer, Subject: "cadet", Email: "cadet@example.com", EmailVerified: true, PreferredUsername: "cadet", Name: "Cadet Example", Roles: []string{"Cadet"}, Claims: raw}
	if diff := cmp.Diff(want, got); diff != "" {
		t.Errorf("identity mismatch (-want +got):\n%s", diff)
	}
	if got.SignInName() != "cadet" {
		t.Errorf("SignInName() = %q, want the preferred username", got.SignInName())
	}
}

// TestMethod_Begin proves the login route's parameters reach the provider as its hints,
// and that a malformed hint or prompt is a login page's mistake, refused.
func TestMethod_Begin(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name        string
		query       string
		wantOptions signin.LoginOptions
		wantErr     bool
	}{
		{name: "no hints", query: ""},
		{name: "the hint and the chooser", query: "?login_hint=cadet&prompt=select_account", wantOptions: signin.LoginOptions{LoginHint: "cadet", SelectAccount: true}},
		{name: "a hint with a space is refused", query: "?login_hint=a+b", wantErr: true},
		{name: "another prompt is refused", query: "?prompt=consent", wantErr: true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			authn := &fakeAuthenticator{}
			m := build(t, baseConfig(authn))
			r := httptest.NewRequestWithContext(t.Context(), http.MethodGet, "/api/user/gateway/login"+tt.query, http.NoBody)
			u, err := m.Begin(t.Context(), httptest.NewRecorder(), r, "/app")
			if (err != nil) != tt.wantErr {
				t.Fatalf("Method.Begin() error = %v, wantErr %v", err, tt.wantErr)
			}
			if err != nil {
				return
			}
			if u != issuer+"/authorize?return=/app" {
				t.Errorf("Method.Begin() = %q, want the provider's URL for /app", u)
			}
			if diff := cmp.Diff(tt.wantOptions, authn.options); diff != "" {
				t.Errorf("login options mismatch (-want +got):\n%s", diff)
			}
		})
	}
}

// TestMethod_Complete proves what a completed round trip verifies: the identity keyed by
// the connection and the subject, its sign-in name, its attestation, the issuer, and the
// role names when the registration synchronizes roles; and the refusals of a token
// without a subject or from another issuer.
func TestMethod_Complete(t *testing.T) {
	t.Parallel()

	base := func() map[string]any {
		return map[string]any{"iss": issuer, "sub": "cadet", "email": "cadet@example.com", "email_verified": true, "preferred_username": "cadet", "name": "Cadet Example", "roles": []string{"Cadet"}, "amr": []string{"pwd"}}
	}
	tests := []struct {
		name     string
		claims   map[string]any
		config   func(cfg *Config)
		roleSync bool
		want     *signin.Verified
		wantCode sessioninfo.LoginRefusalCode
	}{
		{
			name: "the identity under the issuer as the connection", claims: base(),
			want: &signin.Verified{Identity: &sessioninfo.Identity{
				Method: sessioninfo.MethodOIDC, Connection: issuer, Subject: "cadet", Email: "cadet@example.com", EmailVerified: true,
				IDPAMR: []string{"pwd"}, SignInName: "cadet", Organization: issuer, Attestation: sessioninfo.NotAttested,
			}, ReturnURL: "/home", Issuer: issuer},
		},
		{
			name: "the configured connection", claims: base(), config: func(cfg *Config) { cfg.Connection = "gateway" },
			want: &signin.Verified{Identity: &sessioninfo.Identity{
				Method: sessioninfo.MethodOIDC, Connection: "gateway", Subject: "cadet", Email: "cadet@example.com", EmailVerified: true,
				IDPAMR: []string{"pwd"}, SignInName: "cadet", Organization: "gateway",
			}, ReturnURL: "/home", Issuer: issuer},
		},
		{
			name:   "the email is the sign-in name when the provider sends no preferred username",
			claims: map[string]any{"iss": issuer, "sub": "s-1", "email": "pat@example.com"},
			want: &signin.Verified{Identity: &sessioninfo.Identity{
				Method: sessioninfo.MethodOIDC, Connection: issuer, Subject: "s-1", Email: "pat@example.com", SignInName: "pat@example.com", Organization: issuer,
			}, ReturnURL: "/home", Issuer: issuer},
		},
		{
			name: "a declared provider attests by declaration", claims: base(), config: func(cfg *Config) { cfg.Attesting = true },
			want: &signin.Verified{Identity: &sessioninfo.Identity{
				Method: sessioninfo.MethodOIDC, Connection: issuer, Subject: "cadet", Email: "cadet@example.com", EmailVerified: true,
				IDPAMR: []string{"pwd"}, SignInName: "cadet", Organization: issuer, Attestation: sessioninfo.AttestedByDeclaration,
			}, ReturnURL: "/home", Issuer: issuer},
		},
		{
			name:   "a token naming mfa attests by evidence without a declaration",
			claims: func() map[string]any { c := base(); c["amr"] = []string{"pwd", "mfa"}; return c }(),
			want: &signin.Verified{Identity: &sessioninfo.Identity{
				Method: sessioninfo.MethodOIDC, Connection: issuer, Subject: "cadet", Email: "cadet@example.com", EmailVerified: true,
				IDPAMR: []string{"pwd", "mfa"}, SignInName: "cadet", Organization: issuer, Attestation: sessioninfo.AttestedByEvidence,
			}, ReturnURL: "/home", Issuer: issuer},
		},
		{
			name: "the roles claim is the role names when the registration synchronizes roles", claims: base(), roleSync: true,
			want: &signin.Verified{Identity: &sessioninfo.Identity{
				Method: sessioninfo.MethodOIDC, Connection: issuer, Subject: "cadet", Email: "cadet@example.com", EmailVerified: true,
				IDPAMR: []string{"pwd"}, SignInName: "cadet", Organization: issuer,
			}, ReturnURL: "/home", Issuer: issuer, RoleNames: []string{"Cadet"}},
		},
		{
			name:   "no roles asserted is an empty list under role synchronization",
			claims: map[string]any{"iss": issuer, "sub": "cadet", "preferred_username": "cadet"}, roleSync: true,
			want: &signin.Verified{Identity: &sessioninfo.Identity{
				Method: sessioninfo.MethodOIDC, Connection: issuer, Subject: "cadet", SignInName: "cadet", Organization: issuer,
			}, ReturnURL: "/home", Issuer: issuer, RoleNames: []string{}},
		},
		{name: "a token without a subject is refused", claims: map[string]any{"iss": issuer, "email": "pat@example.com"}, wantCode: sessioninfo.RefusedClaimsParse},
		{name: "a token from another issuer is refused", claims: func() map[string]any { c := base(); c["iss"] = "https://other.example.com"; return c }(), wantCode: sessioninfo.RefusedIDTokenVerification},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			authn := &fakeAuthenticator{claims: tt.claims}
			cfg := baseConfig(authn)
			if tt.roleSync {
				cfg.RoleSync = signin.RoleSync(mock_signin.NewMockUserRoleManager(gomock.NewController(t)))
			}
			if tt.config != nil {
				tt.config(cfg)
			}
			m := build(t, cfg)
			if (m.SyncRoles != nil) != tt.roleSync || (m.RecognizesRoles != nil) != tt.roleSync {
				t.Errorf("SyncRoles set %v, RecognizesRoles set %v, want %v", m.SyncRoles != nil, m.RecognizesRoles != nil, tt.roleSync)
			}

			r := httptest.NewRequestWithContext(t.Context(), http.MethodGet, "/api/user/gateway/callback?code=c&state=s", http.NoBody)
			got, err := m.Complete(t.Context(), httptest.NewRecorder(), r)
			if tt.wantCode != "" {
				if code := sessioninfo.LoginRefusalCodeOf(err); code != tt.wantCode {
					t.Fatalf("Method.Complete() refusal = %q (error %v), want %q", code, err, tt.wantCode)
				}

				return
			}
			if err != nil {
				t.Fatalf("Method.Complete() error = %v", err)
			}
			tt.want.Identity.Claims = claimsOf(t, tt.claims)
			if diff := cmp.Diff(tt.want, got); diff != "" {
				t.Errorf("verified mismatch (-want +got):\n%s", diff)
			}
		})
	}
}

// TestScopesOf proves the scope set: openid first, the defaults when none are given, and
// no repeats.
func TestScopesOf(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name   string
		scopes []string
		want   []string
	}{
		{name: "the defaults", want: []string{"openid", "email", "profile"}},
		{name: "the scopes given", scopes: []string{"groups"}, want: []string{"openid", "groups"}},
		{name: "openid and repeats dropped", scopes: []string{"openid", "email", "email", ""}, want: []string{"openid", "email"}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			if diff := cmp.Diff(tt.want, scopesOf(tt.scopes)); diff != "" {
				t.Errorf("scopesOf() mismatch (-want +got):\n%s", diff)
			}
		})
	}
}
