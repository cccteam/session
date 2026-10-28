//go:build !skipAuth

// The tenant policy through the real sign-in flow on both backends: the person's
// memberships from a role store, each tenant's declaration read by the application's
// reader in the sign-in's transaction, and the application's own rule chained after
// the policy.

package e2e

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"slices"
	"sync"
	"sync/atomic"
	"testing"

	"github.com/cccteam/ccc"
	"github.com/cccteam/ccc/accesstypes"
	"github.com/cccteam/session"
	"github.com/cccteam/session/azure"
	"github.com/cccteam/session/google"
	"github.com/cccteam/session/internal/oidctest"
	"github.com/cccteam/session/sessioninfo"
	"github.com/cccteam/session/signin"
	"github.com/go-chi/chi/v5"
	"github.com/go-playground/errors/v5"
)

// The tenants of these scenarios, as the access store names them, and the directories
// they may declare: the Lakeside Entra tenant by its tenant id, the Lakeside Workspace
// by the name the registration gives it.
const (
	tenantLakeside  = "lakeside"
	tenantRiverside = "riverside"
)

var (
	lakesideEntra     = signin.Directory{Method: sessioninfo.MethodAzure, Connection: azureTenant}
	lakesideWorkspace = signin.Directory{Method: sessioninfo.MethodGoogle, Connection: "lakeside"}
	member            = []accesstypes.Role{"Member"}
)

// tenantRoles stands in for the access library's user manager: the memberships each
// user holds, granted per scenario. The tenant policy reads them and never writes.
type tenantRoles struct {
	mu   sync.Mutex
	held map[accesstypes.User]accesstypes.RoleCollection
	// seated is what the directory seat hook granted, by username.
	seated map[string][]signin.DirectorySeat
}

// seat is the directory seat hook: it grants each seat as a membership in its tenant,
// as the application's hook does over its membership store, and records what was
// granted.
func (r *tenantRoles) seat(_ context.Context, _ ccc.UUID, username string, seats []signin.DirectorySeat) error {
	for _, s := range seats {
		r.grant(username, accesstypes.DomainPolicyScope(s.Tenant), s.Role)
	}
	r.mu.Lock()
	defer r.mu.Unlock()

	if r.seated == nil {
		r.seated = make(map[string][]signin.DirectorySeat)
	}
	r.seated[username] = append(r.seated[username], seats...)

	return nil
}

// seatsOf reads the seats the hook granted username, nil for none.
func (r *tenantRoles) seatsOf(username string) []signin.DirectorySeat {
	r.mu.Lock()
	defer r.mu.Unlock()

	return slices.Clone(r.seated[username])
}

// grant gives user the roles in scope.
func (r *tenantRoles) grant(user string, scope accesstypes.PolicyScope, roles ...accesstypes.Role) {
	r.mu.Lock()
	defer r.mu.Unlock()

	if r.held == nil {
		r.held = make(map[accesstypes.User]accesstypes.RoleCollection)
	}
	if r.held[accesstypes.User(user)] == nil {
		r.held[accesstypes.User(user)] = make(accesstypes.RoleCollection)
	}
	r.held[accesstypes.User(user)][scope] = append(r.held[accesstypes.User(user)][scope], roles...)
}

func (r *tenantRoles) UserRoles(_ context.Context, user accesstypes.User, scopes ...accesstypes.PolicyScope) (accesstypes.RoleCollection, error) {
	r.mu.Lock()
	defer r.mu.Unlock()

	if len(scopes) > 0 {
		return nil, errors.Newf("the tenant policy reads every membership the user holds, not %v", scopes)
	}

	return r.held[user], nil
}

func (r *tenantRoles) ResolveRole(context.Context, accesstypes.PolicyScope, string) (accesstypes.Role, bool, error) {
	return "", false, errors.New("the tenant policy never resolves a role")
}

func (r *tenantRoles) AddUserRoles(context.Context, accesstypes.PolicyScope, accesstypes.User, ...accesstypes.Role) error {
	return errors.New("the tenant policy never writes a membership")
}

func (r *tenantRoles) DeleteUserRoles(context.Context, accesstypes.PolicyScope, accesstypes.User, ...accesstypes.Role) error {
	return errors.New("the tenant policy never removes a membership")
}

// tenantApp is an application of the tenanted shape: password sign-in, the Entra method
// serving the Lakeside and Riverside tenants and the Google method serving the Lakeside
// Workspace, under the tenant policy over roles and the backend's declaration rows,
// with the hooks' policy chained after it as the application's own rule.
type tenantApp[Tx any] struct {
	*authApp[Tx]
	entra, google *oidctest.FakeIDP
	roles         *tenantRoles
}

func newTenantApp[Tx any](ctx context.Context, t *testing.T, be backend[Tx], opts ...signin.TenantPolicyOption) *tenantApp[Tx] {
	t.Helper()

	h := &hooks[Tx]{rows: be.rows}
	db, store := be.newStore(ctx, t)
	roles := &tenantRoles{}
	entraIDP := oidctest.NewFakeEntra(t, "entra-client")
	googleIDP := oidctest.NewFakeIDP(t, "google-client")

	auth, err := session.NewAuth[appSessionData, appUserData](withCustomData(t, store, h), cookieKey,
		session.WithIdentityLinked(h.identityLinked), session.WithPendingHook(h.pendingHook))
	if err != nil {
		t.Fatalf("session.NewAuth() error = %v", err)
	}
	auth.SetSignInPolicy(signin.TenantPolicy(roles, be.rows.tenantDeclaration, opts...).Then(h.signInPolicy))
	auth.SetDirectoryAdmission(be.rows.directoryLookup, roles, roles.seat)

	password := session.PasswordSignIn(auth)
	entra := azure.SignIn(auth, "entra", nil, &azure.Config{
		RoleSync: signin.DisableRoleSync(), Authority: entraIDP.Server.URL,
		Tenants: azure.Tenants(azure.NamedTenant(azureTenant, tenantLakeside), azure.Tenant(riversideTenant)), Accounts: signin.MembersOfDirectory,
		ClientID: "entra-client", ClientSecret: "secret", RedirectURL: "https://app.example/entra/callback",
	})
	googleIssuerMu.Lock()
	issuer := google.IssuerURL
	google.IssuerURL = googleIDP.Server.URL
	workspace := google.SignIn(auth, "google", nil, &google.Config{
		RoleSync: google.DisableRoleSync(), Workspaces: google.Workspace("lakeside", hostedDomain), Accounts: signin.MembersOfDirectory,
		ClientID: "google-client", ClientSecret: "secret", RedirectURL: "https://app.example/google/callback",
	})
	google.IssuerURL = issuer
	googleIssuerMu.Unlock()

	r := chi.NewRouter()
	mountAuth(r, auth, func(r chi.Router) {
		r.With(auth.ValidateXSRFToken).Post("/login", password.Login())
		r.Get("/entra/login", entra.Login())
		r.Get("/entra/callback", entra.Callback())
		r.Get("/google/login", workspace.Login())
		r.Get("/google/callback", workspace.Callback())
	})
	server := httptest.NewTLSServer(r)
	t.Cleanup(server.Close)

	return &tenantApp[Tx]{
		authApp: &authApp[Tx]{db: db, rows: be.rows, server: server, api: auth.API(), hooks: h},
		entra:   entraIDP, google: googleIDP, roles: roles,
	}
}

// entraSignIn runs an Entra round trip with claims in b and returns where the callback
// sent the browser.
func (a *tenantApp[Tx]) entraSignIn(ctx context.Context, b *browser, claims map[string]any) *url.URL {
	b.t.Helper()

	return b.oidcSignIn(ctx, a.entra, "/entra", claims)
}

// googleSignIn runs a Google round trip with claims in b and returns where the
// callback sent the browser.
func (a *tenantApp[Tx]) googleSignIn(ctx context.Context, b *browser, claims map[string]any) *url.URL {
	b.t.Helper()

	return b.oidcSignIn(ctx, a.google, "/google", claims)
}

// passwordSignIn signs username in by password in b and returns the status and the
// refusal code the login answered, "" when it signed in.
func (a *tenantApp[Tx]) passwordSignIn(ctx context.Context, b *browser, username, password string) (status int, code string) {
	b.t.Helper()

	b.prime(ctx)
	status, body := b.do(ctx, http.MethodPost, "/login", map[string]string{"username": username, "password": password})
	var answer struct {
		Code string `json:"code"`
	}
	_ = json.Unmarshal(body, &answer)

	return status, answer.Code
}

// assertPasswordSignIn fails unless username's password sign-in answers wantStatus
// and wantCode.
func (a *tenantApp[Tx]) assertPasswordSignIn(ctx context.Context, t *testing.T, username string, wantStatus int, wantCode string) {
	t.Helper()

	b := a.browser(t)
	if status, code := a.passwordSignIn(ctx, b, username, seedPassword); status != wantStatus || code != wantCode {
		t.Errorf("password sign-in of %s = %d %q, want %d %q", username, status, code, wantStatus, wantCode)
	}
}

// TestAuthSeams_TenantPolicy runs the tenant policy scenarios on each backend.
func TestAuthSeams_TenantPolicy(t *testing.T) {
	t.Parallel()

	t.Run(postgresBackend.name, func(t *testing.T) {
		t.Parallel()
		runTenantPolicySeams(t, postgresBackend)
	})
	t.Run(spannerBackend.name, func(t *testing.T) {
		t.Parallel()
		runTenantPolicySeams(t, spannerBackend)
	})
}

func runTenantPolicySeams[Tx any](t *testing.T, be backend[Tx]) {
	tests := []struct {
		name string
		run  func(ctx context.Context, t *testing.T, be backend[Tx])
	}{
		{
			name: "a member of a tenant that declares the Entra directory signs in through it, and by password since the tenant admits passwords; the directory is read from the tenant's row in the sign-in's transaction",
			run:  seamTenantAdmitted[Tx],
		},
		{
			name: "a sign-in through a directory no tenant of the person declares is refused with connection_not_in_tenant, from the Workspace and from the other Entra tenant, and the account the rule made stays",
			run:  seamTenantConnectionNotInTenant[Tx],
		},
		{
			name: "a person who is a member of no tenant is refused with no_tenant",
			run:  seamTenantNoTenant[Tx],
		},
		{
			name: "a person who is a member of no tenant signs in when the policy admits people without a tenant",
			run:  seamTenantAdmitWithoutTenant[Tx],
		},
		{
			name: "a password sign-in by a person whose every tenant is directory only is refused with directory_only; a second tenant that admits passwords admits it, and the directory-only tenant admits its own directory",
			run:  seamTenantDirectoryOnly[Tx],
		},
		{
			name: "a person holding a global role is the application's staff: admitted through a directory no tenant declares",
			run:  seamTenantStaff[Tx],
		},
		{
			name: "the application's own rule is asked after the tenant policy allows, and its answer is the decision; it is not asked after the tenant policy denies",
			run:  seamTenantChainedRule[Tx],
		},
		{
			name: "a stranger from a directory a tenant declares with a default seat is created and seated with it before the policy decides, through either method, and reaches the tenant; a second tenant declaring the directory without a seat gives nothing; a second sign-in seats nothing more",
			run:  seamDirectoryDefaultSeat[Tx],
		},
		{
			name: "a stranger from a directory a tenant declares with no default seat is refused with invitation_only and no account is created, though the registration admits members of the directory; a directory no tenant declares falls to the registration's rule",
			run:  seamDirectoryInvitationOnly[Tx],
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			tt.run(t.Context(), t, be)
		})
	}
}

// seamDirectoryDefaultSeat is the scenario "a stranger from a directory a tenant declares with a default seat is created and seated with it".
func seamDirectoryDefaultSeat[Tx any](ctx context.Context, t *testing.T, be backend[Tx]) {
	a := newTenantApp(ctx, t, be)
	a.db.declareTenant(ctx, t, tenantLakeside, false, lakesideWorkspace, lakesideEntra)
	a.db.seatDirectory(ctx, t, tenantLakeside, lakesideWorkspace, "Member")
	a.db.seatDirectory(ctx, t, tenantLakeside, lakesideEntra, "Member")
	a.db.declareTenant(ctx, t, tenantRiverside, false, lakesideWorkspace)
	want := []signin.DirectorySeat{{Tenant: tenantLakeside, Role: "Member"}}

	// The Workspace stranger: created, seated in lakeside alone (riverside declares
	// the directory without a seat), and admitted by the policy on that membership.
	workspace := a.browser(t)
	assertRedirect(t, a.googleSignIn(ctx, workspace, googleClaims("sub-pat", "pat@lakeside.edu")), "/home", url.Values{})
	signedInAs(ctx, t, workspace, "pat@lakeside.edu")
	if got := a.roles.seatsOf("pat@lakeside.edu"); !slices.Equal(got, want) {
		t.Errorf("seats granted to the Workspace stranger = %v, want %v", got, want)
	}

	// The Entra stranger, the same through the other method.
	entra := a.browser(t)
	assertRedirect(t, a.entraSignIn(ctx, entra, azureClaims(azureTenant, "oid-sam", "sam@lakeside.edu")), "/home", url.Values{})
	signedInAs(ctx, t, entra, "sam@lakeside.edu")
	if got := a.roles.seatsOf("sam@lakeside.edu"); !slices.Equal(got, want) {
		t.Errorf("seats granted to the Entra stranger = %v, want %v", got, want)
	}

	// A second sign-in finds the link and seats nothing more.
	again := a.browser(t)
	assertRedirect(t, a.googleSignIn(ctx, again, googleClaims("sub-pat", "pat@lakeside.edu")), "/home", url.Values{})
	if got := a.roles.seatsOf("pat@lakeside.edu"); !slices.Equal(got, want) {
		t.Errorf("seats granted after a second sign-in = %v, want the first sign-in's alone %v", got, want)
	}
}

// seamDirectoryInvitationOnly is the scenario "a stranger from a directory a tenant declares with no default seat is refused with invitation_only".
func seamDirectoryInvitationOnly[Tx any](ctx context.Context, t *testing.T, be backend[Tx]) {
	a := newTenantApp(ctx, t, be)
	a.db.declareTenant(ctx, t, tenantLakeside, false, lakesideWorkspace)

	// The registration admits members of the directory; the tenant's declaration
	// decides first, and writes nothing.
	stranger := a.browser(t)
	assertRedirect(t, a.googleSignIn(ctx, stranger, googleClaims("sub-pat", "pat@lakeside.edu")), "/login", url.Values{"code": {"invitation_only"}})
	stranger.expect(ctx, http.StatusUnauthorized, http.MethodGet, "/whoami", nil)
	if a.db.hasUser(ctx, t, "pat@lakeside.edu") {
		t.Error("an account was created for the refused stranger, want none: invitation only writes nothing")
	}
	if got := a.roles.seatsOf("pat@lakeside.edu"); got != nil {
		t.Errorf("seats granted to the refused stranger = %v, want none", got)
	}

	// A directory no tenant declares falls to the registration's rule: the stranger
	// from the other Entra tenant is provisioned as a member of the directory, then
	// refused by the policy as a member of no tenant, and the account stays.
	other := a.browser(t)
	assertRedirect(t, a.entraSignIn(ctx, other, azureClaims(riversideTenant, "oid-sam", "sam@riverside.edu")), "/login", url.Values{"code": {"no_tenant"}})
	if !a.db.hasUser(ctx, t, "sam@riverside.edu") {
		t.Error("the member of an undeclared directory was not provisioned, want the registration's rule applied as before")
	}
}

// seamTenantAdmitted is the scenario "a member of a tenant that declares the Entra directory signs in through it".
func seamTenantAdmitted[Tx any](ctx context.Context, t *testing.T, be backend[Tx]) {
	a := newTenantApp(ctx, t, be)
	a.db.declareTenant(ctx, t, tenantLakeside, false, lakesideEntra)
	a.roles.grant("pat@lakeside.edu", accesstypes.DomainPolicyScope(tenantLakeside), member...)
	a.roles.grant("kim@lakeside.edu", accesstypes.DomainPolicyScope(tenantLakeside), member...)
	a.seed(ctx, t, "kim@lakeside.edu")

	b := a.browser(t)
	assertRedirect(t, a.entraSignIn(ctx, b, azureClaims(azureTenant, "oid-pat", "pat@lakeside.edu")), "/home", url.Values{})
	v := signedInAs(ctx, t, b, "pat@lakeside.edu")
	// The fake Entra asserts mfa in every token: the session records the evidence
	// after the sign-in's own event.
	assertEventsSeen(t, v, "azure:"+azureTenant, "attested-by-evidence:"+azureTenant)

	a.assertPasswordSignIn(ctx, t, "kim@lakeside.edu", http.StatusOK, "")
}

// seamTenantConnectionNotInTenant is the scenario "a sign-in through a directory no tenant of the person declares is refused".
func seamTenantConnectionNotInTenant[Tx any](ctx context.Context, t *testing.T, be backend[Tx]) {
	a := newTenantApp(ctx, t, be)
	a.db.declareTenant(ctx, t, tenantLakeside, false, lakesideEntra)
	a.roles.grant("pat@lakeside.edu", accesstypes.DomainPolicyScope(tenantLakeside), member...)
	a.roles.grant("sam@riverside.edu", accesstypes.DomainPolicyScope(tenantLakeside), member...)

	workspace := a.browser(t)
	assertRedirect(t, a.googleSignIn(ctx, workspace, googleClaims("sub-pat", "pat@lakeside.edu")), "/login", url.Values{"code": {"connection_not_in_tenant"}})
	workspace.expect(ctx, http.StatusUnauthorized, http.MethodGet, "/whoami", nil)
	if !a.db.hasUser(ctx, t, "pat@lakeside.edu") {
		t.Error("the account the rule provisioned is gone, want it kept: the policy decides sessions, not accounts")
	}

	other := a.browser(t)
	assertRedirect(t, a.entraSignIn(ctx, other, azureClaims(riversideTenant, "oid-sam", "sam@riverside.edu")), "/login", url.Values{"code": {"connection_not_in_tenant"}})
	other.expect(ctx, http.StatusUnauthorized, http.MethodGet, "/whoami", nil)
}

// seamTenantNoTenant is the scenario "a person who is a member of no tenant is refused with no_tenant".
func seamTenantNoTenant[Tx any](ctx context.Context, t *testing.T, be backend[Tx]) {
	a := newTenantApp(ctx, t, be)

	stranger := a.browser(t)
	assertRedirect(t, a.entraSignIn(ctx, stranger, azureClaims(azureTenant, "oid-new", "new@lakeside.edu")), "/login", url.Values{"code": {"no_tenant"}})
	stranger.expect(ctx, http.StatusUnauthorized, http.MethodGet, "/whoami", nil)
}

// seamTenantAdmitWithoutTenant is the scenario "a person who is a member of no tenant signs in when the policy admits people without a tenant".
func seamTenantAdmitWithoutTenant[Tx any](ctx context.Context, t *testing.T, be backend[Tx]) {
	a := newTenantApp(ctx, t, be, signin.AdmitWithoutTenant())

	stranger := a.browser(t)
	assertRedirect(t, a.entraSignIn(ctx, stranger, azureClaims(azureTenant, "oid-new", "new@lakeside.edu")), "/home", url.Values{})
	signedInAs(ctx, t, stranger, "new@lakeside.edu")
}

// seamTenantDirectoryOnly is the scenario "a password sign-in by a person whose every tenant is directory only is refused".
func seamTenantDirectoryOnly[Tx any](ctx context.Context, t *testing.T, be backend[Tx]) {
	a := newTenantApp(ctx, t, be)
	a.db.declareTenant(ctx, t, tenantLakeside, true, lakesideEntra)
	a.roles.grant("kim@lakeside.edu", accesstypes.DomainPolicyScope(tenantLakeside), member...)
	a.roles.grant("lee@lakeside.edu", accesstypes.DomainPolicyScope(tenantLakeside), member...)
	a.roles.grant("lee@lakeside.edu", accesstypes.DomainPolicyScope(tenantRiverside), member...)
	a.roles.grant("pat@lakeside.edu", accesstypes.DomainPolicyScope(tenantLakeside), member...)
	a.seed(ctx, t, "kim@lakeside.edu")
	a.seed(ctx, t, "lee@lakeside.edu")

	a.assertPasswordSignIn(ctx, t, "kim@lakeside.edu", http.StatusUnauthorized, "directory_only")
	a.assertPasswordSignIn(ctx, t, "lee@lakeside.edu", http.StatusOK, "")

	b := a.browser(t)
	assertRedirect(t, a.entraSignIn(ctx, b, azureClaims(azureTenant, "oid-pat", "pat@lakeside.edu")), "/home", url.Values{})
	signedInAs(ctx, t, b, "pat@lakeside.edu")
}

// seamTenantStaff is the scenario "a person holding a global role is the application's staff".
func seamTenantStaff[Tx any](ctx context.Context, t *testing.T, be backend[Tx]) {
	a := newTenantApp(ctx, t, be)
	a.roles.grant("ops@lakeside.edu", accesstypes.GlobalPolicyScope(), "Administrator")

	b := a.browser(t)
	assertRedirect(t, a.googleSignIn(ctx, b, googleClaims("sub-ops", "ops@lakeside.edu")), "/home", url.Values{})
	v := signedInAs(ctx, t, b, "ops@lakeside.edu")
	assertEventsSeen(t, v, "google:lakeside")
}

// seamTenantChainedRule is the scenario "the application's own rule is asked after the tenant policy allows".
func seamTenantChainedRule[Tx any](ctx context.Context, t *testing.T, be backend[Tx]) {
	a := newTenantApp(ctx, t, be)
	a.db.declareTenant(ctx, t, tenantLakeside, false, lakesideEntra)
	a.roles.grant("pat@lakeside.edu", accesstypes.DomainPolicyScope(tenantLakeside), member...)
	var asked atomic.Int32
	a.hooks.set(func(h *hooks[Tx]) {
		h.policy = func(*sessioninfo.NewSessionRequest) *signin.Decision {
			asked.Add(1)

			return signin.Deny("app_denied")
		}
	})

	b := a.browser(t)
	assertRedirect(t, a.entraSignIn(ctx, b, azureClaims(azureTenant, "oid-pat", "pat@lakeside.edu")), "/login", url.Values{"code": {"app_denied"}})
	b.expect(ctx, http.StatusUnauthorized, http.MethodGet, "/whoami", nil)
	if got := asked.Load(); got != 1 {
		t.Errorf("the application's own rule was asked %d times after the tenant policy allowed, want once", got)
	}

	// A stranger from a directory no tenant declares (the lakeside declaration would
	// refuse them by invitation only before any policy ran) is provisioned by the
	// registration's rule and denied by the tenant policy, which the own rule never
	// sees.
	stranger := a.browser(t)
	assertRedirect(t, a.entraSignIn(ctx, stranger, azureClaims(riversideTenant, "oid-new", "new@riverside.edu")), "/login", url.Values{"code": {"no_tenant"}})
	if got := asked.Load(); got != 1 {
		t.Errorf("the application's own rule was asked %d times in all, want still once: it is not asked after the tenant policy denies", got)
	}
}
