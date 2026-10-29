//go:build !skipAuth

// The sign-in rules through the real sign-in flow on both backends, shape by rule: the
// standard account rules and a custom rule beside them, the organization slots of both
// methods, the policy at every session start and the provider-initiated logout across
// the tenants of one registration.

package e2e

import (
	"context"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/cccteam/ccc"
	"github.com/cccteam/ccc/accesstypes"
	"github.com/cccteam/session"
	"github.com/cccteam/session/azure"
	"github.com/cccteam/session/google"
	"github.com/cccteam/session/internal/oidctest"
	"github.com/cccteam/session/sessioninfo"
	"github.com/cccteam/session/sessionstorage"
	"github.com/cccteam/session/signin"
	"github.com/go-chi/chi/v5"
)

// otherTenant is an Entra tenant no registration in these scenarios lists.
const otherTenant = "33333333-3333-3333-3333-333333333333"

// rulesShape is what one scenario registers: the Entra method under tenants with its
// standard rule, a custom rule beside it when entraRule is set (the hooks' Azure
// resolver) and role synchronization when entraRoles is set; the Google method under
// workspaces with its standard rule and a custom rule when googleRule is set.
type rulesShape struct {
	tenants        azure.TenantSet
	entraAccounts  signin.StandardAccountRule
	entraRule      bool
	entraRoles     bool
	workspaces     google.WorkspaceSet
	googleAccounts signin.StandardAccountRule
	googleRule     bool
}

// oneOrganization is the shape of today's staff application: one tenant and one
// Workspace, each under accounts.
func oneOrganization(accounts signin.StandardAccountRule) *rulesShape {
	return &rulesShape{
		tenants: azure.Tenant(azureTenant), entraAccounts: accounts,
		workspaces: google.Workspace("lakeside", hostedDomain), googleAccounts: accounts,
	}
}

// rulesApp is an application of one shape: its Entra registration at /entra against a
// fake shaped like the Microsoft identity platform, its Google registration at /google
// against a fake Google.
type rulesApp[Tx any] struct {
	*authApp[Tx]
	entra, google *oidctest.FakeIDP
}

// rolesNeverAsked is the role store of a registration that synchronizes roles in a
// scenario where the sign-in must be refused before any role is read or written.
type rolesNeverAsked struct {
	t *testing.T
}

func (r rolesNeverAsked) UserRoles(context.Context, accesstypes.User, ...accesstypes.PolicyScope) (accesstypes.RoleCollection, error) {
	r.t.Error("the role store was asked for a user's roles, want the sign-in refused first")

	return accesstypes.RoleCollection{}, nil
}

func (r rolesNeverAsked) ResolveRole(context.Context, accesstypes.PolicyScope, string) (accesstypes.Role, bool, error) {
	r.t.Error("the role store was asked to resolve a role, want the sign-in refused first")

	return "", false, nil
}

func (r rolesNeverAsked) AddUserRoles(context.Context, accesstypes.PolicyScope, accesstypes.User, ...accesstypes.Role) error {
	r.t.Error("the role store was asked to add roles, want the sign-in refused first")

	return nil
}

func (r rolesNeverAsked) DeleteUserRoles(context.Context, accesstypes.PolicyScope, accesstypes.User, ...accesstypes.Role) error {
	r.t.Error("the role store was asked to remove roles, want the sign-in refused first")

	return nil
}

func newRulesApp[Tx any](ctx context.Context, t *testing.T, be backend[Tx], shape *rulesShape) *rulesApp[Tx] {
	t.Helper()

	h := &hooks[Tx]{rows: be.rows}
	db, store := be.newStore(ctx, t)
	entraIDP := oidctest.NewFakeEntra(t, "entra-client")
	googleIDP := oidctest.NewFakeIDP(t, "google-client")

	auth, err := session.NewAuth[appSessionData, appUserData](withCustomData(t, store, h), cookieKey,
		session.WithIdentityLinked(h.identityLinked), session.WithPendingHook(h.pendingHook))
	if err != nil {
		t.Fatalf("session.NewAuth() error = %v", err)
	}
	auth.SetSignInPolicy(h.signInPolicy)

	var entraRule azure.AccountRule[Tx]
	if shape.entraRule {
		entraRule = h.azureResolver
	}
	roleSync := signin.DisableRoleSync()
	if shape.entraRoles {
		roleSync = signin.RoleSync(rolesNeverAsked{t: t})
	}
	entra := azure.SignIn(auth, "entra", entraRule, &azure.Config{
		RoleSync: roleSync, Authority: entraIDP.Server.URL, Tenants: shape.tenants, Accounts: shape.entraAccounts,
		ClientID: "entra-client", ClientSecret: "secret", RedirectURL: "https://app.example/entra/callback",
	})
	var googleRule google.AccountRule[Tx]
	if shape.googleRule {
		googleRule = h.googleResolver
	}
	// A registration that synchronizes roles stands alone on its Auth, so the Google
	// method is registered beside the Entra one only where the Entra one leaves the
	// roles to the application.
	var workspace *google.Method
	if !shape.entraRoles {
		googleIssuerMu.Lock()
		issuer := google.IssuerURL
		google.IssuerURL = googleIDP.Server.URL
		workspace = google.SignIn(auth, "google", googleRule, &google.Config{
			RoleSync: google.DisableRoleSync(), Workspaces: shape.workspaces, Accounts: shape.googleAccounts,
			ClientID: "google-client", ClientSecret: "secret", RedirectURL: "https://app.example/google/callback",
		})
		google.IssuerURL = issuer
		googleIssuerMu.Unlock()
	}

	r := chi.NewRouter()
	mountAuth(r, auth, func(r chi.Router) {
		r.Get("/entra/login", entra.Login())
		r.Get("/entra/callback", entra.Callback())
		r.Get("/entra/logout", entra.FrontChannelLogout())
		if workspace != nil {
			r.Get("/google/login", workspace.Login())
			r.Get("/google/callback", workspace.Callback())
		}
	})
	server := httptest.NewTLSServer(r)
	t.Cleanup(server.Close)

	return &rulesApp[Tx]{
		authApp: &authApp[Tx]{db: db, rows: be.rows, server: server, api: auth.API(), hooks: h},
		entra:   entraIDP, google: googleIDP,
	}
}

// entraSignIn runs an Entra round trip with claims in b and returns where the callback
// sent the browser.
func (a *rulesApp[Tx]) entraSignIn(ctx context.Context, b *browser, claims map[string]any) *url.URL {
	b.t.Helper()

	return b.oidcSignIn(ctx, a.entra, "/entra", claims)
}

// googleSignIn runs a Google round trip with claims in b and returns where the
// callback sent the browser.
func (a *rulesApp[Tx]) googleSignIn(ctx context.Context, b *browser, claims map[string]any) *url.URL {
	b.t.Helper()

	return b.oidcSignIn(ctx, a.google, "/google", claims)
}

// createUser creates a user without a password: pre-created for an external identity.
func (a *authApp[Tx]) createUser(ctx context.Context, t *testing.T, username string) ccc.UUID {
	t.Helper()

	id, err := a.api.CreateSessionUser(ctx, &session.CreateUserRequest{Username: username})
	if err != nil {
		t.Fatalf("CreateSessionUser(%q) error = %v", username, err)
	}

	return id
}

// links lists the identity links of the user whose id the session view carries.
func (a *authApp[Tx]) links(ctx context.Context, t *testing.T, userID string) []*sessionstorage.SessionIdentity {
	t.Helper()

	links, err := a.api.Identities(ctx, ccc.Must(ccc.UUIDFromString(userID)))
	if err != nil {
		t.Fatalf("Identities(%s) error = %v", userID, err)
	}

	return links
}

// assertNoRow fails unless b has no session and no user exists under username: a
// refusal before any row was written.
func (a *authApp[Tx]) assertNoRow(ctx context.Context, t *testing.T, b *browser, username string) {
	t.Helper()

	b.expect(ctx, http.StatusUnauthorized, http.MethodGet, "/whoami", nil)
	if a.db.hasUser(ctx, t, username) {
		t.Errorf("a user exists under %q, want none written", username)
	}
}

// signedInAs fails unless b is signed in under username, and returns the session view.
func signedInAs(ctx context.Context, t *testing.T, b *browser, username string) *sessionView {
	t.Helper()

	v := b.view(ctx)
	if v.Username != username {
		t.Errorf("session username = %q, want %q", v.Username, username)
	}

	return v
}

// assertOneLink fails unless links is exactly one link, of connection with tenant as
// its tenant key.
func assertOneLink(t *testing.T, links []*sessionstorage.SessionIdentity, connection, tenant string) {
	t.Helper()

	got := make([]string, 0, len(links))
	for _, l := range links {
		key := "<nil>"
		if l.Tenant != nil {
			key = *l.Tenant
		}
		got = append(got, string(l.Method)+":"+l.Connection+":"+l.Subject+"@"+key)
	}
	if len(links) != 1 || links[0].Connection != connection || links[0].Tenant == nil || *links[0].Tenant != tenant {
		t.Errorf("identity links = %v, want one of connection %q with tenant key %q", got, connection, tenant)
	}
}

// pendingConfirmation fails unless the sign-in that sent the browser to redirect waits
// for a password confirmation, then confirms it with password and returns the view.
func confirmWithPassword(ctx context.Context, t *testing.T, b *browser, redirect *url.URL, password string) *sessionView {
	t.Helper()

	assertRedirect(t, redirect, "/login", url.Values{"pending": {"confirmation"}, "returnUrl": {"/home"}})
	b.expect(ctx, http.StatusUnauthorized, http.MethodGet, "/whoami", nil)
	b.expect(ctx, http.StatusOK, http.MethodPost, "/pending/confirm", map[string]string{"password": password})

	return b.view(ctx)
}

// TestAuthSeams_SignInRules runs the sign-in rule scenarios on each backend.
func TestAuthSeams_SignInRules(t *testing.T) {
	t.Parallel()

	t.Run(postgresBackend.name, func(t *testing.T) {
		t.Parallel()
		runSignInRuleSeams(t, postgresBackend)
	})
	t.Run(spannerBackend.name, func(t *testing.T) {
		t.Parallel()
		runSignInRuleSeams(t, spannerBackend)
	})
}

func runSignInRuleSeams[Tx any](t *testing.T, be backend[Tx]) {
	tests := []struct {
		name string
		run  func(ctx context.Context, t *testing.T, be backend[Tx])
	}{
		{
			name: "members of the directory: a stranger is provisioned under the sign-in name with the tenant id as the link's tenant key, signs in through the link afterwards, and keeps the username after the directory renames the person",
			run:  seamRulesMembersProvision[Tx],
		},
		{
			name: "members of the directory: a pre-created user with a password confirms with it before the link is made, matched without regard to case and keeping its spelling, and a pre-created user without a password or an identity is linked outright",
			run:  seamRulesMembersPreCreated[Tx],
		},
		{
			name: "members of the directory: a token asserting no application role is refused when the registration synchronizes roles, before any row is written or any role is read",
			run:  seamRulesMembersNoRoles[Tx],
		},
		{
			name: "invited users only: a pre-created user is linked, one with a password confirms, and a stranger is refused with not_invited and a guest with guest_account, both without a row",
			run:  seamRulesInvitedUsersOnly[Tx],
		},
		{
			name: "any tenant and any Google account with open sign-up: a work or school account of a tenant the application never heard of and a Google account outside any Workspace get accounts keyed by where they came from, a personal Microsoft account is refused, and an unverified Google email is refused, each before any user is resolved",
			run:  seamRulesOpenSignUp[Tx],
		},
		{
			name: "personal accounts beside one tenant, invited users only: a pre-created person signs in with a Microsoft personal account under the consumer tenant, and a work account of an unlisted tenant is refused without a row",
			run:  seamRulesPersonalAccounts[Tx],
		},
		{
			name: "listed tenants: each listed tenant is admitted and the link carries the name the registration gives it, a person from the other tenant is a new identity, the same sign-in name across tenants is refused by the cross-connection guard, and an unlisted tenant is refused without a row",
			run:  seamRulesListedTenants[Tx],
		},
		{
			name: "a custom rule runs first: it refuses with its own code before any row, hands the rest to the standard rule with a tenant key of its own, and never runs again once the identity is linked",
			run:  seamRulesCustomRuleFirst[Tx],
		},
		{
			name: "the policy decides every session start: a provisioning sign-in it denies starts no session (the account the rule made stays, for the policy to decide again), the MFA completion is decided again, and a session the application starts through the API is decided too",
			run:  seamRulesPolicyEveryStart[Tx],
		},
		{
			name: "an Entra front-channel logout on a registration serving two tenants ends the sessions under the issuer it names and no other, refuses an issuer outside the slot, and one naming no issuer, as Entra sends it, ends the sessions under whichever of the slot's issuers carry the sid",
			run:  seamRulesLogoutAcrossTenants[Tx],
		},
		{
			name: "listed Workspaces: the hd claim selects the entry and the link carries its name as connection and tenant key, a person from the other Workspace is a new identity, and a Workspace outside the list is refused without a row",
			run:  seamRulesListedWorkspaces[Tx],
		},
		{
			name: "a token whose amr names mfa attests by evidence, so a policy requiring the email code proceeds with an attested-by-evidence event; a token without it, and a Google sign-in, are held for the code",
			run:  seamRulesAttestedByEvidence[Tx],
		},
		{
			name: "a Workspace and a tenant declared Attesting() attest by declaration, so the policy proceeds with an attested-by-declaration event under the connection; evidence still wins where the token carries it",
			run:  seamRulesAttestedByDeclaration[Tx],
		},
		{
			name: "any Workspace, invited users only: a pre-created person signs in from a Workspace the application never named under its domain as connection, a stranger from another Workspace is refused with not_invited, and an account outside any Workspace is refused",
			run:  seamRulesAnyWorkspace[Tx],
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			tt.run(t.Context(), t, be)
		})
	}
}

// seamRulesMembersProvision is the scenario "members of the directory".
func seamRulesMembersProvision[Tx any](ctx context.Context, t *testing.T, be backend[Tx]) {
	a := newRulesApp(ctx, t, be, oneOrganization(signin.MembersOfDirectory))

	b := a.browser(t)
	assertRedirect(t, a.entraSignIn(ctx, b, azureClaims(azureTenant, "oid-pat", "p.lee@lakeside.edu")), "/home", url.Values{})
	v := signedInAs(ctx, t, b, "p.lee@lakeside.edu")
	// The fake Entra asserts mfa in every token: the session records the evidence
	// after the sign-in's own event.
	assertEventsSeen(t, v, "azure:"+azureTenant, "attested-by-evidence:"+azureTenant)
	assertOneLink(t, a.links(ctx, t, v.UserID), azureTenant, azureTenant)

	// The identity is linked: the next sign-in goes through the link, and the
	// directory's new spelling of the name changes nothing.
	again := a.browser(t)
	assertRedirect(t, a.entraSignIn(ctx, again, azureClaims(azureTenant, "oid-pat", "pat.lee@lakeside.edu")), "/home", url.Values{})
	if got := again.view(ctx); got.UserID != v.UserID || got.Username != "p.lee@lakeside.edu" {
		t.Errorf("second sign-in = user %s %q, want %s %q: the link decides, and the username is never renamed", got.UserID, got.Username, v.UserID, "p.lee@lakeside.edu")
	}
	if got := a.db.username(ctx, t, ccc.Must(ccc.UUIDFromString(v.UserID))); got != "p.lee@lakeside.edu" {
		t.Errorf("stored username after the rename = %q, want %q", got, "p.lee@lakeside.edu")
	}
	if links := a.links(ctx, t, v.UserID); len(links) != 1 {
		t.Errorf("identity links after the second sign-in = %d, want the one", len(links))
	}
}

// seamRulesMembersPreCreated is the scenario "members of the directory".
func seamRulesMembersPreCreated[Tx any](ctx context.Context, t *testing.T, be backend[Tx]) {
	a := newRulesApp(ctx, t, be, oneOrganization(signin.MembersOfDirectory))
	pat := a.seed(ctx, t, "pat@lakeside.edu")
	kim := a.createUser(ctx, t, "kim@lakeside.edu")

	b := a.browser(t)
	b.prime(ctx)
	redirect := a.entraSignIn(ctx, b, azureClaims(azureTenant, "oid-pat", "Pat@Lakeside.edu"))
	if links := a.links(ctx, t, pat.String()); len(links) != 0 {
		t.Errorf("identity links before the confirmation = %d, want none", len(links))
	}
	v := confirmWithPassword(ctx, t, b, redirect, seedPassword)
	if v.UserID != pat.String() || v.Username != "pat@lakeside.edu" {
		t.Errorf("confirmed session = user %s %q, want %s %q", v.UserID, v.Username, pat, "pat@lakeside.edu")
	}
	assertEventsSeen(t, v, "azure:"+azureTenant, "attested-by-evidence:"+azureTenant, "link-confirmation")
	assertOneLink(t, a.links(ctx, t, pat.String()), azureTenant, azureTenant)

	k := a.browser(t)
	assertRedirect(t, a.entraSignIn(ctx, k, azureClaims(azureTenant, "oid-kim", "kim@lakeside.edu")), "/home", url.Values{})
	if kv := signedInAs(ctx, t, k, "kim@lakeside.edu"); kv.UserID != kim.String() {
		t.Errorf("session user = %s, want the pre-created %s", kv.UserID, kim)
	}
	assertOneLink(t, a.links(ctx, t, kim.String()), azureTenant, azureTenant)
}

// seamRulesMembersNoRoles is the scenario "members of the directory".
func seamRulesMembersNoRoles[Tx any](ctx context.Context, t *testing.T, be backend[Tx]) {
	shape := oneOrganization(signin.MembersOfDirectory)
	shape.entraRoles = true
	a := newRulesApp(ctx, t, be, shape)

	b := a.browser(t)
	assertRedirect(t, a.entraSignIn(ctx, b, azureClaims(azureTenant, "oid-x", "x@lakeside.edu")), "/login", url.Values{"code": {"no_roles"}})
	a.assertNoRow(ctx, t, b, "x@lakeside.edu")
}

// seamRulesInvitedUsersOnly is the scenario "invited users only".
func seamRulesInvitedUsersOnly[Tx any](ctx context.Context, t *testing.T, be backend[Tx]) {
	a := newRulesApp(ctx, t, be, oneOrganization(signin.InvitedUsersOnly))
	kim := a.createUser(ctx, t, "kim@lakeside.edu")
	pat := a.seed(ctx, t, "pat@lakeside.edu")

	k := a.browser(t)
	assertRedirect(t, a.entraSignIn(ctx, k, azureClaims(azureTenant, "oid-kim", "kim@lakeside.edu")), "/home", url.Values{})
	if kv := signedInAs(ctx, t, k, "kim@lakeside.edu"); kv.UserID != kim.String() {
		t.Errorf("session user = %s, want the pre-created %s", kv.UserID, kim)
	}

	p := a.browser(t)
	p.prime(ctx)
	if pv := confirmWithPassword(ctx, t, p, a.entraSignIn(ctx, p, azureClaims(azureTenant, "oid-pat", "pat@lakeside.edu")), seedPassword); pv.UserID != pat.String() {
		t.Errorf("confirmed session user = %s, want %s", pv.UserID, pat)
	}

	s := a.browser(t)
	assertRedirect(t, a.entraSignIn(ctx, s, azureClaims(azureTenant, "oid-stranger", "stranger@lakeside.edu")), "/login", url.Values{"code": {"not_invited"}})
	a.assertNoRow(ctx, t, s, "stranger@lakeside.edu")

	g := a.browser(t)
	guest := azureClaims(azureTenant, "oid-guest", "visitor_gmail.com#EXT#@lakeside.onmicrosoft.com")
	assertRedirect(t, a.entraSignIn(ctx, g, guest), "/login", url.Values{"code": {"guest_account"}})
	a.assertNoRow(ctx, t, g, "visitor_gmail.com#EXT#@lakeside.onmicrosoft.com")
}

// seamRulesOpenSignUp is the scenario "any tenant and any Google account with open sign-up".
func seamRulesOpenSignUp[Tx any](ctx context.Context, t *testing.T, be backend[Tx]) {
	a := newRulesApp(ctx, t, be, &rulesShape{
		tenants: azure.AnyTenant(), entraAccounts: signin.OpenSignUp,
		workspaces: google.AnyGoogleAccount(), googleAccounts: signin.OpenSignUp,
	})

	b := a.browser(t)
	assertRedirect(t, a.entraSignIn(ctx, b, azureClaims(otherTenant, "oid-z", "someone@contoso.example")), "/home", url.Values{})
	v := signedInAs(ctx, t, b, "someone@contoso.example")
	assertOneLink(t, a.links(ctx, t, v.UserID), otherTenant, otherTenant)

	personal := a.browser(t)
	assertRedirect(t, a.entraSignIn(ctx, personal, azureClaims(azure.ConsumerTenantID, "oid-p", "pat@outlook.example")), "/login", url.Values{"code": {"personal_account"}})
	a.assertNoRow(ctx, t, personal, "pat@outlook.example")

	g := a.browser(t)
	assertRedirect(t, a.googleSignIn(ctx, g, map[string]any{"sub": "g-sub-pat", "email": "pat@gmail.example", "email_verified": true}), "/home", url.Values{})
	gv := signedInAs(ctx, t, g, "pat@gmail.example")
	assertOneLink(t, a.links(ctx, t, gv.UserID), google.AnyAccountConnection, google.AnyAccountConnection)

	u := a.browser(t)
	assertRedirect(t, a.googleSignIn(ctx, u, map[string]any{"sub": "g-sub-u", "email": "u@gmail.example", "email_verified": false}), "/login", url.Values{"code": {"email_not_verified"}})
	a.assertNoRow(ctx, t, u, "u@gmail.example")
}

// seamRulesPersonalAccounts is the scenario "personal accounts beside one tenant, invited users only".
func seamRulesPersonalAccounts[Tx any](ctx context.Context, t *testing.T, be backend[Tx]) {
	a := newRulesApp(ctx, t, be, &rulesShape{
		tenants: azure.Tenants(azure.Tenant(azureTenant), azure.PersonalAccounts()), entraAccounts: signin.InvitedUsersOnly,
		workspaces: google.Workspace("lakeside", hostedDomain), googleAccounts: signin.InvitedUsersOnly,
	})
	pat := a.createUser(ctx, t, "pat@outlook.example")

	b := a.browser(t)
	assertRedirect(t, a.entraSignIn(ctx, b, azureClaims(azure.ConsumerTenantID, "oid-p", "pat@outlook.example")), "/home", url.Values{})
	if v := signedInAs(ctx, t, b, "pat@outlook.example"); v.UserID != pat.String() {
		t.Errorf("session user = %s, want the pre-created %s", v.UserID, pat)
	}
	assertOneLink(t, a.links(ctx, t, pat.String()), azure.ConsumerTenantID, azure.ConsumerTenantID)

	o := a.browser(t)
	assertRedirect(t, a.entraSignIn(ctx, o, azureClaims(otherTenant, "oid-o", "o@other.example")), "/login", url.Values{"code": {"unlisted_tenant"}})
	a.assertNoRow(ctx, t, o, "o@other.example")
}

// seamRulesListedTenants is the scenario "listed tenants".
func seamRulesListedTenants[Tx any](ctx context.Context, t *testing.T, be backend[Tx]) {
	a := newRulesApp(ctx, t, be, &rulesShape{
		tenants: azure.Tenants(azure.NamedTenant(azureTenant, "lakeside"), azure.Tenant(riversideTenant)), entraAccounts: signin.MembersOfDirectory,
		workspaces: google.Workspace("lakeside", hostedDomain), googleAccounts: signin.MembersOfDirectory,
	})

	lake := a.browser(t)
	assertRedirect(t, a.entraSignIn(ctx, lake, azureClaims(azureTenant, "oid-pat", "p.lee@lakeside.edu")), "/home", url.Values{})
	lv := signedInAs(ctx, t, lake, "p.lee@lakeside.edu")
	assertOneLink(t, a.links(ctx, t, lv.UserID), azureTenant, "lakeside")

	river := a.browser(t)
	assertRedirect(t, a.entraSignIn(ctx, river, azureClaims(riversideTenant, "oid-river", "river@riverside.edu")), "/home", url.Values{})
	rv := signedInAs(ctx, t, river, "river@riverside.edu")
	if rv.UserID == lv.UserID {
		t.Error("the riverside person signed in as the lakeside user, want a new identity")
	}
	assertOneLink(t, a.links(ctx, t, rv.UserID), riversideTenant, riversideTenant)

	// The same object id and sign-in name in the other tenant is another identity:
	// it would link the password-less lakeside user across connections, which
	// the guard refuses.
	same := a.browser(t)
	assertRedirect(t, a.entraSignIn(ctx, same, azureClaims(riversideTenant, "oid-pat", "p.lee@lakeside.edu")), "/login", url.Values{"code": {"identity_rejected"}})
	same.expect(ctx, http.StatusUnauthorized, http.MethodGet, "/whoami", nil)
	if links := a.links(ctx, t, lv.UserID); len(links) != 1 {
		t.Errorf("lakeside user's links after the refused cross-tenant sign-in = %d, want the one", len(links))
	}

	o := a.browser(t)
	assertRedirect(t, a.entraSignIn(ctx, o, azureClaims(otherTenant, "oid-o", "o@other.example")), "/login", url.Values{"code": {"unlisted_tenant"}})
	a.assertNoRow(ctx, t, o, "o@other.example")
}

// seamRulesCustomRuleFirst is the scenario "a custom rule runs first".
func seamRulesCustomRuleFirst[Tx any](ctx context.Context, t *testing.T, be backend[Tx]) {
	shape := oneOrganization(signin.MembersOfDirectory)
	shape.entraRule = true
	a := newRulesApp(ctx, t, be, shape)
	a.hooks.set(func(h *hooks[Tx]) {
		h.resolveAzure = func(identity *azure.Identity) *signin.Resolution {
			if strings.HasSuffix(identity.PreferredUsername, "@blocked.example") {
				return signin.Reject("blocked")
			}

			return signin.Standard(signin.Tenant("partner-" + identity.Organization))
		}
	})

	blocked := a.browser(t)
	assertRedirect(t, a.entraSignIn(ctx, blocked, azureClaims(azureTenant, "oid-b", "b@blocked.example")), "/login", url.Values{"code": {"blocked"}})
	a.assertNoRow(ctx, t, blocked, "b@blocked.example")

	b := a.browser(t)
	assertRedirect(t, a.entraSignIn(ctx, b, azureClaims(azureTenant, "oid-pat", "p.lee@lakeside.edu")), "/home", url.Values{})
	v := signedInAs(ctx, t, b, "p.lee@lakeside.edu")
	assertOneLink(t, a.links(ctx, t, v.UserID), azureTenant, "partner-"+azureTenant)
	if resolved, _ := a.hooks.counts(); resolved != 2 {
		t.Errorf("the custom rule ran %d times, want 2: once per first sign-in", resolved)
	}

	again := a.browser(t)
	assertRedirect(t, a.entraSignIn(ctx, again, azureClaims(azureTenant, "oid-pat", "p.lee@lakeside.edu")), "/home", url.Values{})
	if resolved, _ := a.hooks.counts(); resolved != 2 {
		t.Errorf("the custom rule ran %d times after a sign-in through the link, want still 2", resolved)
	}
}

// seamRulesPolicyEveryStart is the scenario "the policy decides every session start".
func seamRulesPolicyEveryStart[Tx any](ctx context.Context, t *testing.T, be backend[Tx]) {
	a := newRulesApp(ctx, t, be, oneOrganization(signin.MembersOfDirectory))
	a.hooks.set(func(h *hooks[Tx]) {
		h.policy = func(req *sessioninfo.NewSessionRequest) *signin.Decision {
			switch {
			case req.User.Provisioned() && strings.HasPrefix(req.Username, "denied@"):
				return signin.Deny("sso_required")
			case req.Username == "mfa@lakeside.edu" && req.Reason == sessioninfo.ReasonLogin:
				return signin.RequireMFA()
			case req.Username == "mfa@lakeside.edu":
				return signin.Deny("step_denied")
			case req.Username == "kiosk@lakeside.edu":
				return signin.Deny("api_denied")
			}

			return signin.Allow()
		}
	})

	// The account rule's transaction commits before the policy's: the person's
	// account and link stay, and the policy decides their next sign-in again.
	denied := a.browser(t)
	assertRedirect(t, a.entraSignIn(ctx, denied, azureClaims(azureTenant, "oid-d", "denied@lakeside.edu")), "/login", url.Values{"code": {"sso_required"}})
	denied.expect(ctx, http.StatusUnauthorized, http.MethodGet, "/whoami", nil)
	if !a.db.hasUser(ctx, t, "denied@lakeside.edu") {
		t.Error("the account the rule provisioned is gone, want it kept: the policy decides sessions, not accounts")
	}

	// A token asserting the password alone: nothing attests, so the policy's
	// RequireMFA holds the sign-in (one asserting mfa would satisfy it).
	mfa := a.browser(t)
	mfa.prime(ctx)
	assertRedirect(t, a.entraSignIn(ctx, mfa, passwordOnlyClaims(azureTenant, "oid-m", "mfa@lakeside.edu")), "/login", url.Values{"pending": {"mfa"}, "returnUrl": {"/home"}})
	if status, body := mfa.do(ctx, http.MethodPost, "/mfa", nil); status != http.StatusUnauthorized || !strings.Contains(string(body), "sign-in denied") {
		t.Errorf("MFA completion the policy denies = %d %s, want 401 with the policy's refusal", status, body)
	}
	mfa.expect(ctx, http.StatusUnauthorized, http.MethodGet, "/whoami", nil)

	kiosk := a.createUser(ctx, t, "kiosk@lakeside.edu")
	if _, err := a.api.StartAuthenticatedSession(ctx, httptest.NewRecorder(), kiosk, []sessioninfo.AuthEvent{{Method: "kiosk"}}); sessioninfo.LoginRefusalCodeOf(err) != "api_denied" {
		t.Errorf("StartAuthenticatedSession() error = %v, want the policy's refusal api_denied", err)
	}
}

// requireEmailCodeTx is the policy of an application whose every session carries a
// second factor, for the rules app: the library's email code, which an attestation
// stands in for.
func requireEmailCodeTx(*sessioninfo.NewSessionRequest) *signin.Decision {
	return signin.RequireMFA(sessioninfo.MethodEmailCode)
}

// passwordOnlyClaims are azureClaims whose amr names the password alone: Entra ran no
// second factor.
func passwordOnlyClaims(tid, oid, username string) map[string]any {
	claims := azureClaims(tid, oid, username)
	claims["amr"] = []string{"pwd"}

	return claims
}

// seamRulesAttestedByEvidence is the scenario "a token whose amr names mfa attests by evidence".
func seamRulesAttestedByEvidence[Tx any](ctx context.Context, t *testing.T, be backend[Tx]) {
	a := newRulesApp(ctx, t, be, oneOrganization(signin.MembersOfDirectory))
	a.hooks.set(func(h *hooks[Tx]) { h.policy = requireEmailCodeTx })

	// Entra asserts mfa: the sign-in is never held, and the session records the
	// evidence after the sign-in's own event, under the same connection.
	attested := a.browser(t)
	attested.prime(ctx)
	assertRedirect(t, a.entraSignIn(ctx, attested, azureClaims(azureTenant, "oid-a", "ann@lakeside.edu")), "/home", url.Values{})
	assertEventsSeen(t, signedInAs(ctx, t, attested, "ann@lakeside.edu"), "azure:"+azureTenant, "attested-by-evidence:"+azureTenant)

	// Entra asserts the password alone: nothing vouches, the sign-in waits for the
	// code, and the status names the factor.
	held := a.browser(t)
	held.prime(ctx)
	assertRedirect(t, a.entraSignIn(ctx, held, passwordOnlyClaims(azureTenant, "oid-p", "pat@lakeside.edu")), "/login", url.Values{"pending": {"mfa"}, "returnUrl": {"/home"}})
	held.expect(ctx, http.StatusUnauthorized, http.MethodGet, "/whoami", nil)
	if body := held.expect(ctx, http.StatusOK, http.MethodGet, "/pending", nil); !strings.Contains(string(body), `"factors":["email-code"]`) {
		t.Errorf("pending status = %s, want the email code as the factor", body)
	}

	// Google puts no evidence in its token, and the Workspace is not declared: held.
	undeclared := a.browser(t)
	undeclared.prime(ctx)
	assertRedirect(t, a.googleSignIn(ctx, undeclared, googleClaims("g-sub-sam", "sam@lakeside.edu")), "/login", url.Values{"pending": {"mfa"}, "returnUrl": {"/home"}})
	undeclared.expect(ctx, http.StatusUnauthorized, http.MethodGet, "/whoami", nil)
}

// seamRulesAttestedByDeclaration is the scenario "a Workspace and a tenant declared Attesting() attest by declaration".
func seamRulesAttestedByDeclaration[Tx any](ctx context.Context, t *testing.T, be backend[Tx]) {
	a := newRulesApp(ctx, t, be, &rulesShape{
		tenants: azure.Tenant(azureTenant).Attesting(), entraAccounts: signin.MembersOfDirectory,
		workspaces: google.Workspace("lakeside", hostedDomain).Attesting(), googleAccounts: signin.MembersOfDirectory,
	})
	a.hooks.set(func(h *hooks[Tx]) { h.policy = requireEmailCodeTx })

	// The Workspace the application administers vouches for its people.
	workspace := a.browser(t)
	workspace.prime(ctx)
	assertRedirect(t, a.googleSignIn(ctx, workspace, googleClaims("g-sub-sam", "sam@lakeside.edu")), "/home", url.Values{})
	assertEventsSeen(t, signedInAs(ctx, t, workspace, "sam@lakeside.edu"), "google:lakeside", "attested-by-declaration:lakeside")

	// So does the tenant, where the token carries no evidence.
	declared := a.browser(t)
	declared.prime(ctx)
	assertRedirect(t, a.entraSignIn(ctx, declared, passwordOnlyClaims(azureTenant, "oid-p", "pat@lakeside.edu")), "/home", url.Values{})
	assertEventsSeen(t, signedInAs(ctx, t, declared, "pat@lakeside.edu"), "azure:"+azureTenant, "attested-by-declaration:"+azureTenant)

	// Evidence in the token is recorded as such, declaration or not.
	evidence := a.browser(t)
	evidence.prime(ctx)
	assertRedirect(t, a.entraSignIn(ctx, evidence, azureClaims(azureTenant, "oid-a", "ann@lakeside.edu")), "/home", url.Values{})
	assertEventsSeen(t, signedInAs(ctx, t, evidence, "ann@lakeside.edu"), "azure:"+azureTenant, "attested-by-evidence:"+azureTenant)

	// The declaration reaches the sign-in's events on the second sign-in too, through
	// the link, and a session the SignedInHook is told of carries them.
	again := a.browser(t)
	again.prime(ctx)
	assertRedirect(t, a.googleSignIn(ctx, again, googleClaims("g-sub-sam", "sam@lakeside.edu")), "/home", url.Values{})
	assertEventsSeen(t, again.view(ctx), "google:lakeside", "attested-by-declaration:lakeside")
}

// seamRulesLogoutAcrossTenants is the scenario "an Entra front-channel logout on a registration serving two tenants ends the sessions under the issuer it names and no other, refuses an issuer outside the slot, and one naming no issuer, as Entra sends it, ends the sessions under whichever of the slot's issuers carry the sid".
func seamRulesLogoutAcrossTenants[Tx any](ctx context.Context, t *testing.T, be backend[Tx]) {
	a := newRulesApp(ctx, t, be, &rulesShape{
		tenants: azure.Tenants(azure.Tenant(azureTenant), azure.Tenant(riversideTenant)), entraAccounts: signin.MembersOfDirectory,
		workspaces: google.Workspace("lakeside", hostedDomain), googleAccounts: signin.MembersOfDirectory,
	})

	lake := a.browser(t)
	assertRedirect(t, a.entraSignIn(ctx, lake, withSID(azureClaims(azureTenant, "oid-a", "a@lakeside.edu"), "sid-shared")), "/home", url.Values{})
	river := a.browser(t)
	assertRedirect(t, a.entraSignIn(ctx, river, withSID(azureClaims(riversideTenant, "oid-b", "b@riverside.edu"), "sid-shared")), "/home", url.Values{})
	lake.view(ctx)
	river.view(ctx)

	provider := a.browser(t)
	provider.expect(ctx, http.StatusBadRequest, http.MethodGet, "/entra/logout?sid=sid-shared&iss="+url.QueryEscape(a.entra.TenantIssuer(otherTenant)), nil)
	lake.view(ctx)
	river.view(ctx)

	provider.expect(ctx, http.StatusOK, http.MethodGet, "/entra/logout?sid=sid-shared&iss="+url.QueryEscape(a.entra.TenantIssuer(azureTenant)), nil)
	lake.expect(ctx, http.StatusUnauthorized, http.MethodGet, "/whoami", nil)
	if v := river.view(ctx); v.Username != "b@riverside.edu" {
		t.Errorf("the riverside session after lakeside's logout = %+v, want it still signed in", v)
	}

	// Entra sends the sid alone: the riverside session, under the slot's other issuer, ends.
	provider.expect(ctx, http.StatusOK, http.MethodGet, "/entra/logout?sid=sid-shared", nil)
	river.expect(ctx, http.StatusUnauthorized, http.MethodGet, "/whoami", nil)
}

// seamRulesListedWorkspaces is the scenario "listed Workspaces".
func seamRulesListedWorkspaces[Tx any](ctx context.Context, t *testing.T, be backend[Tx]) {
	a := newRulesApp(ctx, t, be, &rulesShape{
		tenants: azure.Tenant(azureTenant), entraAccounts: signin.MembersOfDirectory,
		workspaces:     google.Workspaces(google.Workspace("lakeside", hostedDomain), google.Workspace("riverside", riversideDomain)),
		googleAccounts: signin.MembersOfDirectory,
	})

	lake := a.browser(t)
	assertRedirect(t, a.googleSignIn(ctx, lake, googleClaimsAt(hostedDomain, "sub-pat", "pat@lakeside.edu")), "/home", url.Values{})
	lv := signedInAs(ctx, t, lake, "pat@lakeside.edu")
	assertEventsSeen(t, lv, "google:lakeside")
	assertOneLink(t, a.links(ctx, t, lv.UserID), "lakeside", "lakeside")

	river := a.browser(t)
	assertRedirect(t, a.googleSignIn(ctx, river, googleClaimsAt(riversideDomain, "sub-sam", "sam@riverside.edu")), "/home", url.Values{})
	rv := signedInAs(ctx, t, river, "sam@riverside.edu")
	if rv.UserID == lv.UserID {
		t.Error("the riverside person signed in as the lakeside user, want a new identity")
	}
	assertOneLink(t, a.links(ctx, t, rv.UserID), "riverside", "riverside")

	o := a.browser(t)
	assertRedirect(t, a.googleSignIn(ctx, o, googleClaimsAt("elsewhere.example", "sub-x", "x@elsewhere.example")), "/login", url.Values{"code": {"not_workspace_member"}})
	a.assertNoRow(ctx, t, o, "x@elsewhere.example")
}

// seamRulesAnyWorkspace is the scenario "any Workspace, invited users only".
func seamRulesAnyWorkspace[Tx any](ctx context.Context, t *testing.T, be backend[Tx]) {
	a := newRulesApp(ctx, t, be, &rulesShape{
		tenants: azure.Tenant(azureTenant), entraAccounts: signin.InvitedUsersOnly,
		workspaces: google.AnyWorkspace(), googleAccounts: signin.InvitedUsersOnly,
	})
	pat := a.createUser(ctx, t, "pat@hilltop.edu")

	b := a.browser(t)
	assertRedirect(t, a.googleSignIn(ctx, b, googleClaimsAt("Hilltop.edu", "sub-h", "pat@hilltop.edu")), "/home", url.Values{})
	if v := signedInAs(ctx, t, b, "pat@hilltop.edu"); v.UserID != pat.String() {
		t.Errorf("session user = %s, want the pre-created %s", v.UserID, pat)
	}
	assertOneLink(t, a.links(ctx, t, pat.String()), "hilltop.edu", "hilltop.edu")

	s := a.browser(t)
	assertRedirect(t, a.googleSignIn(ctx, s, googleClaimsAt("elsewhere.example", "sub-x", "x@elsewhere.example")), "/login", url.Values{"code": {"not_invited"}})
	a.assertNoRow(ctx, t, s, "x@elsewhere.example")

	n := a.browser(t)
	assertRedirect(t, a.googleSignIn(ctx, n, map[string]any{"sub": "sub-n", "email": "n@gmail.example", "email_verified": true}), "/login", url.Values{"code": {"not_workspace_member"}})
	a.assertNoRow(ctx, t, n, "n@gmail.example")
}
