package azure

import (
	"strings"
	"testing"

	"github.com/cccteam/session/mock/mock_signin"
	"github.com/cccteam/session/sessioninfo"
	"github.com/cccteam/session/signin"
	"github.com/google/go-cmp/cmp"
	"go.uber.org/mock/gomock"
)

const (
	// tenantLake, tenantRiver and tenantOther are three Entra tenants' ids.
	tenantLake  = "11111111-1111-1111-1111-111111111111"
	tenantRiver = "22222222-2222-2222-2222-222222222222"
	tenantOther = "33333333-3333-3333-3333-333333333333"
	// testAuthority is the Microsoft identity platform the tests' tenants live on.
	testAuthority = "https://login"
)

func TestTenantSet_validate(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name    string
		tenants TenantSet
		wantErr string
	}{
		{name: "one tenant", tenants: Tenant(tenantLake)},
		{name: "a named tenant", tenants: NamedTenant(tenantLake, "lakeside")},
		{name: "several tenants", tenants: Tenants(Tenant(tenantLake), NamedTenant(tenantRiver, "riverside"))},
		{name: "any tenant", tenants: AnyTenant()},
		{name: "personal accounts", tenants: PersonalAccounts()},
		{name: "listed tenants beside any tenant and personal accounts", tenants: Tenants(NamedTenant(tenantLake, "lakeside"), AnyTenant(), PersonalAccounts())},
		{name: "a tenant id in upper case is a tenant id", tenants: Tenant(strings.ToUpper(tenantLake))},
		{name: "the zero value admits no one", wantErr: "Tenants is required"},
		{name: "a tenant id that is not a GUID", tenants: Tenant("lakeside"), wantErr: `Tenants: "lakeside" is not a tenant id`},
		{name: "an empty tenant id", tenants: Tenant(""), wantErr: `Tenants: "" is not a tenant id`},
		{name: "the consumer tenant listed", tenants: Tenant(ConsumerTenantID), wantErr: "is Microsoft's consumer tenant, the personal accounts: use azure.PersonalAccounts()"},
		{name: "a tenant listed twice, in another case", tenants: Tenants(Tenant(tenantLake), NamedTenant(strings.ToUpper(tenantLake), "again")), wantErr: "is listed twice"},
		{name: "a blank name", tenants: NamedTenant(tenantLake, "  "), wantErr: "is blank"},
		{name: "a name used twice, in another case", tenants: Tenants(NamedTenant(tenantLake, "lakeside"), NamedTenant(tenantRiver, "Lakeside")), wantErr: `the name "Lakeside" is used twice`},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			err := tt.tenants.validate()
			if (err != nil) != (tt.wantErr != "") {
				t.Fatalf("validate() error = %v, wantErr %q", err, tt.wantErr)
			}
			if err != nil && !strings.Contains(err.Error(), tt.wantErr) {
				t.Errorf("validate() error = %q, want it to contain %q", err.Error(), tt.wantErr)
			}
		})
	}
}

func TestTenantSet_admits(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name             string
		tenants          TenantSet
		tid              string
		wantOrganization string
		wantOK           bool
		wantCode         sessioninfo.LoginRefusalCode
	}{
		{name: "one tenant admits its tenant under its id", tenants: Tenant(tenantLake), tid: tenantLake, wantOrganization: tenantLake, wantOK: true},
		{name: "a tenant id is matched without regard to case and the organization is the id in lower case", tenants: Tenant(tenantLake), tid: strings.ToUpper(tenantLake), wantOrganization: tenantLake, wantOK: true},
		{name: "a named tenant is admitted under its name", tenants: NamedTenant(tenantLake, "lakeside"), tid: tenantLake, wantOrganization: "lakeside", wantOK: true},
		{name: "one tenant refuses another tenant", tenants: Tenant(tenantLake), tid: tenantRiver, wantCode: sessioninfo.RefusedUnlistedTenant},
		{name: "one tenant refuses a personal account", tenants: Tenant(tenantLake), tid: ConsumerTenantID, wantCode: sessioninfo.RefusedPersonalAccount},
		{name: "listed tenants admit each under its own key", tenants: Tenants(Tenant(tenantLake), NamedTenant(tenantRiver, "riverside")), tid: tenantRiver, wantOrganization: "riverside", wantOK: true},
		{name: "listed tenants refuse one outside the list", tenants: Tenants(Tenant(tenantLake), Tenant(tenantRiver)), tid: tenantOther, wantCode: sessioninfo.RefusedUnlistedTenant},
		{name: "any tenant admits a work or school tenant under its id", tenants: AnyTenant(), tid: tenantOther, wantOrganization: tenantOther, wantOK: true},
		{name: "any tenant refuses a personal account", tenants: AnyTenant(), tid: ConsumerTenantID, wantCode: sessioninfo.RefusedPersonalAccount},
		{name: "personal accounts admit the consumer tenant", tenants: PersonalAccounts(), tid: ConsumerTenantID, wantOrganization: ConsumerTenantID, wantOK: true},
		{name: "personal accounts refuse a work or school tenant", tenants: PersonalAccounts(), tid: tenantLake, wantCode: sessioninfo.RefusedUnlistedTenant},
		{name: "a named tenant beside any tenant keeps its name", tenants: Tenants(NamedTenant(tenantLake, "lakeside"), AnyTenant()), tid: tenantLake, wantOrganization: "lakeside", wantOK: true},
		{name: "any tenant beside personal accounts admits both", tenants: Tenants(AnyTenant(), PersonalAccounts()), tid: ConsumerTenantID, wantOrganization: ConsumerTenantID, wantOK: true},
		{name: "no tenant is admitted without a tid", tenants: AnyTenant(), tid: "", wantCode: sessioninfo.RefusedUnlistedTenant},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			organization, ok := tt.tenants.admits(tt.tid)
			if ok != tt.wantOK || organization != tt.wantOrganization {
				t.Fatalf("admits(%q) = %q, %v; want %q, %v", tt.tid, organization, ok, tt.wantOrganization, tt.wantOK)
			}
			if ok {
				return
			}
			err := tt.tenants.refusal(tt.tid)
			if got := sessioninfo.LoginRefusalCodeOf(err); got != tt.wantCode {
				t.Errorf("refusal(%q) code = %q, want %q: %v", tt.tid, got, tt.wantCode, err)
			}
		})
	}
}

func TestTenantSet_endpoints(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name          string
		tenants       TenantSet
		wantDiscovery string
		wantShared    bool
	}{
		{name: "one tenant is served at the tenant's own endpoint", tenants: Tenant(tenantLake), wantDiscovery: testAuthority + "/" + tenantLake + "/v2.0"},
		{name: "a tenant id is lowercased in its endpoint", tenants: Tenant(strings.ToUpper(tenantLake)), wantDiscovery: testAuthority + "/" + tenantLake + "/v2.0"},
		{name: "several tenants are served at organizations", tenants: Tenants(Tenant(tenantLake), Tenant(tenantRiver)), wantDiscovery: testAuthority + "/organizations/v2.0", wantShared: true},
		{name: "any tenant is served at organizations", tenants: AnyTenant(), wantDiscovery: testAuthority + "/organizations/v2.0", wantShared: true},
		{name: "personal accounts alone are served at consumers", tenants: PersonalAccounts(), wantDiscovery: testAuthority + "/consumers/v2.0", wantShared: true},
		{name: "personal accounts beside any tenant are served at common", tenants: Tenants(AnyTenant(), PersonalAccounts()), wantDiscovery: testAuthority + "/common/v2.0", wantShared: true},
		{name: "personal accounts beside a listed tenant are served at common", tenants: Tenants(Tenant(tenantLake), PersonalAccounts()), wantDiscovery: testAuthority + "/common/v2.0", wantShared: true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			if got := tt.tenants.discoveryURL(testAuthority); got != tt.wantDiscovery {
				t.Errorf("discoveryURL() = %q, want %q", got, tt.wantDiscovery)
			}
			if got := tt.tenants.shared(); got != tt.wantShared {
				t.Errorf("shared() = %v, want %v", got, tt.wantShared)
			}
		})
	}
}

func TestTenantSet_issuers(t *testing.T) {
	t.Parallel()

	issuer := func(tid string) string { return testAuthority + "/" + tid + "/v2.0" }
	tests := []struct {
		name         string
		tenants      TenantSet
		iss          string
		wantContains bool
		wantOnly     string
	}{
		{name: "one tenant declares its issuer alone", tenants: Tenant(tenantLake), iss: issuer(tenantLake), wantContains: true, wantOnly: issuer(tenantLake)},
		{name: "one tenant does not contain another tenant's issuer", tenants: Tenant(tenantLake), iss: issuer(tenantRiver), wantOnly: issuer(tenantLake)},
		{name: "listed tenants contain each listed tenant's issuer and name no only issuer", tenants: Tenants(Tenant(tenantLake), Tenant(tenantRiver)), iss: issuer(tenantRiver), wantContains: true},
		{name: "listed tenants do not contain an unlisted tenant's issuer", tenants: Tenants(Tenant(tenantLake), Tenant(tenantRiver)), iss: issuer(tenantOther)},
		{name: "any tenant contains every work or school tenant's issuer under the authority", tenants: AnyTenant(), iss: issuer(tenantOther), wantContains: true},
		{name: "any tenant does not contain the consumer tenant's issuer", tenants: AnyTenant(), iss: issuer(ConsumerTenantID)},
		{name: "personal accounts contain the consumer tenant's issuer", tenants: PersonalAccounts(), iss: issuer(ConsumerTenantID), wantContains: true},
		{name: "an issuer under another authority is never contained", tenants: AnyTenant(), iss: "https://evil/" + tenantLake + "/v2.0"},
		{name: "a shared endpoint's placeholder issuer is never contained", tenants: AnyTenant(), iss: testAuthority + "/{tenantid}/v2.0"},
		{name: "an issuer of another shape is never contained", tenants: AnyTenant(), iss: testAuthority + "/organizations/v2.0"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			issuers := tt.tenants.issuers(testAuthority)
			if got := issuers.Contains(tt.iss); got != tt.wantContains {
				t.Errorf("issuers().Contains(%q) = %v, want %v", tt.iss, got, tt.wantContains)
			}
			if only, ok := issuers.Only(); ok != (tt.wantOnly != "") || only != tt.wantOnly {
				t.Errorf("issuers().Only() = %q, %v; want %q", only, ok, tt.wantOnly)
			}
		})
	}
}

func TestTenantSet_simulatedTenantID(t *testing.T) {
	t.Parallel()

	const fallback = "034cdd64-5dd9-4a3b-90fb-c76d3a499433"
	tests := []struct {
		name    string
		tenants TenantSet
		want    string
	}{
		{name: "one tenant simulates it", tenants: Tenant(tenantLake), want: tenantLake},
		{name: "a listed tenant is simulated in lower case", tenants: Tenant(strings.ToUpper(tenantLake)), want: tenantLake},
		{name: "several tenants simulate the first", tenants: Tenants(Tenant(tenantRiver), Tenant(tenantLake)), want: tenantRiver},
		{name: "a listed tenant beside any tenant is simulated", tenants: Tenants(AnyTenant(), Tenant(tenantLake)), want: tenantLake},
		{name: "any tenant simulates the fixed tenant", tenants: AnyTenant(), want: fallback},
		{name: "personal accounts alone simulate the consumer tenant", tenants: PersonalAccounts(), want: ConsumerTenantID},
		{name: "any tenant beside personal accounts simulates the fixed tenant", tenants: Tenants(AnyTenant(), PersonalAccounts()), want: fallback},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			if got := tt.tenants.simulatedTenantID(fallback); got != tt.want {
				t.Errorf("simulatedTenantID() = %q, want %q", got, tt.want)
			}
		})
	}
}

func TestTenantOfIssuer(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name          string
		issuer        string
		wantAuthority string
		wantTenant    TenantSet
		wantErr       bool
	}{
		{name: "a tenant's v2.0 issuer", issuer: "https://login.microsoftonline.com/" + tenantLake + "/v2.0", wantAuthority: DefaultAuthority, wantTenant: Tenant(tenantLake)},
		{name: "a trailing slash is tolerated", issuer: "https://login.microsoftonline.com/" + tenantLake + "/v2.0/", wantAuthority: DefaultAuthority, wantTenant: Tenant(tenantLake)},
		{name: "another authority", issuer: "https://login.microsoftonline.us/" + tenantLake + "/v2.0", wantAuthority: "https://login.microsoftonline.us", wantTenant: Tenant(tenantLake)},
		{name: "a v1.0 issuer names no v2.0 tenant", issuer: "https://sts.windows.net/" + tenantLake + "/", wantErr: true},
		{name: "a shared endpoint is no tenant's issuer", issuer: "https://login.microsoftonline.com/common/v2.0", wantErr: true},
		{name: "a bare word", issuer: "issuerURL", wantErr: true},
		{name: "an issuer without a scheme", issuer: "login/" + tenantLake + "/v2.0", wantErr: true},
		{name: "an authority with a path", issuer: "https://login.microsoftonline.com/extra/" + tenantLake + "/v2.0", wantErr: true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			authority, tenant, err := TenantOfIssuer(tt.issuer)
			if (err != nil) != tt.wantErr {
				t.Fatalf("TenantOfIssuer() error = %v, wantErr %v", err, tt.wantErr)
			}
			if authority != tt.wantAuthority {
				t.Errorf("TenantOfIssuer() authority = %q, want %q", authority, tt.wantAuthority)
			}
			if diff := cmp.Diff(tt.wantTenant, tenant, cmp.AllowUnexported(TenantSet{}, namedTenant{})); diff != "" {
				t.Errorf("TenantOfIssuer() tenant mismatch (-want +got):\n%s", diff)
			}
		})
	}
}

func TestAuthorityOf(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name      string
		authority string
		want      string
		wantErr   bool
	}{
		{name: "empty is the default", want: DefaultAuthority},
		{name: "a base URL", authority: "https://login.microsoftonline.us", want: "https://login.microsoftonline.us"},
		{name: "a trailing slash is dropped", authority: "https://login.microsoftonline.us/", want: "https://login.microsoftonline.us"},
		{name: "a test server over http", authority: "http://127.0.0.1:8443", want: "http://127.0.0.1:8443"},
		{name: "a path is refused", authority: "https://login.microsoftonline.com/common", wantErr: true},
		{name: "a query is refused", authority: "https://login.microsoftonline.com?x=1", wantErr: true},
		{name: "no scheme is refused", authority: "login.microsoftonline.com", wantErr: true},
		{name: "another scheme is refused", authority: "ftp://login.microsoftonline.com", wantErr: true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			got, err := authorityOf(tt.authority)
			if (err != nil) != tt.wantErr {
				t.Fatalf("authorityOf() error = %v, wantErr %v", err, tt.wantErr)
			}
			if err != nil && !strings.Contains(err.Error(), "Authority: ") {
				t.Errorf("authorityOf() error = %q, want it to name the field", err.Error())
			}
			if got != tt.want {
				t.Errorf("authorityOf() = %q, want %q", got, tt.want)
			}
		})
	}
}

func TestRefuseShape(t *testing.T) {
	t.Parallel()

	sync := signin.RoleSync(mock_signin.NewMockUserRoleManager(gomock.NewController(t)))
	off := signin.DisableRoleSync()
	tests := []struct {
		name     string
		tenants  TenantSet
		roleSync signin.RoleSyncConfig
		accounts signin.StandardAccountRule
		noRule   bool
		wantErr  string
	}{
		{name: "one tenant with role sync and members of the directory", tenants: Tenant(tenantLake), roleSync: sync, accounts: signin.MembersOfDirectory, noRule: true},
		{name: "several tenants without role sync, invited users only", tenants: Tenants(Tenant(tenantLake), Tenant(tenantRiver)), roleSync: off, accounts: signin.InvitedUsersOnly, noRule: true},
		{name: "any tenant with invited users only", tenants: AnyTenant(), roleSync: off, accounts: signin.InvitedUsersOnly, noRule: true},
		{name: "any tenant with open sign-up", tenants: AnyTenant(), roleSync: off, accounts: signin.OpenSignUp, noRule: true},
		{name: "personal accounts with open sign-up", tenants: PersonalAccounts(), roleSync: off, accounts: signin.OpenSignUp, noRule: true},
		{name: "any tenant as members of the directory with a rule of the application's own", tenants: AnyTenant(), roleSync: off, accounts: signin.MembersOfDirectory},
		{name: "the slot's own rules come first", roleSync: sync, accounts: signin.OpenSignUp, noRule: true, wantErr: "Tenants is required"},
		{name: "a missing role sync slot", tenants: Tenant(tenantLake), accounts: signin.MembersOfDirectory, noRule: true, wantErr: "roleSync is required"},
		{name: "role sync across several tenants", tenants: Tenants(Tenant(tenantLake), Tenant(tenantRiver)), roleSync: sync, accounts: signin.InvitedUsersOnly, noRule: true, wantErr: "RoleSync: role synchronization follows one tenant's application roles"},
		{name: "role sync across any tenant", tenants: AnyTenant(), roleSync: sync, accounts: signin.InvitedUsersOnly, noRule: true, wantErr: "RoleSync: role synchronization follows one tenant's application roles"},
		{name: "role sync with personal accounts", tenants: PersonalAccounts(), roleSync: sync, accounts: signin.OpenSignUp, noRule: true, wantErr: "RoleSync: role synchronization follows one tenant's application roles"},
		{name: "open sign-up with one tenant", tenants: Tenant(tenantLake), roleSync: off, accounts: signin.OpenSignUp, noRule: true, wantErr: "Accounts: open sign-up is for any tenant or personal accounts"},
		{name: "open sign-up with listed tenants", tenants: Tenants(Tenant(tenantLake), Tenant(tenantRiver)), roleSync: off, accounts: signin.OpenSignUp, noRule: true, wantErr: "Accounts: open sign-up is for any tenant or personal accounts"},
		{name: "any tenant as members of the directory with no rule", tenants: AnyTenant(), roleSync: off, accounts: signin.MembersOfDirectory, noRule: true, wantErr: "Accounts: members of the directory with any tenant or personal accounts would sign up the world"},
		{name: "personal accounts as members of the directory with no rule", tenants: PersonalAccounts(), roleSync: off, accounts: signin.MembersOfDirectory, noRule: true, wantErr: "would sign up the world"},
		{name: "a listed tenant beside any tenant is still an open slot", tenants: Tenants(Tenant(tenantLake), AnyTenant()), roleSync: off, accounts: signin.MembersOfDirectory, noRule: true, wantErr: "would sign up the world"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			err := refuseShape(tt.tenants, tt.roleSync, tt.accounts, tt.noRule)
			if (err != nil) != (tt.wantErr != "") {
				t.Fatalf("refuseShape() error = %v, wantErr %q", err, tt.wantErr)
			}
			if err != nil && !strings.Contains(err.Error(), tt.wantErr) {
				t.Errorf("refuseShape() error = %q, want it to contain %q", err.Error(), tt.wantErr)
			}
		})
	}
}
