package azure

import (
	"strings"
	"testing"
)

func TestTenantSet_Attesting(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name        string
		tenants     TenantSet
		wantErrHas  string
		tid         string
		wantAttests bool
	}{
		{name: "a listed tenant declared attesting attests", tenants: Tenant(tenantLake).Attesting(), tid: strings.ToUpper(tenantLake), wantAttests: true},
		{name: "a named tenant declared attesting attests and keeps its name", tenants: NamedTenant(tenantLake, "lakeside").Attesting(), tid: tenantLake, wantAttests: true},
		{name: "a listed tenant not declared does not attest", tenants: Tenant(tenantLake), tid: tenantLake},
		{name: "beside an open entry, the declared tenant attests and the open entry does not", tenants: Tenants(Tenant(tenantLake).Attesting(), AnyTenant()), tid: tenantRiver},
		{name: "beside an open entry, the declared tenant still attests its own", tenants: Tenants(Tenant(tenantLake).Attesting(), PersonalAccounts()), tid: tenantLake, wantAttests: true},
		{name: "any tenant cannot attest", tenants: AnyTenant().Attesting(), wantErrHas: "Attesting() declares the tenants the application administers"},
		{name: "personal accounts cannot attest", tenants: PersonalAccounts().Attesting(), wantErrHas: "Attesting() declares the tenants the application administers"},
		{name: "a union declared attesting as a whole with an open entry is refused", tenants: Tenants(Tenant(tenantLake), AnyTenant()).Attesting(), wantErrHas: "Attesting() declares the tenants"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			err := tt.tenants.validate()
			if (err != nil) != (tt.wantErrHas != "") || (err != nil && !strings.Contains(err.Error(), tt.wantErrHas)) {
				t.Fatalf("validate() error = %v, want one containing %q", err, tt.wantErrHas)
			}
			if err != nil {
				return
			}
			if _, ok := tt.tenants.admits(tt.tid); !ok {
				t.Fatalf("admits(%q) = false, want the tenant admitted", tt.tid)
			}
			if got := tt.tenants.attests(tt.tid); got != tt.wantAttests {
				t.Errorf("attests(%q) = %v, want %v", tt.tid, got, tt.wantAttests)
			}
		})
	}
}
