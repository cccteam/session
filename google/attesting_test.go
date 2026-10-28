package google

import (
	"strings"
	"testing"
)

func TestWorkspaceSet_Attesting(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name        string
		workspaces  WorkspaceSet
		wantErrHas  string
		hd          string
		wantAttests bool
	}{
		{name: "a named Workspace declared attesting attests its domains", workspaces: Workspace("lakeside", "lakeside.edu", "lakeside.org").Attesting(), hd: "Lakeside.ORG", wantAttests: true},
		{name: "a named Workspace not declared does not attest", workspaces: Workspace("lakeside", "lakeside.edu"), hd: "lakeside.edu"},
		{name: "beside an open entry, the declared Workspace attests and the open entry does not", workspaces: Workspaces(Workspace("lakeside", "lakeside.edu").Attesting(), AnyGoogleAccount()), hd: "riverside.edu"},
		{name: "beside an open entry, the declared Workspace still attests its own", workspaces: Workspaces(Workspace("lakeside", "lakeside.edu").Attesting(), AnyWorkspace()), hd: "lakeside.edu", wantAttests: true},
		{name: "any Workspace cannot attest", workspaces: AnyWorkspace().Attesting(), wantErrHas: "Attesting() declares the Workspaces the application administers"},
		{name: "any Google account cannot attest", workspaces: AnyGoogleAccount().Attesting(), wantErrHas: "Attesting() declares the Workspaces the application administers"},
		{name: "a union declared attesting as a whole with an open entry is refused", workspaces: Workspaces(Workspace("lakeside", "lakeside.edu"), AnyWorkspace()).Attesting(), wantErrHas: "Attesting() declares the Workspaces"},
		{name: "a refused declaration survives a later union", workspaces: Workspaces(AnyWorkspace().Attesting(), Workspace("lakeside", "lakeside.edu")), wantErrHas: "Attesting() declares the Workspaces"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			err := tt.workspaces.validate()
			if (err != nil) != (tt.wantErrHas != "") || (err != nil && !strings.Contains(err.Error(), tt.wantErrHas)) {
				t.Fatalf("validate() error = %v, want one containing %q", err, tt.wantErrHas)
			}
			if err != nil {
				return
			}
			_, attests, ok := tt.workspaces.entryFor(tt.hd)
			if !ok || attests != tt.wantAttests {
				t.Errorf("entryFor(%q) = attests %v, admitted %v; want attests %v, admitted", tt.hd, attests, ok, tt.wantAttests)
			}
		})
	}
}
