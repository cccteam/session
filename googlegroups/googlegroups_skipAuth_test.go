//go:build skipAuth

package googlegroups

import (
	"testing"

	"github.com/google/go-cmp/cmp"
)

func TestDirectory_simulatedUnderSkipAuth(t *testing.T) {
	tests := []struct {
		name        string
		credentials []byte
		subject     string
		appRoles    string
		want        []string
	}{
		{name: "nothing configured, as a development environment has, and no roles", appRoles: "", want: nil},
		{name: "each APP_ROLES entry is one simulated group", appRoles: "admin,viewer", want: []string{"admin@skipauth.invalid", "viewer@skipauth.invalid"}},
		{name: "roles are lowercased, as group emails are, and stray entries ignored", appRoles: " Admin, ,Viewer,", want: []string{"admin@skipauth.invalid", "viewer@skipauth.invalid"}},
		{name: "credentials without a subject are accepted, since none is read", credentials: []byte(`{}`), appRoles: "admin", want: []string{"admin@skipauth.invalid"}},
		{name: "a full registration is accepted and unused", credentials: []byte(`{}`), subject: "admin@example.com", appRoles: "admin", want: []string{"admin@skipauth.invalid"}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Setenv("APP_ROLES", tt.appRoles)
			d, err := NewDirectory(t.Context(), tt.credentials, tt.subject)
			if err != nil {
				t.Fatalf("NewDirectory() error = %v", err)
			}
			got, err := d.UserGroups(t.Context(), "user@example.com")
			if err != nil {
				t.Fatalf("UserGroups() error = %v", err)
			}
			if diff := cmp.Diff(tt.want, got); diff != "" {
				t.Errorf("UserGroups() mismatch (-want +got):\n%s", diff)
			}
		})
	}
}
