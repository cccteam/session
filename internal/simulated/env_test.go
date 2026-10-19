//go:build skipAuth

package simulated

import (
	"testing"

	"github.com/google/go-cmp/cmp"
)

func TestVariable(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name         string
		registration string
		shared       string
		want         string
	}{
		{name: "a plain name is upper-cased", registration: "google", shared: "APP_USERNAME", want: "APP_GOOGLE_USERNAME"},
		{name: "a hyphen becomes an underscore", registration: "lakeside-entra", shared: "APP_ROLES", want: "APP_LAKESIDE_ENTRA_ROLES"},
		{name: "digits stay, anything else becomes an underscore", registration: "tenant2.eu", shared: "APP_USERNAME", want: "APP_TENANT2_EU_USERNAME"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			if got := Variable(tt.registration, tt.shared); got != tt.want {
				t.Errorf("Variable(%q, %q) = %q, want %q", tt.registration, tt.shared, got, tt.want)
			}
		})
	}
}

func TestUsernameAndRoles(t *testing.T) {
	tests := []struct {
		name         string
		env          map[string]string
		registration string
		wantUser     string
		wantRoles    []string
	}{
		{
			name:         "a registration without a pair of its own reads the shared pair",
			env:          map[string]string{"APP_USERNAME": "dev@example.com", "APP_ROLES": "admin, viewer"},
			registration: "google",
			wantUser:     "dev@example.com",
			wantRoles:    []string{"admin", "viewer"},
		},
		{
			name:         "a registration's own pair wins over the shared pair",
			env:          map[string]string{"APP_USERNAME": "client", "APP_ROLES": "client-portal", "APP_GOOGLE_USERNAME": "navigator", "APP_GOOGLE_ROLES": "CrewCommon,,Headquarters"},
			registration: "google",
			wantUser:     "navigator",
			wantRoles:    []string{"CrewCommon", "Headquarters"},
		},
		{
			name:         "another registration in the same process keeps the shared pair",
			env:          map[string]string{"APP_USERNAME": "client", "APP_ROLES": "client-portal", "APP_GOOGLE_USERNAME": "navigator", "APP_GOOGLE_ROLES": "CrewCommon"},
			registration: "directory",
			wantUser:     "client",
			wantRoles:    []string{"client-portal"},
		},
		{
			name:         "an own variable set empty is an empty answer, not the shared one",
			env:          map[string]string{"APP_USERNAME": "client", "APP_ROLES": "client-portal", "APP_GOOGLE_USERNAME": "", "APP_GOOGLE_ROLES": ""},
			registration: "google",
			wantUser:     "",
			wantRoles:    nil,
		},
		{
			name:         "no registration reads the shared pair",
			env:          map[string]string{"APP_USERNAME": "dev@example.com", "APP_ROLES": ""},
			registration: "",
			wantUser:     "dev@example.com",
			wantRoles:    nil,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			for _, name := range []string{"APP_USERNAME", "APP_ROLES", "APP_GOOGLE_USERNAME", "APP_GOOGLE_ROLES", "APP_DIRECTORY_USERNAME", "APP_DIRECTORY_ROLES"} {
				t.Setenv(name, "")
				if _, ok := tt.env[name]; !ok {
					// Setenv registered the restore; the variable itself must be absent.
					if err := unsetenv(name); err != nil {
						t.Fatal(err)
					}
				}
			}
			for name, value := range tt.env {
				t.Setenv(name, value)
			}

			if got := Username(tt.registration); got != tt.wantUser {
				t.Errorf("Username(%q) = %q, want %q", tt.registration, got, tt.wantUser)
			}
			if diff := cmp.Diff(tt.wantRoles, Roles(tt.registration)); diff != "" {
				t.Errorf("Roles(%q) mismatch (-want +got):\n%s", tt.registration, diff)
			}
		})
	}
}
