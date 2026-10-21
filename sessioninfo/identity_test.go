package sessioninfo

import "testing"

func TestAuthMethod_ThroughDirectory(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name   string
		method AuthMethod
		want   bool
	}{
		{name: "Microsoft Entra ID signs in through a directory", method: MethodAzure, want: true},
		{name: "Google Workspace signs in through a directory", method: MethodGoogle, want: true},
		{name: "WorkOS signs in through a directory", method: MethodWorkOS, want: true},
		{name: "a password is the application's own", method: MethodPassword},
		{name: "a session the application starts itself is the application's own", method: MethodApplication},
		{name: "an impersonation is not a sign-in through a directory", method: MethodImpersonation},
		{name: "a link confirmation is not a sign-in through a directory", method: MethodLinkConfirmation},
		{name: "a step the application records under its own name is the application's own", method: "email-otp"},
		{name: "no method is not a sign-in through a directory", method: ""},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			if got := tt.method.ThroughDirectory(); got != tt.want {
				t.Errorf("AuthMethod(%q).ThroughDirectory() = %v, want %v", tt.method, got, tt.want)
			}
		})
	}
}
