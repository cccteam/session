package sessioninfo

import (
	"testing"

	"github.com/google/go-cmp/cmp"
)

func TestSessionData_EstablishedBy(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name      string
		session   *SessionData
		wantEvent AuthEvent
		wantOK    bool
	}{
		{
			name: "no session records no establishment",
		},
		{
			name:    "a session without events records no establishment",
			session: &SessionData{},
		},
		{
			name:      "a session established by a sign-in through a directory names its method and connection",
			session:   &SessionData{AuthEvents: []AuthEvent{{Method: MethodAzure, Connection: "tid-lakeside", IDPAMR: []string{"pwd", "mfa"}}}},
			wantEvent: AuthEvent{Method: MethodAzure, Connection: "tid-lakeside", IDPAMR: []string{"pwd", "mfa"}},
			wantOK:    true,
		},
		{
			name:      "the sign-in stays the establishment after a link confirmation and an MFA step",
			session:   &SessionData{AuthEvents: []AuthEvent{{Method: MethodPassword}, {Method: MethodLinkConfirmation}, {Method: "email-otp"}}},
			wantEvent: AuthEvent{Method: MethodPassword},
			wantOK:    true,
		},
		{
			name:      "an impersonated session is established by the impersonation, naming the actor",
			session:   &SessionData{AuthEvents: []AuthEvent{{Method: MethodImpersonation, Connection: "alice@example.com"}}},
			wantEvent: AuthEvent{Method: MethodImpersonation, Connection: "alice@example.com"},
			wantOK:    true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			event, ok := tt.session.EstablishedBy()

			if ok != tt.wantOK {
				t.Errorf("EstablishedBy() ok = %v, want %v", ok, tt.wantOK)
			}
			if diff := cmp.Diff(tt.wantEvent, event); diff != "" {
				t.Errorf("EstablishedBy() event mismatch (-want +got):\n%s", diff)
			}
		})
	}
}
