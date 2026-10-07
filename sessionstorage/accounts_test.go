package sessionstorage

import (
	"testing"
	"time"

	"github.com/cccteam/ccc"
	"github.com/cccteam/ccc/accesstypes"
	"github.com/cccteam/session/internal/dbtype"
	"github.com/cccteam/session/sessioninfo"
	"github.com/google/go-cmp/cmp"
	"github.com/google/go-cmp/cmp/cmpopts"
	gomock "go.uber.org/mock/gomock"
)

// TestSessionStorage_Session_Account proves the account columns and auth events a
// driver reads reach the public SessionData: the account's ID, when it authenticated,
// and its events; a session without them maps to the zero values.
func TestSessionStorage_Session_Account(t *testing.T) {
	t.Parallel()

	sessionID := ccc.Must(ccc.NewUUID())
	userID := ccc.Must(ccc.NewUUID())
	at := time.Date(2026, 10, 7, 12, 0, 0, 0, time.UTC)
	events := []sessioninfo.AuthEvent{{Method: sessioninfo.MethodWorkOS, Connection: "conn_1", IdPAMR: []string{"mfa"}, At: at}}

	tests := []struct {
		name string
		row  *dbtype.SessionData
		want *sessioninfo.SessionData
	}{
		{
			name: "an account session carries its account, authentication time and events",
			row:  &dbtype.SessionData{Session: &dbtype.Session{ID: sessionID}, UserID: ccc.NullUUIDFromUUID(userID), AuthenticatedAt: &at, AuthEvents: events},
			want: &sessioninfo.SessionData{SessionInfo: &sessioninfo.SessionInfo{ID: sessionID}, UserID: ccc.NullUUIDFromUUID(userID), AuthenticatedAt: at, AuthEvents: events},
		},
		{
			name: "a legacy session carries none",
			row:  &dbtype.SessionData{Session: &dbtype.Session{ID: sessionID}},
			want: &sessioninfo.SessionData{SessionInfo: &sessioninfo.SessionInfo{ID: sessionID}},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			ctrl := gomock.NewController(t)

			mockDB := NewMockdb(ctrl)
			mockDB.EXPECT().Session(gomock.Any(), sessionID).Return(tt.row, nil)

			got, err := (&sessionStorage{db: mockDB}).Session(t.Context(), sessionID)
			if err != nil {
				t.Fatalf("Session() error = %v", err)
			}
			if diff := cmp.Diff(tt.want, got, cmpopts.EquateComparable(accesstypes.Principal{})); diff != "" {
				t.Errorf("Session() mismatch (-want +got):\n%s", diff)
			}
		})
	}
}
