package dbtype

import (
	"testing"
	"time"

	"github.com/cccteam/ccc"
	"github.com/cccteam/ccc/accesstypes"
	"github.com/cccteam/session/sessioninfo"
	"github.com/google/go-cmp/cmp"
)

func strPtr(s string) *string { return &s }

func TestMaskColumn_RoundTrip(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name    string
		mask    accesstypes.PermissionMask
		wantCol *string
	}{
		{name: "unrestricted is NULL", mask: accesstypes.PermissionMask{}, wantCol: nil},
		{name: "read-only", mask: accesstypes.MaskPermissions(accesstypes.DenyAll(), accesstypes.Read, accesstypes.List), wantCol: strPtr("List,Read")},
		{name: "allows nothing is the empty string", mask: accesstypes.DenyAll(), wantCol: strPtr("")},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			col := MaskColumn(tt.mask)
			if (col == nil) != (tt.wantCol == nil) || (col != nil && *col != *tt.wantCol) {
				t.Fatalf("MaskColumn() = %v, want %v", col, tt.wantCol)
			}
			if got := MaskFromColumn(col); got.String() != tt.mask.String() {
				t.Errorf("MaskFromColumn(MaskColumn()) = %v, want %v", got, tt.mask)
			}
		})
	}
}

func TestMaskFromColumn_Tolerates(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		col  string
		want string
	}{
		{name: "spaces and empty entries", col: " Read, ,List,", want: "List,Read"},
		{name: "duplicates", col: "Read,Read", want: "Read"},
		{name: "empty", col: "", want: ""},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			if got := MaskFromColumn(&tt.col).String(); got != tt.want {
				t.Errorf("MaskFromColumn(%q) = %q, want %q", tt.col, got, tt.want)
			}
		})
	}
}

func TestImpersonation_RowConversions(t *testing.T) {
	t.Parallel()

	sessionID := ccc.Must(ccc.UUIDFromString("de6e1a12-2d4d-4c4d-aaf1-d82cb9a9eff5"))
	sourceID := ccc.Must(ccc.UUIDFromString("7a1d5f6e-0c2b-4a3e-9d8f-1b2c3d4e5f60"))
	started := time.Date(2026, 8, 27, 10, 0, 0, 0, time.UTC)
	expires := started.Add(time.Hour)
	ended := started.Add(30 * time.Minute)

	tests := []struct {
		name       string
		imp        *sessioninfo.Impersonation
		wantInsert *InsertImpersonation
		row        *Impersonation
		wantInfo   *sessioninfo.Impersonation
	}{
		{
			name: "impersonated user, read-only, minimal",
			imp: &sessioninfo.Impersonation{
				Actor:     "alice@example.com",
				Principal: accesstypes.UserPrincipal("bob@partner.org"),
				Mask:      accesstypes.MaskPermissions(accesstypes.DenyAll(), accesstypes.List, accesstypes.Read),
				ExpiresAt: expires,
			},
			wantInsert: &InsertImpersonation{
				ActorUsername: "alice@example.com",
				PrincipalKind: PrincipalKindUser,
				PrincipalUser: strPtr("bob@partner.org"),
				Mask:          strPtr("List,Read"),
				ExpiresAt:     expires,
			},
			row: &Impersonation{
				SessionID:     sessionID,
				ActorUsername: "alice@example.com",
				PrincipalKind: PrincipalKindUser,
				PrincipalUser: strPtr("bob@partner.org"),
				Mask:          strPtr("List,Read"),
				StartedAt:     started,
				ExpiresAt:     expires,
			},
			wantInfo: &sessioninfo.Impersonation{
				SessionID: sessionID,
				Actor:     "alice@example.com",
				Principal: accesstypes.UserPrincipal("bob@partner.org"),
				Mask:      accesstypes.MaskPermissions(accesstypes.DenyAll(), accesstypes.List, accesstypes.Read),
				StartedAt: started,
				ExpiresAt: expires,
			},
		},
		{
			name: "impersonated role, every optional field, ended",
			imp: &sessioninfo.Impersonation{
				Actor:           "alice@example.com",
				ActorRealm:      "admin-portal",
				SourceSessionID: ccc.NullUUID{UUID: sourceID, Valid: true},
				Principal:       accesstypes.RolePrincipal("PartnerViewer"),
				Reason:          "ticket JRN-123",
				ExpiresAt:       expires,
			},
			wantInsert: &InsertImpersonation{
				ActorUsername:   "alice@example.com",
				ActorRealm:      strPtr("admin-portal"),
				SourceSessionID: &sourceID,
				PrincipalKind:   PrincipalKindRole,
				PrincipalRole:   strPtr("PartnerViewer"),
				Reason:          strPtr("ticket JRN-123"),
				ExpiresAt:       expires,
			},
			row: &Impersonation{
				SessionID:       sessionID,
				ActorUsername:   "alice@example.com",
				ActorRealm:      strPtr("admin-portal"),
				SourceSessionID: &sourceID,
				PrincipalKind:   PrincipalKindRole,
				PrincipalRole:   strPtr("PartnerViewer"),
				Reason:          strPtr("ticket JRN-123"),
				StartedAt:       started,
				ExpiresAt:       expires,
				EndedAt:         &ended,
				EndReason:       strPtr("Revoked"),
			},
			wantInfo: &sessioninfo.Impersonation{
				SessionID:       sessionID,
				Actor:           "alice@example.com",
				ActorRealm:      "admin-portal",
				SourceSessionID: ccc.NullUUID{UUID: sourceID, Valid: true},
				Principal:       accesstypes.RolePrincipal("PartnerViewer"),
				Reason:          "ticket JRN-123",
				StartedAt:       started,
				ExpiresAt:       expires,
				EndedAt:         &ended,
				EndReason:       sessioninfo.ImpersonationEndedByRevocation,
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			if diff := cmp.Diff(tt.wantInsert, NewInsertImpersonation(tt.imp)); diff != "" {
				t.Errorf("NewInsertImpersonation() mismatch (-want +got):\n%s", diff)
			}
			if diff := cmp.Diff(tt.wantInfo, tt.row.ToSessionInfo(), cmp.Comparer(func(a, b accesstypes.Principal) bool { return a == b }), cmp.Comparer(func(a, b accesstypes.PermissionMask) bool { return a.String() == b.String() })); diff != "" {
				t.Errorf("ToSessionInfo() mismatch (-want +got):\n%s", diff)
			}
		})
	}
}
