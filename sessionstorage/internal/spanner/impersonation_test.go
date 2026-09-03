package spanner

import (
	"context"
	"reflect"
	"testing"
	"time"

	"cloud.google.com/go/spanner"
	"github.com/cccteam/ccc"
	"github.com/cccteam/session/internal/dbtype"
	"github.com/cccteam/session/sessioninfo"
	"github.com/google/go-cmp/cmp"
	"github.com/google/go-cmp/cmp/cmpopts"
)

const impersonationSchema = "file://testdata/sessions_test/impersonation_schema"

var (
	impersonatedUserSession = ccc.Must(ccc.UUIDFromString("11111111-1111-1111-1111-111111111111"))
	impersonatedRoleSession = ccc.Must(ccc.UUIDFromString("22222222-2222-2222-2222-222222222222"))
	plainSession            = ccc.Must(ccc.UUIDFromString("33333333-3333-3333-3333-333333333333"))
	impersonatedCarol       = ccc.Must(ccc.UUIDFromString("44444444-4444-4444-4444-444444444444"))
	impersonatedByDave      = ccc.Must(ccc.UUIDFromString("66666666-6666-6666-6666-666666666666"))
	sourceSession           = ccc.Must(ccc.UUIDFromString("55555555-5555-5555-5555-555555555555"))
)

func strPtr(s string) *string { return &s }

func timePtr(t time.Time) *time.Time { return &t }

// impersonationEnd reads the end columns of a record straight from the table.
func impersonationEnd(ctx context.Context, t *testing.T, client *spanner.Client, id ccc.UUID) (endedAt spanner.NullTime, endReason spanner.NullString) {
	t.Helper()

	row, err := client.Single().ReadRow(ctx, "SessionImpersonations", spanner.Key{id.String()}, []string{"EndedAt", "EndReason"})
	if err != nil {
		t.Fatalf("ReadRow() error = %v", err)
	}
	if err := row.Columns(&endedAt, &endReason); err != nil {
		t.Fatalf("row.Columns() error = %v", err)
	}

	return endedAt, endReason
}

func TestSessionStorageDriver_Session_Impersonation(t *testing.T) {
	t.Parallel()

	impersonation := &ImpersonationConfig{TableName: "SessionImpersonations"}
	customData := &CustomSessionDataConfig{TableName: "SessionCustomData", Codec: mustCodec(reflect.TypeFor[customStringData]())}

	tests := []struct {
		name              string
		sessionID         ccc.UUID
		impersonation     *ImpersonationConfig
		customData        *CustomSessionDataConfig
		wantUsername      string
		wantImpersonation *dbtype.Impersonation
		wantCustomData    any
	}{
		{
			name:          "impersonated user, read-only, every optional column set",
			sessionID:     impersonatedUserSession,
			impersonation: impersonation,
			wantUsername:  "bob@partner.org",
			wantImpersonation: &dbtype.Impersonation{
				SessionID:       impersonatedUserSession,
				ActorUsername:   "alice@example.com",
				ActorRealm:      strPtr("admin-portal"),
				SourceSessionID: &sourceSession,
				PrincipalKind:   dbtype.PrincipalKindUser,
				PrincipalUser:   strPtr("bob@partner.org"),
				Mask:            strPtr("List,Read"),
				Reason:          strPtr("ticket JRN-1"),
				StartedAt:       time.Date(2026, 8, 27, 10, 0, 0, 0, time.UTC),
				ExpiresAt:       time.Date(2026, 8, 27, 11, 0, 0, 0, time.UTC),
			},
		},
		{
			name:          "impersonated role, ended, nullable columns NULL",
			sessionID:     impersonatedRoleSession,
			impersonation: impersonation,
			wantUsername:  "alice@example.com",
			wantImpersonation: &dbtype.Impersonation{
				SessionID:     impersonatedRoleSession,
				ActorUsername: "alice@example.com",
				PrincipalKind: dbtype.PrincipalKindRole,
				PrincipalRole: strPtr("PartnerViewer"),
				StartedAt:     time.Date(2026, 8, 27, 9, 0, 0, 0, time.UTC),
				ExpiresAt:     time.Date(2026, 8, 27, 10, 0, 0, 0, time.UTC),
				EndedAt:       timePtr(time.Date(2026, 8, 27, 9, 30, 0, 0, time.UTC)),
				EndReason:     strPtr("Logout"),
			},
		},
		{
			name:          "empty mask column is the mask that allows nothing, not NULL",
			sessionID:     impersonatedCarol,
			impersonation: impersonation,
			wantUsername:  "carol@partner.org",
			wantImpersonation: &dbtype.Impersonation{
				SessionID:     impersonatedCarol,
				ActorUsername: "alice@example.com",
				PrincipalKind: dbtype.PrincipalKindUser,
				PrincipalUser: strPtr("carol@partner.org"),
				Mask:          strPtr(""),
				StartedAt:     time.Date(2026, 8, 27, 10, 0, 0, 0, time.UTC),
				ExpiresAt:     time.Date(2026, 8, 27, 11, 0, 0, 0, time.UTC),
			},
		},
		{
			name:          "session that is not impersonated yields no record",
			sessionID:     plainSession,
			impersonation: impersonation,
			wantUsername:  "plain_user",
		},
		{
			name:         "impersonated session read without the configuration yields no record",
			sessionID:    impersonatedUserSession,
			wantUsername: "bob@partner.org",
		},
		{
			name:           "custom data and impersonation are read together",
			sessionID:      impersonatedUserSession,
			impersonation:  impersonation,
			customData:     customData,
			wantUsername:   "bob@partner.org",
			wantCustomData: &customStringData{CustomString: "admin"},
			wantImpersonation: &dbtype.Impersonation{
				SessionID:       impersonatedUserSession,
				ActorUsername:   "alice@example.com",
				ActorRealm:      strPtr("admin-portal"),
				SourceSessionID: &sourceSession,
				PrincipalKind:   dbtype.PrincipalKindUser,
				PrincipalUser:   strPtr("bob@partner.org"),
				Mask:            strPtr("List,Read"),
				Reason:          strPtr("ticket JRN-1"),
				StartedAt:       time.Date(2026, 8, 27, 10, 0, 0, 0, time.UTC),
				ExpiresAt:       time.Date(2026, 8, 27, 11, 0, 0, 0, time.UTC),
			},
		},
		{
			name:           "no custom row and no record, both joins configured",
			sessionID:      plainSession,
			impersonation:  impersonation,
			customData:     customData,
			wantUsername:   "plain_user",
			wantCustomData: &customStringData{},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			ctx := t.Context()
			conn, err := prepareDatabase(ctx, t, impersonationSchema)
			if err != nil {
				t.Fatalf("prepareDatabase() error = %v", err)
			}
			c := NewSessionStorageDriver(conn.Client)
			if tt.impersonation != nil {
				c.SetImpersonation(tt.impersonation)
			}
			if tt.customData != nil {
				c.SetCustomSessionData(tt.customData)
			}

			got, err := c.Session(ctx, tt.sessionID)
			if err != nil {
				t.Fatalf("Session() error = %v", err)
			}
			if got.Username != tt.wantUsername {
				t.Errorf("Session().Username = %q, want %q", got.Username, tt.wantUsername)
			}
			if diff := cmp.Diff(tt.wantImpersonation, got.Impersonation); diff != "" {
				t.Errorf("Session().Impersonation mismatch (-want +got):\n%s", diff)
			}
			if diff := cmp.Diff(tt.wantCustomData, got.CustomData); diff != "" {
				t.Errorf("Session().CustomData mismatch (-want +got):\n%s", diff)
			}
		})
	}
}

func TestSessionStorageDriver_InsertImpersonatedSession(t *testing.T) {
	t.Parallel()

	expires := time.Now().UTC().Add(time.Hour).Truncate(time.Microsecond)

	tests := []struct {
		name          string
		configured    bool
		customData    *CustomSessionDataConfig
		req           *sessioninfo.NewSessionRequest
		imp           *dbtype.InsertImpersonation
		wantErr       bool
		wantCustom    any
		wantPrincipal string
	}{
		{
			name:       "role principal",
			configured: true,
			req:        &sessioninfo.NewSessionRequest{Reason: sessioninfo.ReasonImpersonation, Username: "alice@example.com"},
			imp: &dbtype.InsertImpersonation{
				ActorUsername: "alice@example.com",
				ActorRealm:    strPtr("admin-portal"),
				PrincipalKind: dbtype.PrincipalKindRole,
				PrincipalRole: strPtr("PartnerViewer"),
				ExpiresAt:     expires,
			},
			wantPrincipal: "PartnerViewer",
		},
		{
			name:       "user principal with mask, reason, source session and per-call custom data",
			configured: true,
			customData: &CustomSessionDataConfig{TableName: "SessionCustomData", Codec: mustCodec(reflect.TypeFor[customStringData]())},
			req: &sessioninfo.NewSessionRequest{
				Reason:     sessioninfo.ReasonImpersonation,
				Username:   "bob@partner.org",
				CustomData: &customStringData{CustomString: "support"},
			},
			imp: &dbtype.InsertImpersonation{
				ActorUsername:   "alice@example.com",
				SourceSessionID: &sourceSession,
				PrincipalKind:   dbtype.PrincipalKindUser,
				PrincipalUser:   strPtr("bob@partner.org"),
				Mask:            strPtr("List,Read"),
				Reason:          strPtr("ticket JRN-2"),
				ExpiresAt:       expires,
			},
			wantCustom:    &customStringData{CustomString: "support"},
			wantPrincipal: "bob@partner.org",
		},
		{
			name:    "refused without the configuration",
			req:     &sessioninfo.NewSessionRequest{Reason: sessioninfo.ReasonImpersonation, Username: "alice@example.com"},
			imp:     &dbtype.InsertImpersonation{ActorUsername: "alice@example.com", PrincipalKind: dbtype.PrincipalKindRole, PrincipalRole: strPtr("Editor"), ExpiresAt: expires},
			wantErr: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			ctx := t.Context()
			conn, err := prepareDatabase(ctx, t, impersonationSchema)
			if err != nil {
				t.Fatalf("prepareDatabase() error = %v", err)
			}
			c := NewSessionStorageDriver(conn.Client)
			if tt.configured {
				c.SetImpersonation(&ImpersonationConfig{TableName: "SessionImpersonations"})
			}
			if tt.customData != nil {
				c.SetCustomSessionData(tt.customData)
			}

			now := time.Now()
			id, err := c.InsertImpersonatedSession(ctx, &dbtype.InsertSession{Username: tt.req.Username, CreatedAt: now, UpdatedAt: now}, tt.req, tt.imp)
			if (err != nil) != tt.wantErr {
				t.Fatalf("InsertImpersonatedSession() error = %v, wantErr %v", err, tt.wantErr)
			}
			if tt.wantErr {
				return
			}

			got, err := c.Session(ctx, id)
			if err != nil {
				t.Fatalf("Session() error = %v", err)
			}
			if got.Username != tt.req.Username || got.Expired {
				t.Errorf("Session() = (%q, expired %v), want (%q, live)", got.Username, got.Expired, tt.req.Username)
			}
			want := &dbtype.Impersonation{
				SessionID:       id,
				ActorUsername:   tt.imp.ActorUsername,
				ActorRealm:      tt.imp.ActorRealm,
				SourceSessionID: tt.imp.SourceSessionID,
				PrincipalKind:   tt.imp.PrincipalKind,
				PrincipalUser:   tt.imp.PrincipalUser,
				PrincipalRole:   tt.imp.PrincipalRole,
				Mask:            tt.imp.Mask,
				Reason:          tt.imp.Reason,
				ExpiresAt:       tt.imp.ExpiresAt,
			}
			if diff := cmp.Diff(want, got.Impersonation, cmpopts.IgnoreFields(dbtype.Impersonation{}, "StartedAt")); diff != "" {
				t.Errorf("Session().Impersonation mismatch (-want +got):\n%s", diff)
			}
			if got.Impersonation.StartedAt.Before(now.Add(-time.Minute)) || got.Impersonation.StartedAt.After(time.Now().Add(time.Minute)) {
				t.Errorf("StartedAt = %v, want about now", got.Impersonation.StartedAt)
			}
			if diff := cmp.Diff(tt.wantCustom, got.CustomData); diff != "" {
				t.Errorf("Session().CustomData mismatch (-want +got):\n%s", diff)
			}
		})
	}
}

func TestSessionStorageDriver_EndImpersonation(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name       string
		sessionID  ccc.UUID
		reason     string
		wantEnded  bool
		wantReason string
	}{
		{name: "live record ends once", sessionID: impersonatedUserSession, reason: "Expired", wantEnded: true, wantReason: "Expired"},
		{name: "already ended record keeps its end", sessionID: impersonatedRoleSession, reason: "Revoked", wantEnded: true, wantReason: "Logout"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			ctx := t.Context()
			conn, err := prepareDatabase(ctx, t, impersonationSchema)
			if err != nil {
				t.Fatalf("prepareDatabase() error = %v", err)
			}
			c := NewSessionStorageDriver(conn.Client)
			c.SetImpersonation(&ImpersonationConfig{TableName: "SessionImpersonations"})

			if err := c.EndImpersonation(ctx, tt.sessionID, tt.reason); err != nil {
				t.Fatalf("EndImpersonation() error = %v", err)
			}
			// A second call must be a no-op.
			if err := c.EndImpersonation(ctx, tt.sessionID, "Revoked"); err != nil {
				t.Fatalf("EndImpersonation() second call error = %v", err)
			}

			endedAt, endReason := impersonationEnd(ctx, t, conn.Client, tt.sessionID)
			if endedAt.Valid != tt.wantEnded || endReason.StringVal != tt.wantReason {
				t.Errorf("record end = (%v, %q), want (%v, %q)", endedAt, endReason.StringVal, tt.wantEnded, tt.wantReason)
			}
		})
	}
}

func TestSessionStorageDriver_EndImpersonation_NoRecordAndUnconfigured(t *testing.T) {
	t.Parallel()
	ctx := t.Context()
	conn, err := prepareDatabase(ctx, t, impersonationSchema)
	if err != nil {
		t.Fatalf("prepareDatabase() error = %v", err)
	}

	unconfigured := NewSessionStorageDriver(conn.Client)
	if err := unconfigured.EndImpersonation(ctx, plainSession, "Logout"); err == nil {
		t.Error("EndImpersonation() without the configuration did not error")
	}

	c := NewSessionStorageDriver(conn.Client)
	c.SetImpersonation(&ImpersonationConfig{TableName: "SessionImpersonations"})
	if err := c.EndImpersonation(ctx, plainSession, "Logout"); err != nil {
		t.Errorf("EndImpersonation() for a session with no record error = %v, want nil", err)
	}
}

func TestSessionStorageDriver_DestroyImpersonatedSessions(t *testing.T) {
	t.Parallel()
	ctx := t.Context()
	conn, err := prepareDatabase(ctx, t, impersonationSchema)
	if err != nil {
		t.Fatalf("prepareDatabase() error = %v", err)
	}
	c := NewSessionStorageDriver(conn.Client)
	c.SetImpersonation(&ImpersonationConfig{TableName: "SessionImpersonations"})

	if err := c.DestroyImpersonatedSessions(ctx, "alice@example.com"); err != nil {
		t.Fatalf("DestroyImpersonatedSessions() error = %v", err)
	}

	tests := []struct {
		name        string
		sessionID   ccc.UUID
		wantExpired bool
		wantReason  string
	}{
		{name: "alice's live user impersonation is expired and revoked", sessionID: impersonatedUserSession, wantExpired: true, wantReason: "Revoked"},
		{name: "alice's other live impersonation is expired and revoked", sessionID: impersonatedCarol, wantExpired: true, wantReason: "Revoked"},
		{name: "alice's already ended record keeps its end", sessionID: impersonatedRoleSession, wantExpired: true, wantReason: "Logout"},
		{name: "another actor's session is untouched", sessionID: impersonatedByDave},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			got, err := c.Session(ctx, tt.sessionID)
			if err != nil {
				t.Fatalf("Session() error = %v", err)
			}
			if got.Expired != tt.wantExpired {
				t.Errorf("Session().Expired = %v, want %v", got.Expired, tt.wantExpired)
			}
			_, endReason := impersonationEnd(ctx, t, conn.Client, tt.sessionID)
			if endReason.StringVal != tt.wantReason {
				t.Errorf("EndReason = %q, want %q", endReason.StringVal, tt.wantReason)
			}
		})
	}

	plain, err := c.Session(ctx, plainSession)
	if err != nil {
		t.Fatalf("Session() error = %v", err)
	}
	if plain.Expired {
		t.Error("a session that is not impersonated was expired")
	}
}

func TestSessionStorageDriver_DestroySession_EndsImpersonation(t *testing.T) {
	t.Parallel()
	ctx := t.Context()
	conn, err := prepareDatabase(ctx, t, impersonationSchema)
	if err != nil {
		t.Fatalf("prepareDatabase() error = %v", err)
	}
	c := NewSessionStorageDriver(conn.Client)
	c.SetImpersonation(&ImpersonationConfig{TableName: "SessionImpersonations"})

	if err := c.DestroySession(ctx, impersonatedUserSession); err != nil {
		t.Fatalf("DestroySession() error = %v", err)
	}
	endedAt, endReason := impersonationEnd(ctx, t, conn.Client, impersonatedUserSession)
	if !endedAt.Valid || endReason.StringVal != "Logout" {
		t.Errorf("record end = (%v, %q), want (ended, Logout)", endedAt, endReason.StringVal)
	}

	// A session that is not impersonated destroys as before.
	if err := c.DestroySession(ctx, plainSession); err != nil {
		t.Fatalf("DestroySession() error = %v", err)
	}
}

func TestSessionStorageDriver_DestroyAllUserSessions_EndsImpersonation(t *testing.T) {
	t.Parallel()
	ctx := t.Context()
	conn, err := prepareDatabase(ctx, t, impersonationSchema)
	if err != nil {
		t.Fatalf("prepareDatabase() error = %v", err)
	}
	c := NewSessionStorageDriver(conn.Client)
	c.SetImpersonation(&ImpersonationConfig{TableName: "SessionImpersonations"})

	if err := c.DestroyAllUserSessions(ctx, "bob@partner.org"); err != nil {
		t.Fatalf("DestroyAllUserSessions() error = %v", err)
	}

	got, err := c.Session(ctx, impersonatedUserSession)
	if err != nil {
		t.Fatalf("Session() error = %v", err)
	}
	if !got.Expired {
		t.Error("bob's impersonated session was not expired")
	}
	endedAt, endReason := impersonationEnd(ctx, t, conn.Client, impersonatedUserSession)
	if !endedAt.Valid || endReason.StringVal != "Revoked" {
		t.Errorf("record end = (%v, %q), want (ended, Revoked)", endedAt, endReason.StringVal)
	}

	_, otherReason := impersonationEnd(ctx, t, conn.Client, impersonatedCarol)
	if otherReason.Valid {
		t.Errorf("another user's record was ended: %q", otherReason.StringVal)
	}
}
