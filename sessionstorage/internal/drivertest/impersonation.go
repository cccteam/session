package drivertest

import (
	"context"
	"testing"
	"time"

	"github.com/cccteam/ccc"
	"github.com/cccteam/ccc/accesstypes"
	"github.com/cccteam/ccc/securehash"
	"github.com/cccteam/session/internal/dbtype"
	"github.com/cccteam/session/sessioninfo"
	"github.com/google/go-cmp/cmp"
)

// RunImpersonation runs the impersonation conformance suite against h. Every case
// prepares its own database and runs in parallel.
func RunImpersonation(t *testing.T, h *Harness) {
	t.Helper()

	tests := []struct {
		name string
		run  func(ctx context.Context, t *testing.T, h *Harness)
	}{
		{name: "Session reads the record joined to the row", run: testSessionReadsRecord},
		{name: "InsertImpersonatedSession writes the row and record atomically", run: testInsertImpersonatedSession},
		{name: "InsertImpersonatedSessionOIDC writes the OIDC-shaped row", run: testInsertImpersonatedSessionOIDC},
		{name: "EndImpersonation ends a live record once", run: testEndImpersonation},
		{name: "EndImpersonation without a record or configuration", run: testEndImpersonationNoRecordAndUnconfigured},
		{name: "DestroyImpersonatedSessions revokes every session the actor holds", run: testDestroyImpersonatedSessions},
		{name: "DestroySession ends the record Logout", run: testDestroySessionEndsImpersonation},
		{name: "DestroyAllUserSessions ends the record Revoked", run: testDestroyAllUserSessionsEndsImpersonation},
		{name: "ActiveImpersonations lists live records newest first", run: testActiveImpersonations},
		{name: "DestroyImpersonatedSession expires one session and ends its record", run: testDestroyImpersonatedSession},
		{name: "username-keyed operations distinguish local and foreign actors", run: testUsernameKeyedOperations},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			tt.run(t.Context(), t, h)
		})
	}
}

func testSessionReadsRecord(_ context.Context, t *testing.T, h *Harness) {
	tests := []struct {
		name              string
		sessionID         ccc.UUID
		cfg               Config
		wantUsername      string
		wantImpersonation *dbtype.Impersonation
		wantCustomData    any
	}{
		{
			name:         "impersonated user, read-only, every optional column set",
			sessionID:    SeededImpersonatedUser,
			cfg:          Config{Impersonation: true},
			wantUsername: "bob@partner.org",
			wantImpersonation: &dbtype.Impersonation{
				SessionID:       SeededImpersonatedUser,
				ActorUsername:   "alice@example.com",
				ActorRealm:      strPtr("admin-portal"),
				SourceSessionID: &SeededSource,
				PrincipalKind:   dbtype.PrincipalKindUser,
				PrincipalUser:   strPtr("bob@partner.org"),
				Mask:            strPtr("List,Read"),
				Reason:          strPtr("ticket JRN-1"),
				StartedAt:       time.Date(2026, 8, 27, 10, 0, 0, 0, time.UTC),
				ExpiresAt:       time.Date(2026, 8, 27, 11, 0, 0, 0, time.UTC),
			},
		},
		{
			name:         "impersonated role, ended, nullable columns NULL",
			sessionID:    SeededImpersonatedRole,
			cfg:          Config{Impersonation: true},
			wantUsername: "alice@example.com",
			wantImpersonation: &dbtype.Impersonation{
				SessionID:     SeededImpersonatedRole,
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
			name:         "empty mask column is the mask that allows nothing, not NULL",
			sessionID:    SeededImpersonatedCarol,
			cfg:          Config{Impersonation: true},
			wantUsername: "carol@partner.org",
			wantImpersonation: &dbtype.Impersonation{
				SessionID:     SeededImpersonatedCarol,
				ActorUsername: "alice@example.com",
				PrincipalKind: dbtype.PrincipalKindUser,
				PrincipalUser: strPtr("carol@partner.org"),
				Mask:          strPtr(""),
				StartedAt:     time.Date(2026, 8, 27, 10, 0, 0, 0, time.UTC),
				ExpiresAt:     time.Date(2026, 8, 27, 11, 0, 0, 0, time.UTC),
			},
		},
		{
			name:         "session that is not impersonated yields no record",
			sessionID:    SeededPlain,
			cfg:          Config{Impersonation: true},
			wantUsername: "plain_user",
		},
		{
			name:         "impersonated session read without the configuration yields no record",
			sessionID:    SeededImpersonatedUser,
			wantUsername: "bob@partner.org",
		},
		{
			name:           "custom data and impersonation are read together",
			sessionID:      SeededImpersonatedUser,
			cfg:            Config{Impersonation: true, CustomData: true},
			wantUsername:   "bob@partner.org",
			wantCustomData: &CustomStringData{CustomString: "admin"},
			wantImpersonation: &dbtype.Impersonation{
				SessionID:       SeededImpersonatedUser,
				ActorUsername:   "alice@example.com",
				ActorRealm:      strPtr("admin-portal"),
				SourceSessionID: &SeededSource,
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
			sessionID:      SeededPlain,
			cfg:            Config{Impersonation: true, CustomData: true},
			wantUsername:   "plain_user",
			wantCustomData: &CustomStringData{},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			ctx := t.Context()
			c := h.New(ctx, t, SeededImpersonation, tt.cfg).Driver

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

func testInsertImpersonatedSession(_ context.Context, t *testing.T, h *Harness) {
	started := time.Now().UTC().Add(-time.Minute).Truncate(time.Microsecond)
	expires := started.Add(time.Hour)

	tests := []struct {
		name       string
		cfg        Config
		req        *sessioninfo.NewSessionRequest
		imp        *dbtype.InsertImpersonation
		wantErr    bool
		wantCustom any
	}{
		{
			name: "role principal",
			cfg:  Config{Impersonation: true},
			req:  &sessioninfo.NewSessionRequest{Reason: sessioninfo.ReasonImpersonation, Username: "alice@example.com"},
			imp: &dbtype.InsertImpersonation{
				ActorUsername: "alice@example.com",
				ActorRealm:    strPtr("admin-portal"),
				PrincipalKind: dbtype.PrincipalKindRole,
				PrincipalRole: strPtr("PartnerViewer"),
				StartedAt:     started,
				ExpiresAt:     expires,
			},
		},
		{
			name: "user principal with mask, reason, source session and per-call custom data",
			cfg:  Config{Impersonation: true, CustomData: true},
			req: &sessioninfo.NewSessionRequest{
				Reason:     sessioninfo.ReasonImpersonation,
				Username:   "bob@partner.org",
				CustomData: &CustomStringData{CustomString: "support"},
			},
			imp: &dbtype.InsertImpersonation{
				ActorUsername:   "alice@example.com",
				SourceSessionID: &SeededSource,
				PrincipalKind:   dbtype.PrincipalKindUser,
				PrincipalUser:   strPtr("bob@partner.org"),
				Mask:            strPtr("List,Read"),
				Reason:          strPtr("ticket JRN-2"),
				StartedAt:       started,
				ExpiresAt:       expires,
			},
			wantCustom: &CustomStringData{CustomString: "support"},
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
			c := h.New(ctx, t, SeededImpersonation, tt.cfg).Driver

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
				StartedAt:       tt.imp.StartedAt,
				ExpiresAt:       tt.imp.ExpiresAt,
			}
			if diff := cmp.Diff(want, got.Impersonation); diff != "" {
				t.Errorf("Session().Impersonation mismatch (-want +got):\n%s", diff)
			}
			if diff := cmp.Diff(tt.wantCustom, got.CustomData); diff != "" {
				t.Errorf("Session().CustomData mismatch (-want +got):\n%s", diff)
			}
		})
	}
}

// The shipped OIDC session schema declares OidcSid NOT NULL; the impersonated insert
// writes the OIDC-shaped row with an empty identity provider session ID.
func testInsertImpersonatedSessionOIDC(_ context.Context, t *testing.T, h *Harness) {
	started := time.Now().UTC().Add(-time.Minute).Truncate(time.Microsecond)
	req := &sessioninfo.NewSessionRequest{Reason: sessioninfo.ReasonImpersonation, Username: "bob@example.com"}
	imp := &dbtype.InsertImpersonation{
		ActorUsername: "alice@example.com",
		PrincipalKind: dbtype.PrincipalKindUser,
		PrincipalUser: strPtr("bob@example.com"),
		Mask:          strPtr("List,Read"),
		StartedAt:     started,
		ExpiresAt:     started.Add(time.Hour),
	}

	tests := []struct {
		name    string
		cfg     Config
		wantErr bool
	}{
		{name: "writes the OIDC session row with an empty OidcSid and the record", cfg: Config{Impersonation: true}},
		{name: "refused without the configuration", wantErr: true},
		{name: "refused on a Google OIDC driver", cfg: Config{Impersonation: true, Google: true}, wantErr: true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			ctx := t.Context()
			inst := h.New(ctx, t, OIDC, tt.cfg)

			now := time.Now()
			session := &dbtype.InsertOIDCSession{InsertSession: dbtype.InsertSession{Username: req.Username, CreatedAt: now, UpdatedAt: now}}
			id, err := inst.Driver.InsertImpersonatedSessionOIDC(ctx, session, req, imp)
			if (err != nil) != tt.wantErr {
				t.Fatalf("InsertImpersonatedSessionOIDC() error = %v, wantErr %v", err, tt.wantErr)
			}
			if tt.wantErr {
				return
			}

			got, err := inst.Driver.Session(ctx, id)
			if err != nil {
				t.Fatalf("Session() error = %v", err)
			}
			if got.Username != req.Username || got.Expired {
				t.Errorf("Session() = (%q, expired %v), want (%q, live)", got.Username, got.Expired, req.Username)
			}
			want := &dbtype.Impersonation{
				SessionID:     id,
				ActorUsername: imp.ActorUsername,
				PrincipalKind: imp.PrincipalKind,
				PrincipalUser: imp.PrincipalUser,
				Mask:          imp.Mask,
				StartedAt:     imp.StartedAt,
				ExpiresAt:     imp.ExpiresAt,
			}
			if diff := cmp.Diff(want, got.Impersonation); diff != "" {
				t.Errorf("Session().Impersonation mismatch (-want +got):\n%s", diff)
			}
			if sid := h.OIDCSid(ctx, t, inst.Raw, id); sid != "" {
				t.Errorf("OidcSid = %q, want empty", sid)
			}
		})
	}
}

func testEndImpersonation(_ context.Context, t *testing.T, h *Harness) {
	tests := []struct {
		name       string
		sessionID  ccc.UUID
		reason     string
		wantReason string
	}{
		{name: "live record ends once", sessionID: SeededImpersonatedUser, reason: "Expired", wantReason: "Expired"},
		{name: "already ended record keeps its end", sessionID: SeededImpersonatedRole, reason: "Revoked", wantReason: "Logout"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			ctx := t.Context()
			inst := h.New(ctx, t, SeededImpersonation, Config{Impersonation: true})

			if err := inst.Driver.EndImpersonation(ctx, tt.sessionID, tt.reason); err != nil {
				t.Fatalf("EndImpersonation() error = %v", err)
			}
			// A second call must be a no-op.
			if err := inst.Driver.EndImpersonation(ctx, tt.sessionID, "Revoked"); err != nil {
				t.Fatalf("EndImpersonation() second call error = %v", err)
			}

			endedAt, endReason := h.RecordEnd(ctx, t, inst.Raw, tt.sessionID)
			if endedAt == nil || reasonOf(endReason) != tt.wantReason {
				t.Errorf("record end = (%v, %q), want (ended, %q)", endedAt, reasonOf(endReason), tt.wantReason)
			}
		})
	}
}

func testEndImpersonationNoRecordAndUnconfigured(ctx context.Context, t *testing.T, h *Harness) {
	inst := h.New(ctx, t, SeededImpersonation, Config{})

	if err := inst.Driver.EndImpersonation(ctx, SeededPlain, "Logout"); err == nil {
		t.Error("EndImpersonation() without the configuration did not error")
	}

	c := inst.NewDriver(Config{Impersonation: true})
	if err := c.EndImpersonation(ctx, SeededPlain, "Logout"); err != nil {
		t.Errorf("EndImpersonation() for a session with no record error = %v, want nil", err)
	}
}

func testDestroyImpersonatedSessions(ctx context.Context, t *testing.T, h *Harness) {
	inst := h.New(ctx, t, SeededImpersonation, Config{Impersonation: true})
	c := inst.Driver

	if err := c.DestroyImpersonatedSessions(ctx, "alice@example.com"); err != nil {
		t.Fatalf("DestroyImpersonatedSessions() error = %v", err)
	}

	tests := []struct {
		name        string
		sessionID   ccc.UUID
		wantExpired bool
		wantReason  string
	}{
		{name: "alice's live user impersonation is expired and revoked", sessionID: SeededImpersonatedUser, wantExpired: true, wantReason: "Revoked"},
		{name: "alice's other live impersonation is expired and revoked", sessionID: SeededImpersonatedCarol, wantExpired: true, wantReason: "Revoked"},
		{name: "alice's already ended record keeps its end", sessionID: SeededImpersonatedRole, wantExpired: true, wantReason: "Logout"},
		{name: "another actor's session is untouched", sessionID: SeededImpersonatedByDave},
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
			_, endReason := h.RecordEnd(ctx, t, inst.Raw, tt.sessionID)
			if got := reasonOf(endReason); got != tt.wantReason {
				t.Errorf("EndReason = %q, want %q", got, tt.wantReason)
			}
		})
	}

	plain, err := c.Session(ctx, SeededPlain)
	if err != nil {
		t.Fatalf("Session() error = %v", err)
	}
	if plain.Expired {
		t.Error("a session that is not impersonated was expired")
	}
}

func testDestroySessionEndsImpersonation(ctx context.Context, t *testing.T, h *Harness) {
	inst := h.New(ctx, t, SeededImpersonation, Config{Impersonation: true})

	if err := inst.Driver.DestroySession(ctx, SeededImpersonatedUser); err != nil {
		t.Fatalf("DestroySession() error = %v", err)
	}
	got, err := inst.Driver.Session(ctx, SeededImpersonatedUser)
	if err != nil {
		t.Fatalf("Session() error = %v", err)
	}
	if !got.Expired {
		t.Error("the session row was not expired")
	}
	endedAt, endReason := h.RecordEnd(ctx, t, inst.Raw, SeededImpersonatedUser)
	if endedAt == nil || reasonOf(endReason) != "Logout" {
		t.Errorf("record end = (%v, %q), want (ended, Logout)", endedAt, reasonOf(endReason))
	}

	// A session that is not impersonated destroys as before, and one that does not
	// exist is not an error.
	if err := inst.Driver.DestroySession(ctx, SeededPlain); err != nil {
		t.Fatalf("DestroySession() error = %v", err)
	}
	if err := inst.Driver.DestroySession(ctx, ccc.Must(ccc.NewUUID())); err != nil {
		t.Fatalf("DestroySession() of a missing session error = %v", err)
	}
}

func testDestroyAllUserSessionsEndsImpersonation(ctx context.Context, t *testing.T, h *Harness) {
	inst := h.New(ctx, t, SeededImpersonation, Config{Impersonation: true})

	if err := inst.Driver.DestroyAllUserSessions(ctx, "bob@partner.org"); err != nil {
		t.Fatalf("DestroyAllUserSessions() error = %v", err)
	}

	got, err := inst.Driver.Session(ctx, SeededImpersonatedUser)
	if err != nil {
		t.Fatalf("Session() error = %v", err)
	}
	if !got.Expired {
		t.Error("bob's impersonated session was not expired")
	}
	endedAt, endReason := h.RecordEnd(ctx, t, inst.Raw, SeededImpersonatedUser)
	if endedAt == nil || reasonOf(endReason) != "Revoked" {
		t.Errorf("record end = (%v, %q), want (ended, Revoked)", endedAt, reasonOf(endReason))
	}

	_, otherReason := h.RecordEnd(ctx, t, inst.Raw, SeededImpersonatedCarol)
	if otherReason != nil {
		t.Errorf("another user's record was ended: %q", *otherReason)
	}
}

func testActiveImpersonations(ctx context.Context, t *testing.T, h *Harness) {
	inst := h.New(ctx, t, SeededImpersonation, Config{Impersonation: true})
	c := inst.Driver

	now := time.Now()
	insert := func(actor string, principal accesstypes.Principal, expiresAt, updatedAt time.Time) ccc.UUID {
		t.Helper()
		username := actor
		if user, ok := principal.User(); ok {
			username = string(user)
		}
		imp := dbtype.NewInsertImpersonation(&sessioninfo.Impersonation{Actor: actor, Principal: principal, StartedAt: time.Now(), ExpiresAt: expiresAt})
		req := &sessioninfo.NewSessionRequest{Reason: sessioninfo.ReasonImpersonation, Username: username}
		id, err := c.InsertImpersonatedSession(ctx, &dbtype.InsertSession{Username: username, CreatedAt: updatedAt, UpdatedAt: updatedAt}, req, imp)
		if err != nil {
			t.Fatalf("InsertImpersonatedSession() error = %v", err)
		}
		time.Sleep(2 * time.Millisecond) // the listing orders by StartedAt; keep the order observable

		return id
	}

	// The seeded records are all past their hard cap and never appear.
	liveUser := insert("alice@example.com", accesstypes.UserPrincipal("bob@partner.org"), now.Add(time.Hour), now)
	liveRole := insert("dave@example.com", accesstypes.RolePrincipal("Editor"), now.Add(time.Hour), now)
	ended := insert("alice@example.com", accesstypes.UserPrincipal("carol@partner.org"), now.Add(time.Hour), now)
	if err := c.EndImpersonation(ctx, ended, "Logout"); err != nil {
		t.Fatalf("EndImpersonation() error = %v", err)
	}
	_ = insert("alice@example.com", accesstypes.UserPrincipal("erin@partner.org"), now.Add(-time.Minute), now) // hard cap passed
	idle := insert("alice@example.com", accesstypes.RolePrincipal("Viewer"), now.Add(time.Hour), now.Add(-time.Hour))
	expiredSession := insert("alice@example.com", accesstypes.UserPrincipal("frank@partner.org"), now.Add(time.Hour), now)
	h.ExpireSession(ctx, t, inst.Raw, expiredSession)

	tests := []struct {
		name        string
		activeSince time.Time
		q           *sessioninfo.ImpersonationQuery
		want        []ccc.UUID
	}{
		{name: "every live record, newest first; ended, capped, expired and idle excluded", activeSince: now.Add(-10 * time.Minute), want: []ccc.UUID{liveRole, liveUser}},
		{name: "an idle session counts when activeSince reaches back far enough", activeSince: time.Time{}, want: []ccc.UUID{idle, liveRole, liveUser}},
		{name: "narrowed by actor", activeSince: now.Add(-10 * time.Minute), q: &sessioninfo.ImpersonationQuery{Actor: "alice@example.com"}, want: []ccc.UUID{liveUser}},
		{name: "narrowed by user principal", activeSince: now.Add(-10 * time.Minute), q: &sessioninfo.ImpersonationQuery{Principal: accesstypes.UserPrincipal("bob@partner.org")}, want: []ccc.UUID{liveUser}},
		{name: "narrowed by role principal", activeSince: now.Add(-10 * time.Minute), q: &sessioninfo.ImpersonationQuery{Principal: accesstypes.RolePrincipal("Editor")}, want: []ccc.UUID{liveRole}},
		{name: "actor and principal together", activeSince: now.Add(-10 * time.Minute), q: &sessioninfo.ImpersonationQuery{Actor: "dave@example.com", Principal: accesstypes.UserPrincipal("bob@partner.org")}, want: []ccc.UUID{}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			got, err := c.ActiveImpersonations(ctx, tt.activeSince, tt.q)
			if err != nil {
				t.Fatalf("ActiveImpersonations() error = %v", err)
			}
			ids := make([]ccc.UUID, len(got))
			for i, imp := range got {
				ids[i] = imp.SessionID
				if imp.ActorUsername == "" || imp.PrincipalKind == "" || imp.ExpiresAt.IsZero() {
					t.Errorf("record %v not fully read: %+v", imp.SessionID, imp)
				}
			}
			if diff := cmp.Diff(tt.want, ids); diff != "" {
				t.Errorf("ActiveImpersonations() mismatch (-want +got):\n%s", diff)
			}
		})
	}

	if _, err := inst.NewDriver(Config{}).ActiveImpersonations(ctx, now, nil); err == nil {
		t.Error("ActiveImpersonations() without the configuration error = nil, want error")
	}
}

func testDestroyImpersonatedSession(ctx context.Context, t *testing.T, h *Harness) {
	inst := h.New(ctx, t, SeededImpersonation, Config{Impersonation: true})
	c := inst.Driver

	tests := []struct {
		name        string
		sessionID   ccc.UUID
		reason      sessioninfo.ImpersonationEndReason
		wantExpired bool
		wantReason  string
	}{
		{name: "a live impersonated session is expired and its record revoked", sessionID: SeededImpersonatedUser, reason: sessioninfo.ImpersonationEndedByRevocation, wantExpired: true, wantReason: "Revoked"},
		{name: "a live impersonated session is expired and its record released, in one step", sessionID: SeededImpersonatedCarol, reason: sessioninfo.ImpersonationEndedByRelease, wantExpired: true, wantReason: "Released"},
		{name: "an already ended record keeps its end", sessionID: SeededImpersonatedRole, reason: sessioninfo.ImpersonationEndedByRevocation, wantExpired: true, wantReason: "Logout"},
		{name: "a session that is not impersonated is untouched", sessionID: SeededPlain, reason: sessioninfo.ImpersonationEndedByRevocation},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			if err := c.DestroyImpersonatedSession(ctx, tt.sessionID, string(tt.reason)); err != nil {
				t.Fatalf("DestroyImpersonatedSession() error = %v", err)
			}
			got, err := c.Session(ctx, tt.sessionID)
			if err != nil {
				t.Fatalf("Session() error = %v", err)
			}
			if got.Expired != tt.wantExpired {
				t.Errorf("Session().Expired = %v, want %v", got.Expired, tt.wantExpired)
			}
			if got.Impersonation == nil {
				return
			}
			if gotReason := reasonOf(got.Impersonation.EndReason); gotReason != tt.wantReason {
				t.Errorf("EndReason = %q, want %q", gotReason, tt.wantReason)
			}
		})
	}

	other, err := c.Session(ctx, SeededImpersonatedByDave)
	if err != nil {
		t.Fatalf("Session() error = %v", err)
	}
	if other.Expired || other.Impersonation.EndedAt != nil {
		t.Error("another live impersonated session was touched")
	}
	if err := inst.NewDriver(Config{}).DestroyImpersonatedSession(ctx, SeededImpersonatedCarol, string(sessioninfo.ImpersonationEndedByRevocation)); err == nil {
		t.Error("DestroyImpersonatedSession() without the configuration error = nil, want error")
	}
}

// The two username-keyed operations treat every session under a name as that account's:
// its own login, a user-principal impersonation of it, the role session it holds as a
// local actor, and the sessions it holds as a local actor under other names, except a
// foreign actor's role-principal session, which only borrows the name.
func testUsernameKeyedOperations(ctx context.Context, t *testing.T, h *Harness) {
	c := h.New(ctx, t, Sessions, Config{Impersonation: true}).Driver

	now := time.Now()
	const name = "dave@example.com"
	const target = "erin@example.com"
	session := func(username string) *dbtype.InsertSession {
		return &dbtype.InsertSession{Username: username, CreatedAt: now, UpdatedAt: now}
	}
	request := func(username string) *sessioninfo.NewSessionRequest {
		return &sessioninfo.NewSessionRequest{Reason: sessioninfo.ReasonLogin, Username: username}
	}
	impersonated := func(username string, imp *sessioninfo.Impersonation) ccc.UUID {
		imp.StartedAt = now
		imp.ExpiresAt = now.Add(time.Hour)
		id, err := c.InsertImpersonatedSession(ctx, session(username), request(username), dbtype.NewInsertImpersonation(imp))
		if err != nil {
			t.Fatalf("InsertImpersonatedSession() error = %v", err)
		}

		return id
	}

	own, err := c.InsertSession(ctx, session(name), request(name))
	if err != nil {
		t.Fatalf("InsertSession() error = %v", err)
	}
	source := ccc.NullUUID{UUID: own, Valid: true}
	// Support (from the admin application) viewing dave as a user.
	asUser := impersonated(name, &sessioninfo.Impersonation{Actor: "alice@example.com", ActorRealm: "admin-portal", Principal: accesstypes.UserPrincipal(name)})
	// dave, logged in here, acting under a role: his own session, narrowed.
	ownRole := impersonated(name, &sessioninfo.Impersonation{Actor: name, SourceSessionID: source, Principal: accesstypes.RolePrincipal("Editor")})
	// dave, logged in here, viewing erin.
	held := impersonated(target, &sessioninfo.Impersonation{Actor: name, SourceSessionID: source, Principal: accesstypes.UserPrincipal(target)})
	// An administrator of another application, also named dave, under a role: borrows the name.
	foreignRole := impersonated(name, &sessioninfo.Impersonation{Actor: name, ActorRealm: "admin-portal", Principal: accesstypes.RolePrincipal("Editor")})

	hash, err := securehash.New(securehash.Argon2()).Hash("password")
	if err != nil {
		t.Fatalf("securehash.Hash() error = %v", err)
	}
	user, err := c.CreateUser(ctx, &dbtype.InsertSessionUser{Username: name, PasswordHash: hash}, nil)
	if err != nil {
		t.Fatalf("CreateUser() error = %v", err)
	}

	if err := c.SetUserUsername(ctx, user.ID, "dan@example.com"); err != nil {
		t.Fatalf("SetUserUsername() error = %v", err)
	}
	renamed := []struct {
		name      string
		sessionID ccc.UUID
		want      string
		wantActor string
	}{
		{"dave's own session is renamed", own, "dan@example.com", ""},
		{"the user impersonation of dave is renamed with him", asUser, "dan@example.com", "alice@example.com"},
		{"dave's own role session is renamed with him", ownRole, "dan@example.com", "dan@example.com"},
		{"the session dave holds as erin keeps erin's name; its live record follows dave's rename", held, target, "dan@example.com"},
		{"the foreign role session keeps the borrowed name, record untouched", foreignRole, name, name},
	}
	for _, tt := range renamed {
		got, err := c.Session(ctx, tt.sessionID)
		if err != nil {
			t.Fatalf("Session() error = %v", err)
		}
		if got.Username != tt.want {
			t.Errorf("%s: Username = %q, want %q", tt.name, got.Username, tt.want)
		}
		if got.Impersonation != nil && got.Impersonation.ActorUsername != tt.wantActor {
			t.Errorf("%s: record ActorUsername = %q, want %q", tt.name, got.Impersonation.ActorUsername, tt.wantActor)
		}
	}

	if err := c.DestroyAllUserSessions(ctx, "dan@example.com"); err != nil {
		t.Fatalf("DestroyAllUserSessions() error = %v", err)
	}
	if err := c.DestroyAllUserSessions(ctx, name); err != nil {
		t.Fatalf("DestroyAllUserSessions() error = %v", err)
	}
	destroyed := []struct {
		name        string
		sessionID   ccc.UUID
		wantExpired bool
		wantEnded   bool
	}{
		{"dave's own session is destroyed", own, true, false},
		{"the user impersonation of dave is destroyed and revoked", asUser, true, true},
		{"dave's own role session is destroyed and revoked", ownRole, true, true},
		{"the session dave holds as erin is destroyed and revoked", held, true, true},
		{"the foreign role session survives both calls", foreignRole, false, false},
	}
	for _, tt := range destroyed {
		got, err := c.Session(ctx, tt.sessionID)
		if err != nil {
			t.Fatalf("Session() error = %v", err)
		}
		if got.Expired != tt.wantExpired {
			t.Errorf("%s: Expired = %v, want %v", tt.name, got.Expired, tt.wantExpired)
		}
		if got.Impersonation == nil {
			continue
		}
		if (got.Impersonation.EndedAt != nil) != tt.wantEnded {
			t.Errorf("%s: record ended = %v, want %v", tt.name, got.Impersonation.EndedAt != nil, tt.wantEnded)
		}
		if tt.wantEnded && reasonOf(got.Impersonation.EndReason) != string(sessioninfo.ImpersonationEndedByRevocation) {
			t.Errorf("%s: EndReason = %q, want Revoked", tt.name, reasonOf(got.Impersonation.EndReason))
		}
	}
}
