package drivertest

import (
	"context"
	"testing"
	"time"

	"github.com/cccteam/ccc"
	"github.com/cccteam/ccc/accesstypes"
	"github.com/cccteam/session/internal/dbtype"
	"github.com/cccteam/session/sessioninfo"
	"github.com/google/go-cmp/cmp"
	"github.com/google/go-cmp/cmp/cmpopts"
)

// AccountsDriver is the driver surface the accounts suite exercises. Both drivers
// satisfy it.
type AccountsDriver interface {
	Session(ctx context.Context, sessionID ccc.UUID) (*dbtype.SessionData, error)
	InsertSession(ctx context.Context, insertSession *dbtype.InsertSession, req *sessioninfo.NewSessionRequest) (ccc.UUID, error)
	InsertImpersonatedSession(ctx context.Context, insertSession *dbtype.InsertSession, req *sessioninfo.NewSessionRequest, imp *dbtype.InsertImpersonation) (ccc.UUID, error)
	CreateUser(ctx context.Context, user *dbtype.InsertSessionUser, customData any) (*dbtype.SessionUser, error)
}

// AccountsSchema names the migration set an accounts database is prepared with.
type AccountsSchema int

const (
	// LegacySessions is the shipped sessions schema (Sessions, SessionUsers) and the
	// impersonation migration, without the accounts migration: no Sessions.UserId, no
	// AuthenticatedAt, no identities or auth events tables.
	LegacySessions AccountsSchema = iota
	// Accounts is the shipped sessions schema, the impersonation migration and the
	// accounts migration.
	Accounts
)

// AccountsConfig selects how a driver over a prepared accounts database is configured.
type AccountsConfig struct {
	// Accounts enables the Sessions.UserId and AuthenticatedAt columns.
	Accounts bool
	// AuthEvents attaches the SessionAuthEvents table.
	AuthEvents bool
	// Impersonation attaches the SessionImpersonations table.
	Impersonation bool
}

// AccountsInstance is a driver over a freshly prepared accounts database, with the
// harness's own handle on that database.
type AccountsInstance struct {
	Driver AccountsDriver
	Raw    any
}

// AccountsHarness adapts one driver package to the accounts suite.
type AccountsHarness struct {
	// New prepares a fresh database with schema and returns a driver configured per cfg.
	New func(ctx context.Context, t *testing.T, schema AccountsSchema, cfg AccountsConfig) *AccountsInstance
	// CountAuthEvents counts the session's rows in SessionAuthEvents directly.
	CountAuthEvents func(ctx context.Context, t *testing.T, raw any, sessionID ccc.UUID) int
	// DeleteSession deletes the session row directly, bypassing the driver.
	DeleteSession func(ctx context.Context, t *testing.T, raw any, sessionID ccc.UUID)
}

// RunAccounts runs the accounts conformance suite against h. Every case prepares its
// own database and runs in parallel.
func RunAccounts(t *testing.T, h *AccountsHarness) {
	t.Helper()

	tests := []struct {
		name string
		run  func(ctx context.Context, t *testing.T, h *AccountsHarness)
	}{
		{name: "a legacy schema keeps working: the accounts columns and events are never named", run: testLegacySchemaUnchanged},
		{name: "account sessions record and read UserId and AuthenticatedAt", run: testSessionAccountColumns},
		{name: "the first auth event is the sign-in method, read with the session", run: testInitialAuthEvent},
		{name: "an impersonated session records its account and an impersonation event naming the actor", run: testImpersonatedSessionAccount},
		{name: "a session's auth events go with it", run: testAuthEventsCascade},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			tt.run(t.Context(), t, h)
		})
	}
}

// newInsertSession is a fresh session row for username.
func newInsertSession(username string) *dbtype.InsertSession {
	now := time.Now()

	return &dbtype.InsertSession{Username: username, CreatedAt: now, UpdatedAt: now}
}

// createUser creates an account, with a password hash when withPassword.
func createUser(ctx context.Context, t *testing.T, d AccountsDriver, username string) *dbtype.SessionUser {
	t.Helper()

	user, err := d.CreateUser(ctx, &dbtype.InsertSessionUser{Username: username}, nil)
	if err != nil {
		t.Fatalf("CreateUser(%q) error = %v", username, err)
	}

	return user
}

func mustSession(ctx context.Context, t *testing.T, d AccountsDriver, id ccc.UUID) *dbtype.SessionData {
	t.Helper()

	sess, err := d.Session(ctx, id)
	if err != nil {
		t.Fatalf("Session() error = %v", err)
	}

	return sess
}

// eventsOpts compares auth events with timestamps to the second (the backends store
// different precisions) and nil and empty slices alike.
var eventsOpts = cmp.Options{cmpopts.EquateApproxTime(time.Second), cmpopts.EquateEmpty()}

func testLegacySchemaUnchanged(ctx context.Context, t *testing.T, h *AccountsHarness) {
	in := h.New(ctx, t, LegacySessions, AccountsConfig{Impersonation: true})
	user := createUser(ctx, t, in.Driver, "legacy@example.com")

	req := &sessioninfo.NewSessionRequest{
		Reason: sessioninfo.ReasonLogin, Username: user.Username, UserID: user.ID,
		Identity: &sessioninfo.Identity{Method: sessioninfo.MethodPassword, Subject: user.ID.String()},
	}
	id, err := in.Driver.InsertSession(ctx, newInsertSession(user.Username), req)
	if err != nil {
		t.Fatalf("InsertSession() on the legacy schema error = %v", err)
	}
	impID, err := in.Driver.InsertImpersonatedSession(ctx, newInsertSession(user.Username),
		&sessioninfo.NewSessionRequest{Reason: sessioninfo.ReasonImpersonation, Username: user.Username, UserID: user.ID},
		&dbtype.InsertImpersonation{ActorUsername: "actor", PrincipalKind: dbtype.PrincipalKindUser, PrincipalUser: strPtr(user.Username), StartedAt: time.Now(), ExpiresAt: time.Now().Add(time.Hour)})
	if err != nil {
		t.Fatalf("InsertImpersonatedSession() on the legacy schema error = %v", err)
	}

	for _, sid := range []ccc.UUID{id, impID} {
		sess := mustSession(ctx, t, in.Driver, sid)
		if sess.UserID.Valid || sess.AuthenticatedAt != nil || len(sess.AuthEvents) != 0 {
			t.Errorf("Session() = UserID %v, AuthenticatedAt %v, AuthEvents %v; want none on a legacy driver", sess.UserID, sess.AuthenticatedAt, sess.AuthEvents)
		}
	}
}

func testSessionAccountColumns(ctx context.Context, t *testing.T, h *AccountsHarness) {
	in := h.New(ctx, t, Accounts, AccountsConfig{Accounts: true})
	user := createUser(ctx, t, in.Driver, "account@example.com")

	tests := []struct {
		name              string
		req               *sessioninfo.NewSessionRequest
		wantUserID        ccc.NullUUID
		wantAuthenticated bool
	}{
		{
			name:              "a login records the account and when it authenticated",
			req:               &sessioninfo.NewSessionRequest{Reason: sessioninfo.ReasonLogin, Username: user.Username, UserID: user.ID},
			wantUserID:        ccc.NullUUIDFromUUID(user.ID),
			wantAuthenticated: true,
		},
		{
			name: "a preauth stepping stone has no account and authenticated nothing",
			req:  &sessioninfo.NewSessionRequest{Reason: sessioninfo.ReasonPreauth, Username: "stepping-stone"},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			insert := newInsertSession(tt.req.Username)
			id, err := in.Driver.InsertSession(ctx, insert, tt.req)
			if err != nil {
				t.Fatalf("InsertSession() error = %v", err)
			}

			sess := mustSession(ctx, t, in.Driver, id)
			if sess.UserID != tt.wantUserID {
				t.Errorf("Session().UserID = %v, want %v", sess.UserID, tt.wantUserID)
			}
			if got := sess.AuthenticatedAt != nil; got != tt.wantAuthenticated {
				t.Fatalf("Session().AuthenticatedAt = %v, want set %v", sess.AuthenticatedAt, tt.wantAuthenticated)
			}
			if tt.wantAuthenticated && sess.AuthenticatedAt.Sub(insert.CreatedAt).Abs() > time.Second {
				t.Errorf("Session().AuthenticatedAt = %v, want the creation time %v", sess.AuthenticatedAt, insert.CreatedAt)
			}
			if len(sess.AuthEvents) != 0 {
				t.Errorf("Session().AuthEvents = %v, want none without an auth events table", sess.AuthEvents)
			}
		})
	}
}

func testInitialAuthEvent(ctx context.Context, t *testing.T, h *AccountsHarness) {
	in := h.New(ctx, t, Accounts, AccountsConfig{Accounts: true, AuthEvents: true})
	user := createUser(ctx, t, in.Driver, "events@example.com")

	tests := []struct {
		name       string
		identity   *sessioninfo.Identity
		wantEvents []sessioninfo.AuthEvent
	}{
		{
			name:     "a password sign-in records the password method",
			identity: &sessioninfo.Identity{Method: sessioninfo.MethodPassword, Subject: user.ID.String(), IdPAMR: []string{"pwd"}},
			wantEvents: []sessioninfo.AuthEvent{
				{Method: sessioninfo.MethodPassword, IdPAMR: []string{"pwd"}},
			},
		},
		{
			name: "a session without an identity records no event",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			insert := newInsertSession(user.Username)
			id, err := in.Driver.InsertSession(ctx, insert, &sessioninfo.NewSessionRequest{Reason: sessioninfo.ReasonLogin, Username: user.Username, UserID: user.ID, Identity: tt.identity})
			if err != nil {
				t.Fatalf("InsertSession() error = %v", err)
			}

			for i := range tt.wantEvents {
				tt.wantEvents[i].At = insert.CreatedAt
			}
			if diff := cmp.Diff(tt.wantEvents, mustSession(ctx, t, in.Driver, id).AuthEvents, eventsOpts); diff != "" {
				t.Errorf("Session().AuthEvents mismatch (-want +got):\n%s", diff)
			}
		})
	}
}

func testImpersonatedSessionAccount(ctx context.Context, t *testing.T, h *AccountsHarness) {
	in := h.New(ctx, t, Accounts, AccountsConfig{Accounts: true, AuthEvents: true, Impersonation: true})
	user := createUser(ctx, t, in.Driver, "bob@example.com")

	tests := []struct {
		name       string
		principal  accesstypes.Principal
		userID     ccc.UUID
		wantUserID ccc.NullUUID
	}{
		{
			name:       "a user principal's session belongs to the impersonated account",
			principal:  accesstypes.UserPrincipal(accesstypes.User(user.Username)),
			userID:     user.ID,
			wantUserID: ccc.NullUUIDFromUUID(user.ID),
		},
		{
			name:      "a role principal's session belongs to no account",
			principal: accesstypes.RolePrincipal(accesstypes.Role("Viewer")),
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			now := time.Now()
			imp := dbtype.NewInsertImpersonation(&sessioninfo.Impersonation{Actor: "alice@example.com", Principal: tt.principal, StartedAt: now, ExpiresAt: now.Add(time.Hour)})
			insert := newInsertSession(user.Username)
			id, err := in.Driver.InsertImpersonatedSession(ctx, insert, &sessioninfo.NewSessionRequest{Reason: sessioninfo.ReasonImpersonation, Username: user.Username, UserID: tt.userID}, imp)
			if err != nil {
				t.Fatalf("InsertImpersonatedSession() error = %v", err)
			}

			sess := mustSession(ctx, t, in.Driver, id)
			if sess.UserID != tt.wantUserID {
				t.Errorf("Session().UserID = %v, want %v", sess.UserID, tt.wantUserID)
			}
			want := []sessioninfo.AuthEvent{{Method: sessioninfo.MethodImpersonation, Connection: "alice@example.com", At: insert.CreatedAt}}
			if diff := cmp.Diff(want, sess.AuthEvents, eventsOpts); diff != "" {
				t.Errorf("Session().AuthEvents mismatch (-want +got):\n%s", diff)
			}
		})
	}
}

func testAuthEventsCascade(ctx context.Context, t *testing.T, h *AccountsHarness) {
	in := h.New(ctx, t, Accounts, AccountsConfig{Accounts: true, AuthEvents: true})
	user := createUser(ctx, t, in.Driver, "cascade@example.com")

	id, err := in.Driver.InsertSession(ctx, newInsertSession(user.Username), &sessioninfo.NewSessionRequest{
		Reason: sessioninfo.ReasonLogin, Username: user.Username, UserID: user.ID,
		Identity: &sessioninfo.Identity{Method: sessioninfo.MethodPassword, Subject: user.ID.String()},
	})
	if err != nil {
		t.Fatalf("InsertSession() error = %v", err)
	}
	if got := h.CountAuthEvents(ctx, t, in.Raw, id); got != 1 {
		t.Fatalf("auth events after sign-in = %d, want 1", got)
	}

	h.DeleteSession(ctx, t, in.Raw, id)

	if got := h.CountAuthEvents(ctx, t, in.Raw, id); got != 0 {
		t.Errorf("auth events after the session row is deleted = %d, want 0", got)
	}
}
