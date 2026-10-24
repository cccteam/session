package drivertest

import (
	"context"
	"testing"
	"time"

	"github.com/cccteam/ccc"
	"github.com/cccteam/ccc/accesstypes"
	"github.com/cccteam/ccc/securehash"
	"github.com/cccteam/session/internal/dbtype"
	"github.com/cccteam/session/internal/signinflow"
	"github.com/cccteam/session/sessioninfo"
	"github.com/cccteam/session/signin"
	"github.com/go-playground/errors/v5"
	"github.com/google/go-cmp/cmp"
	"github.com/google/go-cmp/cmp/cmpopts"
)

// AuthDriver is the driver surface the users suite exercises. Both drivers
// satisfy it.
type AuthDriver interface {
	Session(ctx context.Context, sessionID ccc.UUID) (*dbtype.SessionData, error)
	InsertSession(ctx context.Context, insertSession *dbtype.InsertSession, req *sessioninfo.NewSessionRequest) (ccc.UUID, error)
	InsertImpersonatedSession(ctx context.Context, insertSession *dbtype.InsertSession, req *sessioninfo.NewSessionRequest, imp *dbtype.InsertImpersonation) (ccc.UUID, error)
	CreateUser(ctx context.Context, user *dbtype.InsertSessionUser, customData any) (*dbtype.SessionUser, error)
	User(ctx context.Context, id ccc.UUID) (*dbtype.SessionUser, error)
	UserByUserName(ctx context.Context, username string) (*dbtype.SessionUser, error)
	Users(ctx context.Context) ([]*dbtype.SessionUser, error)
	SetUserPassword(ctx context.Context, id ccc.UUID, hash *securehash.Hash, changeRequired bool) error
	DeactivateUser(ctx context.Context, id ccc.UUID) error
	DeleteUser(ctx context.Context, id ccc.UUID) error
	Identity(ctx context.Context, method sessioninfo.AuthMethod, connection, subject string) (*dbtype.SessionIdentity, error)
	IdentitiesByUser(ctx context.Context, userID ccc.UUID) ([]*dbtype.SessionIdentity, error)
	LinkIdentity(ctx context.Context, userID ccc.UUID, identity *sessioninfo.Identity, tenant string) (*dbtype.SessionIdentity, error)
	UnlinkIdentity(ctx context.Context, identityID ccc.UUID) error
	DestroyUserSessions(ctx context.Context, userID ccc.UUID) error
	TouchUserSignIn(ctx context.Context, userID ccc.UUID) error
	DestroySessionsByProviderSessionID(ctx context.Context, issuer, providerSessionID string) error
	AppendAuthEvent(ctx context.Context, sessionID ccc.UUID, event *sessioninfo.AuthEvent) error
	InsertPendingSignIn(ctx context.Context, p *dbtype.PendingSignIn) error
	PendingSignInByToken(ctx context.Context, tokenHash []byte, now time.Time) (*dbtype.PendingSignIn, error)
	ConsumePendingSignIn(ctx context.Context, tokenHash []byte, now time.Time) error
	SignInAttempts(ctx context.Context, name string) (*dbtype.SignInAttempts, error)
	RecordSignInFailure(ctx context.Context, name string, now time.Time, limit dbtype.SignInAttemptLimit) (*dbtype.SignInAttempts, error)
	ClearSignInAttempts(ctx context.Context, name string) error
	// SetSignInAttemptsTableName renames the sign-in attempts table; the suite points
	// it at a table that is not there.
	SetSignInAttemptsTableName(name string) error
	SetUsernameIsEmail(same bool)
	UserByEmail(ctx context.Context, email string) (*dbtype.SessionUser, error)
	SetUserEmail(ctx context.Context, id ccc.UUID, email *string) error
	SetUserUsername(ctx context.Context, id ccc.UUID, newUsername string) error
	VerifyUserEmail(ctx context.Context, id ccc.UUID, email string) error
	ClaimVerifiedEmail(ctx context.Context, id ccc.UUID, email string) (bool, error)
	InsertMailLink(ctx context.Context, l *dbtype.MailLink) error
	MailLinkByToken(ctx context.Context, tokenHash []byte, now time.Time) (*dbtype.MailLink, error)
	LiveMailLinks(ctx context.Context, kind dbtype.MailLinkKind, now time.Time) ([]*dbtype.MailLink, error)
	ConsumeMailLink(ctx context.Context, tokenHash []byte, now time.Time) error
	RevokeMailLink(ctx context.Context, id ccc.UUID, now time.Time) error
}

// AuthSchema names the migration set an users database is prepared with.
type AuthSchema int

const (
	// LegacySessions is the shipped sessions schema (Sessions, SessionUsers) and the
	// impersonation migration, without the auth migrations. It lacks
	// Sessions.UserId and AuthenticatedAt and the identities and auth events tables.
	LegacySessions AuthSchema = iota
	// Auth is the shipped sessions schema, the impersonation migration and the
	// auth migrations.
	Auth
	// AuthWithAppTables is Auth plus the driver package's test-only application
	// tables: HookRecords, which hooks use through HookTx, and SessionCustomData for
	// CustomStringData.
	AuthWithAppTables
	// AuthFromOIDC is a legacy Azure group (the oidc set and the impersonation
	// migration) with the user anchor seeded by the driver package's test data
	// (two anchored users, old@lakeside.edu and other@lakeside.edu, under the ids
	// AnchoredOld and AnchoredOther, and a live session SeededLegacySession of
	// old@lakeside.edu), upgraded by the shipped auth-from-oidc set.
	AuthFromOIDC
	// AuthUsernameIsEmail is AuthWithAppTables with the users table in the shape of an
	// application whose usernames are email addresses: the address columns are
	// generated from the username by the driver package's test data, as the README
	// gives the DDL. The driver is configured with SetUsernameIsEmail.
	AuthUsernameIsEmail
)

// The anchor rows the AuthFromOIDC schema is seeded with.
var (
	AnchoredOld          = ccc.Must(ccc.UUIDFromString("11111111-2222-3333-4444-555555555555"))
	AnchoredOther        = ccc.Must(ccc.UUIDFromString("66666666-7777-8888-9999-aaaaaaaaaaaa"))
	SeededLegacySession  = ccc.Must(ccc.UUIDFromString("bbbbbbbb-cccc-dddd-eeee-ffffffffffff"))
	anchoredOldIdentity  = &sessioninfo.Identity{Method: sessioninfo.MethodAzure, Connection: "tid-1", Subject: "oid-old", Email: "old@lakeside.edu"}
	anchoredOtherSubject = "oid-other"
)

// HookTx is an application hook's view of its transaction, adapted by each harness to
// its backend. It stands in for the application rows a user resolver, sign-in
// policy or custom session data resolver writes and reads. It needs the
// AuthWithAppTables schema.
type HookTx interface {
	// Record writes key=value to the HookRecords table.
	Record(ctx context.Context, key, value string) error
	// Recorded reads key from HookRecords; found is false when it is absent.
	Recorded(ctx context.Context, key string) (value string, found bool, err error)
	// UserExists reports whether the SessionUsers row userID exists.
	UserExists(ctx context.Context, userID ccc.UUID) (bool, error)
}

// AuthConfig selects how a driver over a prepared users database is configured.
type AuthConfig struct {
	// Auth enables the Sessions.UserId and AuthenticatedAt columns.
	Auth bool
	// AuthEvents attaches the SessionAuthEvents table.
	AuthEvents bool
	// Impersonation attaches the SessionImpersonations table.
	Impersonation bool
	// Resolve is the custom account rule the instance's SignIn runs with, which the
	// harness adapts to the driver's transaction. Nil with no Accounts rejects every
	// unlinked identity.
	Resolve func(ctx context.Context, tx HookTx, req *sessioninfo.NewSessionRequest) (*signin.Resolution, error)
	// Accounts is the standard account rule the instance's SignIn runs with, applied
	// when Resolve is nil or answers signin.Standard; "" for none.
	Accounts signin.StandardAccountRule
	// Policy is the sign-in policy the instance's SignIn runs with; nil allows.
	Policy func(ctx context.Context, tx HookTx, req *sessioninfo.NewSessionRequest) (*signin.Decision, error)
	// CustomData, when set, attaches the AuthWithAppTables schema's
	// SessionCustomData table (CustomStringData) with CustomData as its resolver.
	CustomData func(ctx context.Context, tx HookTx, req *sessioninfo.NewSessionRequest) (any, error)
	// Accept is the invitation acceptor the instance's SignIn runs with, once the
	// transaction that consumed an invitation the sign-in carries has committed,
	// outside any transaction; nil for none.
	Accept signinflow.InvitationAcceptor
}

// AuthInstance is a driver over a freshly prepared users database, with the
// harness's own handle on that database.
type AuthInstance struct {
	Driver AuthDriver
	Raw    any
	// SignIn establishes the session of a request that carries a verified identity:
	// the sign-in flow over the driver with the configured resolver and policy, as the
	// Auth session runs it. The harness builds it with NewSignIn.
	SignIn func(ctx context.Context, insert *dbtype.InsertSession, req *sessioninfo.NewSessionRequest) (ccc.UUID, error)
	// Accept accepts inv for userID by hand, as the Auth does for a person already
	// signed in, with the configured acceptor. The harness builds it with NewAccept.
	Accept func(ctx context.Context, userID ccc.UUID, username string, inv *sessioninfo.Invitation) error
}

// NewAccept returns an instance's Accept over d: the flow's acceptance with cfg's
// acceptor.
func NewAccept[Tx any](d signinflow.Driver[Tx], cfg AuthConfig) func(ctx context.Context, userID ccc.UUID, username string, inv *sessioninfo.Invitation) error {
	return func(ctx context.Context, userID ccc.UUID, username string, inv *sessioninfo.Invitation) error {
		if err := signinflow.AcceptInvitation(ctx, d, userID, username, inv, cfg.Accept); err != nil {
			return errors.Wrap(err, "signinflow.AcceptInvitation()")
		}

		return nil
	}
}

// NewSignIn returns an instance's SignIn over d: the sign-in flow with cfg's account
// rules and policy, each given the driver's transaction through adapt.
func NewSignIn[Tx any](
	d signinflow.Driver[Tx], cfg AuthConfig, adapt func(tx Tx) HookTx,
) func(ctx context.Context, insert *dbtype.InsertSession, req *sessioninfo.NewSessionRequest) (ccc.UUID, error) {
	var rule signin.AccountRule[Tx]
	switch {
	case cfg.Resolve != nil:
		rule = func(ctx context.Context, tx Tx, req *sessioninfo.NewSessionRequest) (*signin.Resolution, error) {
			return cfg.Resolve(ctx, adapt(tx), req)
		}
	case cfg.Accounts == "":
		// No rule at all rejects every unlinked identity, as a nil resolution does.
		rule = func(context.Context, Tx, *sessioninfo.NewSessionRequest) (*signin.Resolution, error) { return nil, nil }
	}
	var policy signin.Policy[Tx]
	if cfg.Policy != nil {
		policy = func(ctx context.Context, tx Tx, req *sessioninfo.NewSessionRequest) (*signin.Decision, error) {
			return cfg.Policy(ctx, adapt(tx), req)
		}
	}
	return func(ctx context.Context, insert *dbtype.InsertSession, req *sessioninfo.NewSessionRequest) (ccc.UUID, error) {
		id, err := ccc.NewUUID()
		if err != nil {
			return ccc.NilUUID, errors.Wrap(err, "ccc.NewUUID()")
		}
		rules := signinflow.Rules[Tx]{Account: rule, Standard: cfg.Accounts, Policy: policy, Accept: cfg.Accept}
		if err := signinflow.SignIn(ctx, d, id, insert, req, rules); err != nil {
			return ccc.NilUUID, errors.Wrap(err, "signinflow.SignIn()")
		}

		return id, nil
	}
}

// AuthHarness adapts one driver package to the users suite.
type AuthHarness struct {
	// New prepares a fresh database with schema and returns a driver configured per cfg.
	New func(ctx context.Context, t *testing.T, schema AuthSchema, cfg AuthConfig) *AuthInstance
	// CountAuthEvents counts the session's rows in SessionAuthEvents directly.
	CountAuthEvents func(ctx context.Context, t *testing.T, raw any, sessionID ccc.UUID) int
	// DeleteSession deletes the session row directly, bypassing the driver.
	DeleteSession func(ctx context.Context, t *testing.T, raw any, sessionID ccc.UUID)
	// Recorded reads key from the HookRecords table directly, as committed.
	Recorded func(ctx context.Context, t *testing.T, raw any, key string) (value string, found bool)
	// Record writes key=value to the HookRecords table directly, bypassing the driver:
	// a row the application's hooks then read in a sign-in's transaction.
	Record func(ctx context.Context, t *testing.T, raw any, key, value string)
	// PendingConsumedAt reads the ConsumedAt of the pending sign-in holding tokenHash
	// directly: nil while it is live.
	PendingConsumedAt func(ctx context.Context, t *testing.T, raw any, tokenHash []byte) *time.Time
	// MailLinkConsumedAt reads the ConsumedAt of the mail link holding tokenHash
	// directly: nil while it is live.
	MailLinkConsumedAt func(ctx context.Context, t *testing.T, raw any, tokenHash []byte) *time.Time
	// ClockLead is how far the backend's clock may run ahead of the host's; see
	// Harness.ClockLead.
	ClockLead time.Duration
}

// RunAuth runs the users conformance suite against h. Every case prepares its
// own database and runs in parallel.
func RunAuth(t *testing.T, h *AuthHarness) {
	t.Helper()

	tests := []struct {
		name string
		run  func(ctx context.Context, t *testing.T, h *AuthHarness)
	}{
		{name: "a legacy schema keeps working: the user columns and events are never named", run: testLegacySchemaUnchanged},
		{name: "user sessions record and read UserId and AuthenticatedAt", run: testSessionUserColumns},
		{name: "the first auth event is the sign-in method, read with the session", run: testInitialAuthEvent},
		{name: "a session insert records every auth event it carries, in order, in one write", run: testInitialAuthEvents},
		{name: "an impersonated session records its user and an impersonation event naming the actor", run: testImpersonatedSessionUser},
		{name: "a session's auth events go with it", run: testAuthEventsCascade},
		{name: "a linked identity signs in to its user without the resolver", run: testLinkedIdentitySignsIn},
		{name: "the resolver's outcome decides an unlinked identity", run: testResolverOutcomes},
		{name: "the standard account rules decide an unlinked identity by its sign-in name", run: testStandardAccountRules},
		{name: "a custom account rule runs first and may leave the identity to the standard rule", run: testCustomRuleBeforeStandardRule},
		{name: "the standard rule runs once: a linked identity signs in by its link, and the username is not renamed", run: testStandardRuleRunsOnce},
		{name: "an untrusted link from another connection to a password-less user is refused; the same connection or a trusted link links", run: testLinkAcrossConnections},
		{name: "concurrent untrusted links from two connections to a password-less user link exactly one", run: testConcurrentCrossConnectionLinks},
		{name: "the sign-in policy decides after the user is known", run: testSignInPolicy},
		{name: "a disabled user is refused", run: testDisabledUserRefused},
		{name: "a rejected sign-in keeps the user resolver's own writes", run: testRejectionKeepsResolverWrites},
		{name: "a denied or held sign-in keeps the sign-in policy's own writes", run: testHeldOrRefusedKeepsHookWrites},
		{name: "the policy of a provisioning sign-in reads the new user and the rows OnProvisioned wrote, and knows it was provisioned", run: testPolicySeesProvisionedUser},
		{name: "the custom session data resolver of a provisioning sign-in reads the new user and knows it was provisioned", run: testCustomDataSeesProvisionedUser},
		{name: "a sign-in reports the user it resolved to and how", run: testSignInUserReported},
		{name: "the tenant policy decides a sign-in by the person's memberships and the declarations their tenants make, read in the sign-in's transaction", run: testTenantPolicy},
		{name: "a provisioned username that is taken is refused as a conflict, and nothing is linked", run: testProvisionUsernameTaken},
		{name: "concurrent first sign-ins of one identity link it once", run: testConcurrentFirstSignIn},
		{name: "concurrent first sign-ins of one identity through a provisioning resolver all succeed and provision it once", run: testConcurrentFirstProvision},
		{name: "links are managed outside sign-in, and the last means of sign-in stays", run: testLinkManagement},
		{name: "deleting a user deletes its identity links with it", run: testDeleteUserDeletesLinks},
		{name: "DestroyUserSessions expires the user's sessions by UserId", run: testDestroyUserSessions},
		{name: "AppendAuthEvent records a step-up after the sign-in", run: testAppendAuthEvent},
		{name: "a pending sign-in is read back by its token hash with everything it carried", run: testPendingSignInRoundTrip},
		{name: "a pending sign-in is consumed once, by a conditional update", run: testPendingSignInConsumedOnce},
		{name: "an expired pending sign-in is neither read nor consumed", run: testPendingSignInExpired},
		{name: "concurrent completions of one pending sign-in consume it once", run: testPendingSignInConcurrentConsume},
		{name: "deleting a user deletes its sessions, their auth events and its identity links by the schema's cascade", run: testDeleteUserCascades},
		{name: "a session row names an existing user or no user: the schema refuses an unknown user id", run: testSessionUserForeignKey},
		{name: "the upgrade from the legacy Azure layout keeps the anchor's users and identities under their ids, gives live sessions their user, and serves Auth", run: testUpgradeFromOIDC},
		{name: "a sign-in records the provider's session id under its issuer, and a provider-initiated logout ends the sessions under that issuer and id and no other", run: testProviderSessionLogout},
		{name: "a sign-in and everything written with it take the database's time, once", run: testDatabaseTimeOnSignIn},
		{name: "a user is stored with its password change mark and the database's time, and listed by username", run: testUserAccounts},
		{name: "a password is set with its change mark in one write", run: testUserPasswordSet},
		{name: "a user's last sign-in is the database's time at the touch after a sign-in, nil before the first", run: testUserLastSignIn},
		{name: "a revocation stamps every session it expires and every record it ends with one time, the database's", run: testDatabaseTimeOnRevocation},
		{name: "a failed sign-in attempt is recorded under the name, known or not, counted in its window and locked at the limit, at the database's time", run: testSignInAttemptsRecorded},
		{name: "a failed sign-in attempt after the window ended or the lock passed opens a new window", run: testSignInAttemptsWindowAndLockPass},
		{name: "a clear deletes the name's sign-in attempts and the count starts over", run: testSignInAttemptsCleared},
		{name: "concurrent failed sign-in attempts on one name each count", run: testSignInAttemptsConcurrent},
		{name: "a driver whose sign-in attempts table is not there says so: an error naming the table, never a count of nothing", run: testSignInAttemptsMissingTable},
		{name: "a user's email address is stored in two states, unique among every address held, and read back with the user", run: testUserEmail},
		{name: "a verified address replaces what the user held, at the database's time; an address another user holds is refused", run: testUserEmailVerified},
		{name: "a sign-in refused or held before the acceptance leaves the invitation standing, nothing consumed and nothing granted", run: testInvitationKeptOnRefusal},
		{name: "a method's verified address is claimed for a user without one, once, and never over another user's", run: testClaimVerifiedEmail},
		{name: "where the username is the address, the database derives the address, a rename is refused and a verified address renames the user", run: testUsernameIsEmail},
		{name: "a mail link is read back by its token hash with everything it carried", run: testMailLinkRoundTrip},
		{name: "a mail link is consumed once, by token or by id, and listed while it stands", run: testMailLinkConsumedOnce},
		{name: "an expired mail link is neither read, consumed nor listed", run: testMailLinkExpired},
		{name: "a verification link goes with its user", run: testMailLinkCascade},
		{name: "a sign-in that carries an invitation accepts it in the resolution's transaction: consumed, the address set, the hook's writes committed with the user", run: testInvitationSignIn},
		{name: "an invitation that died is skipped by a member's sign-in and refuses an invited-only one, provisioning nothing", run: testInvitationDead},
		{name: "a failing invitation hook ends the sign-in and leaves the invitation and the user untouched", run: testInvitationHookFails},
		{name: "a password sign-in accepts the invitation it carries in a transaction of its own, and so does an acceptance by hand", run: testInvitationAcceptedByHand},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			tt.run(t.Context(), t, h)
		})
	}
}

// newInsertSession is a fresh session row for username. Its times are the driver's.
func newInsertSession(username string) *dbtype.InsertSession {
	return &dbtype.InsertSession{Username: username}
}

// createUser creates a user, with a password hash when withPassword.
func createUser(ctx context.Context, t *testing.T, d AuthDriver, username string) *dbtype.SessionUser {
	t.Helper()

	user, err := d.CreateUser(ctx, &dbtype.InsertSessionUser{Username: username}, nil)
	if err != nil {
		t.Fatalf("CreateUser(%q) error = %v", username, err)
	}

	return user
}

func mustSession(ctx context.Context, t *testing.T, d AuthDriver, id ccc.UUID) *dbtype.SessionData {
	t.Helper()

	sess, err := d.Session(ctx, id)
	if err != nil {
		t.Fatalf("Session() error = %v", err)
	}

	return sess
}

// eventsOpts compares auth events, nil and empty slices alike. Times are compared
// exactly: an event's time is the database's, read with the session, or a caller's,
// stored as given.
var eventsOpts = cmp.Options{cmpopts.EquateEmpty()}

func testLegacySchemaUnchanged(ctx context.Context, t *testing.T, h *AuthHarness) {
	in := h.New(ctx, t, LegacySessions, AuthConfig{Impersonation: true})
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
		&dbtype.InsertImpersonation{ActorUsername: "actor", PrincipalKind: dbtype.PrincipalKindUser, PrincipalUser: strPtr(user.Username), ExpiresAt: time.Now().Add(time.Hour)})
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

func testSessionUserColumns(ctx context.Context, t *testing.T, h *AuthHarness) {
	in := h.New(ctx, t, Auth, AuthConfig{Auth: true})
	user := createUser(ctx, t, in.Driver, "user@example.com")

	tests := []struct {
		name              string
		req               *sessioninfo.NewSessionRequest
		wantUserID        ccc.NullUUID
		wantAuthenticated bool
	}{
		{
			name:              "a login records the user and when it authenticated",
			req:               &sessioninfo.NewSessionRequest{Reason: sessioninfo.ReasonLogin, Username: user.Username, UserID: user.ID},
			wantUserID:        ccc.NullUUIDFromUUID(user.ID),
			wantAuthenticated: true,
		},
		{
			name: "a preauth stepping stone has no user and authenticated nothing",
			req:  &sessioninfo.NewSessionRequest{Reason: sessioninfo.ReasonPreauth, Username: "stepping-stone"},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			id, err := in.Driver.InsertSession(ctx, newInsertSession(tt.req.Username), tt.req)
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
			if tt.wantAuthenticated {
				assertSameTime(t, "Session().AuthenticatedAt", *sess.AuthenticatedAt, sess.CreatedAt)
			}
			if len(sess.AuthEvents) != 0 {
				t.Errorf("Session().AuthEvents = %v, want none without an auth events table", sess.AuthEvents)
			}
		})
	}
}

func testInitialAuthEvent(ctx context.Context, t *testing.T, h *AuthHarness) {
	in := h.New(ctx, t, Auth, AuthConfig{Auth: true, AuthEvents: true})
	user := createUser(ctx, t, in.Driver, "events@example.com")

	tests := []struct {
		name       string
		identity   *sessioninfo.Identity
		wantEvents []sessioninfo.AuthEvent
	}{
		{
			name:     "a password sign-in records the password method",
			identity: &sessioninfo.Identity{Method: sessioninfo.MethodPassword, Subject: user.ID.String(), IDPAMR: []string{"pwd"}},
			wantEvents: []sessioninfo.AuthEvent{
				{Method: sessioninfo.MethodPassword, IDPAMR: []string{"pwd"}},
			},
		},
		{
			name: "a session without an identity records no event",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			id, err := in.Driver.InsertSession(ctx, newInsertSession(user.Username), &sessioninfo.NewSessionRequest{Reason: sessioninfo.ReasonLogin, Username: user.Username, UserID: user.ID, Identity: tt.identity})
			if err != nil {
				t.Fatalf("InsertSession() error = %v", err)
			}

			sess := mustSession(ctx, t, in.Driver, id)
			for i := range tt.wantEvents {
				tt.wantEvents[i].At = sess.CreatedAt
			}
			if diff := cmp.Diff(tt.wantEvents, sess.AuthEvents, eventsOpts); diff != "" {
				t.Errorf("Session().AuthEvents mismatch (-want +got):\n%s", diff)
			}
		})
	}
}

func testInitialAuthEvents(ctx context.Context, t *testing.T, h *AuthHarness) {
	signedInAt := time.Now().Add(-time.Hour).Truncate(time.Second)

	tests := []struct {
		name       string
		cfg        AuthConfig
		identity   func(user *dbtype.SessionUser) *sessioninfo.Identity
		events     []sessioninfo.AuthEvent
		wantEvents []sessioninfo.AuthEvent
	}{
		{
			name: "a step-up completion records the sign-in and the step-up, keeping the sign-in's time",
			cfg:  AuthConfig{Auth: true, AuthEvents: true},
			identity: func(user *dbtype.SessionUser) *sessioninfo.Identity {
				return &sessioninfo.Identity{Method: sessioninfo.MethodPassword, Subject: user.ID.String()}
			},
			events: []sessioninfo.AuthEvent{
				{Method: sessioninfo.MethodPassword, At: signedInAt},
				{Method: "email-otp"},
			},
			wantEvents: []sessioninfo.AuthEvent{
				{Method: sessioninfo.MethodPassword, At: signedInAt},
				{Method: "email-otp"},
			},
		},
		{
			name: "an identity resolved in the session transaction records the events it carries",
			cfg:  AuthConfig{Auth: true, AuthEvents: true},
			identity: func(user *dbtype.SessionUser) *sessioninfo.Identity {
				return &sessioninfo.Identity{Method: sessioninfo.MethodPassword, Subject: user.ID.String()}
			},
			events: []sessioninfo.AuthEvent{
				{Method: sessioninfo.MethodPassword},
				{Method: sessioninfo.MethodLinkConfirmation},
				{Method: "email-otp", IDPAMR: []string{"otp"}},
			},
			wantEvents: []sessioninfo.AuthEvent{
				{Method: sessioninfo.MethodPassword},
				{Method: sessioninfo.MethodLinkConfirmation},
				{Method: "email-otp", IDPAMR: []string{"otp"}},
			},
		},
		{
			name:   "a session started by the application records the events it was given, with no identity",
			cfg:    AuthConfig{Auth: true, AuthEvents: true},
			events: []sessioninfo.AuthEvent{{Method: "magic-link", Connection: "app"}},
			wantEvents: []sessioninfo.AuthEvent{
				{Method: "magic-link", Connection: "app"},
			},
		},
	}
	for i := range tests {
		tt := &tests[i]
		t.Run(tt.name, func(t *testing.T) {
			in := h.New(ctx, t, Auth, tt.cfg)
			user := createUser(ctx, t, in.Driver, "steps@example.com")

			req := &sessioninfo.NewSessionRequest{Reason: sessioninfo.ReasonStepUp, Username: user.Username, UserID: user.ID, AuthEvents: tt.events}
			if tt.identity != nil {
				req.Identity = tt.identity(user)
			}
			id, err := in.Driver.InsertSession(ctx, newInsertSession(user.Username), req)
			if err != nil {
				t.Fatalf("InsertSession() error = %v", err)
			}

			// An event without a time takes the session's creation time; one with a
			// time keeps it.
			sess := mustSession(ctx, t, in.Driver, id)
			for i := range tt.wantEvents {
				if tt.wantEvents[i].At.IsZero() {
					tt.wantEvents[i].At = sess.CreatedAt
				}
			}
			if diff := cmp.Diff(tt.wantEvents, sess.AuthEvents, eventsOpts); diff != "" {
				t.Errorf("Session().AuthEvents mismatch (-want +got):\n%s", diff)
			}
			if got := h.CountAuthEvents(ctx, t, in.Raw, id); got != len(tt.wantEvents) {
				t.Errorf("auth event rows = %d, want %d", got, len(tt.wantEvents))
			}
		})
	}
}

func testImpersonatedSessionUser(ctx context.Context, t *testing.T, h *AuthHarness) {
	in := h.New(ctx, t, Auth, AuthConfig{Auth: true, AuthEvents: true, Impersonation: true})
	user := createUser(ctx, t, in.Driver, "bob@example.com")

	tests := []struct {
		name       string
		principal  accesstypes.Principal
		userID     ccc.UUID
		wantUserID ccc.NullUUID
	}{
		{
			name:       "a user principal's session belongs to the impersonated user",
			principal:  accesstypes.UserPrincipal(accesstypes.User(user.Username)),
			userID:     user.ID,
			wantUserID: ccc.NullUUIDFromUUID(user.ID),
		},
		{
			name:      "a role principal's session belongs to no user",
			principal: accesstypes.RolePrincipal(accesstypes.Role("Viewer")),
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			imp := dbtype.NewInsertImpersonation(&sessioninfo.Impersonation{Actor: "alice@example.com", Principal: tt.principal, ExpiresAt: time.Now().Add(time.Hour)})
			id, err := in.Driver.InsertImpersonatedSession(ctx, newInsertSession(user.Username), &sessioninfo.NewSessionRequest{Reason: sessioninfo.ReasonImpersonation, Username: user.Username, UserID: tt.userID}, imp)
			if err != nil {
				t.Fatalf("InsertImpersonatedSession() error = %v", err)
			}

			sess := mustSession(ctx, t, in.Driver, id)
			if sess.UserID != tt.wantUserID {
				t.Errorf("Session().UserID = %v, want %v", sess.UserID, tt.wantUserID)
			}
			want := []sessioninfo.AuthEvent{{Method: sessioninfo.MethodImpersonation, Connection: "alice@example.com", At: sess.CreatedAt}}
			if diff := cmp.Diff(want, sess.AuthEvents, eventsOpts); diff != "" {
				t.Errorf("Session().AuthEvents mismatch (-want +got):\n%s", diff)
			}
		})
	}
}

func testAuthEventsCascade(ctx context.Context, t *testing.T, h *AuthHarness) {
	in := h.New(ctx, t, Auth, AuthConfig{Auth: true, AuthEvents: true})
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
