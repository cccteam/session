package spanner

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/cccteam/ccc"
	"github.com/cccteam/session/internal/dbtype"
	"github.com/cccteam/session/sessioninfo"
)

// Every case runs the application clock an hour ahead: the driver's clock, and the
// insert timestamps the public layer would pass in. Spanner refuses a value later than
// its own clock in an allow_commit_timestamp column, so only writes that take the time
// from Spanner succeed.
func TestSessionStorageDriver_CommitTimestamps(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name             string
		commitTimestamps bool
		google           bool
		impersonation    bool
		sourceURL        []string
		write            func(ctx context.Context, d *SessionStorageDriver) error
		wantErrContains  string
		postAssertions   []string
	}{
		{
			name:             "InsertSession with commit timestamps ignores a clock that runs ahead",
			commitTimestamps: true,
			sourceURL: []string{
				"file://../../../schema/spanner/migrations",
				"file://testdata/sessions_test/commit_timestamps",
			},
			write: func(ctx context.Context, d *SessionStorageDriver) error {
				_, err := d.InsertSession(ctx, &dbtype.InsertSession{
					Username:  "ahead",
					CreatedAt: d.now(),
					UpdatedAt: d.now(),
				}, &sessioninfo.NewSessionRequest{Reason: sessioninfo.ReasonLogin, Username: "ahead"})

				return err
			},
			postAssertions: []string{
				`SELECT CreatedAt = UpdatedAt AND CreatedAt <= CURRENT_TIMESTAMP() FROM Sessions WHERE Username = 'ahead'`,
			},
		},
		{
			name: "InsertSession without commit timestamps fails when the clock runs ahead",
			sourceURL: []string{
				"file://../../../schema/spanner/migrations",
				"file://testdata/sessions_test/commit_timestamps",
			},
			write: func(ctx context.Context, d *SessionStorageDriver) error {
				_, err := d.InsertSession(ctx, &dbtype.InsertSession{
					Username:  "ahead",
					CreatedAt: d.now(),
					UpdatedAt: d.now(),
				}, &sessioninfo.NewSessionRequest{Reason: sessioninfo.ReasonLogin, Username: "ahead"})

				return err
			},
			wantErrContains: "in the future",
			postAssertions: []string{
				`SELECT COUNT(*) = 0 FROM Sessions WHERE Username = 'ahead'`,
			},
		},
		{
			name:             "InsertSessionOIDC with commit timestamps ignores a clock that runs ahead",
			commitTimestamps: true,
			sourceURL: []string{
				"file://../../../schema/spanner/oidc/migrations",
				"file://testdata/sessions_test/commit_timestamps",
			},
			write: func(ctx context.Context, d *SessionStorageDriver) error {
				_, err := d.InsertSessionOIDC(ctx, &dbtype.InsertOIDCSession{
					OidcSID: "00000000-0000-0000-0000-000000000001",
					InsertSession: dbtype.InsertSession{
						Username:  "ahead",
						CreatedAt: d.now(),
						UpdatedAt: d.now(),
					},
				}, &sessioninfo.NewSessionRequest{Reason: sessioninfo.ReasonLogin, Username: "ahead"})

				return err
			},
			postAssertions: []string{
				`SELECT CreatedAt = UpdatedAt AND CreatedAt <= CURRENT_TIMESTAMP() FROM Sessions WHERE Username = 'ahead'`,
			},
		},
		{
			name:             "UpdateSessionActivity with commit timestamps writes UpdatedAt",
			commitTimestamps: true,
			sourceURL: []string{
				"file://../../../schema/spanner/migrations",
				"file://testdata/sessions_test/commit_timestamps",
				"file://testdata/sessions_test/valid_sessions",
			},
			write: func(ctx context.Context, d *SessionStorageDriver) error {
				return d.UpdateSessionActivity(ctx, ccc.Must(ccc.UUIDFromString("38bd570b-1280-421b-888e-a63f0ca35be7")))
			},
			postAssertions: []string{
				`SELECT UpdatedAt > TIMESTAMP_SUB(CURRENT_TIMESTAMP(), INTERVAL 1 MINUTE) AND UpdatedAt <= CURRENT_TIMESTAMP() FROM Sessions WHERE Id = '38bd570b-1280-421b-888e-a63f0ca35be7'`,
			},
		},
		{
			name: "UpdateSessionActivity without commit timestamps fails when the clock runs ahead",
			sourceURL: []string{
				"file://../../../schema/spanner/migrations",
				"file://testdata/sessions_test/commit_timestamps",
				"file://testdata/sessions_test/valid_sessions",
			},
			write: func(ctx context.Context, d *SessionStorageDriver) error {
				return d.UpdateSessionActivity(ctx, ccc.Must(ccc.UUIDFromString("38bd570b-1280-421b-888e-a63f0ca35be7")))
			},
			wantErrContains: "in the future",
			postAssertions: []string{
				`SELECT UpdatedAt = '2020-01-02 08:05:03+00:00' FROM Sessions WHERE Id = '38bd570b-1280-421b-888e-a63f0ca35be7'`,
			},
		},
		{
			name: "DestroySession writes UpdatedAt from the Spanner clock",
			sourceURL: []string{
				"file://../../../schema/spanner/migrations",
				"file://testdata/sessions_test/commit_timestamps",
				"file://testdata/sessions_test/valid_sessions",
			},
			write: func(ctx context.Context, d *SessionStorageDriver) error {
				return d.DestroySession(ctx, ccc.Must(ccc.UUIDFromString("38bd570b-1280-421b-888e-a63f0ca35be7")))
			},
			postAssertions: []string{
				`SELECT Expired AND UpdatedAt > TIMESTAMP_SUB(CURRENT_TIMESTAMP(), INTERVAL 1 MINUTE) AND UpdatedAt <= CURRENT_TIMESTAMP() FROM Sessions WHERE Id = '38bd570b-1280-421b-888e-a63f0ca35be7'`,
			},
		},
		{
			name: "DestroyAllUserSessions writes UpdatedAt from the Spanner clock",
			sourceURL: []string{
				"file://../../../schema/spanner/migrations",
				"file://testdata/sessions_test/commit_timestamps",
				"file://testdata/sessions_test/valid_sessions",
			},
			write: func(ctx context.Context, d *SessionStorageDriver) error {
				return d.DestroyAllUserSessions(ctx, "test user 1")
			},
			postAssertions: []string{
				`SELECT COUNT(*) = 3 FROM Sessions WHERE Username = 'test user 1' AND Expired`,
				`SELECT COUNT(*) = 0 FROM Sessions WHERE Username = 'test user 1' AND NOT (UpdatedAt BETWEEN TIMESTAMP_SUB(CURRENT_TIMESTAMP(), INTERVAL 1 MINUTE) AND CURRENT_TIMESTAMP())`,
			},
		},
		{
			name: "SetUserUsername writes session UpdatedAt from the Spanner clock",
			sourceURL: []string{
				"file://../../../schema/spanner/migrations",
				"file://testdata/sessions_test/commit_timestamps",
				"file://testdata/users_test/valid_users",
				"file://testdata/sessions_test/user_sessions",
			},
			write: func(ctx context.Context, d *SessionStorageDriver) error {
				return d.SetUserUsername(ctx, ccc.Must(ccc.UUIDFromString("27b43588-b743-4133-8730-e0439065a844")), "renamed")
			},
			postAssertions: []string{
				`SELECT COUNT(*) = 2 FROM Sessions WHERE Username = 'renamed' AND UpdatedAt > TIMESTAMP_SUB(CURRENT_TIMESTAMP(), INTERVAL 1 MINUTE) AND UpdatedAt <= CURRENT_TIMESTAMP()`,
			},
		},
		{
			name:             "InsertSessionGoogleOIDC with commit timestamps ignores a clock that runs ahead",
			commitTimestamps: true,
			google:           true,
			sourceURL: []string{
				"file://../../../schema/spanner/oidc-google/migrations",
				"file://testdata/sessions_test/commit_timestamps",
			},
			write: func(ctx context.Context, d *SessionStorageDriver) error {
				_, err := d.InsertSessionGoogleOIDC(ctx, &dbtype.InsertSession{
					Username:  "ahead",
					CreatedAt: d.now(),
					UpdatedAt: d.now(),
				}, &sessioninfo.NewSessionRequest{Reason: sessioninfo.ReasonLogin, Username: "ahead"})

				return err
			},
			postAssertions: []string{
				`SELECT CreatedAt = UpdatedAt AND CreatedAt <= CURRENT_TIMESTAMP() FROM Sessions WHERE Username = 'ahead'`,
			},
		},
		{
			name:             "InsertImpersonatedSession with commit timestamps ignores a clock that runs ahead",
			commitTimestamps: true,
			impersonation:    true,
			sourceURL: []string{
				"file://../../../schema/spanner/migrations",
				"file://../../../schema/spanner/impersonation/migrations",
				"file://testdata/sessions_test/commit_timestamps",
			},
			write: func(ctx context.Context, d *SessionStorageDriver) error {
				_, err := d.InsertImpersonatedSession(ctx, &dbtype.InsertSession{
					Username:  "ahead",
					CreatedAt: d.now(),
					UpdatedAt: d.now(),
				}, &sessioninfo.NewSessionRequest{Reason: sessioninfo.ReasonLogin, Username: "ahead"}, &dbtype.InsertImpersonation{
					ActorUsername: "actor",
					PrincipalKind: dbtype.PrincipalKindUser,
					PrincipalUser: new("ahead"),
					StartedAt:     d.now(),
					ExpiresAt:     d.now().Add(time.Hour),
				})

				return err
			},
			postAssertions: []string{
				`SELECT CreatedAt = UpdatedAt AND CreatedAt <= CURRENT_TIMESTAMP() FROM Sessions WHERE Username = 'ahead'`,
			},
		},
		{
			name:             "InsertImpersonatedSessionOIDC with commit timestamps ignores a clock that runs ahead",
			commitTimestamps: true,
			impersonation:    true,
			sourceURL: []string{
				"file://../../../schema/spanner/oidc/migrations",
				"file://../../../schema/spanner/impersonation/migrations",
				"file://testdata/sessions_test/commit_timestamps",
			},
			write: func(ctx context.Context, d *SessionStorageDriver) error {
				_, err := d.InsertImpersonatedSessionOIDC(ctx, &dbtype.InsertOIDCSession{
					InsertSession: dbtype.InsertSession{
						Username:  "ahead",
						CreatedAt: d.now(),
						UpdatedAt: d.now(),
					},
				}, &sessioninfo.NewSessionRequest{Reason: sessioninfo.ReasonLogin, Username: "ahead"}, &dbtype.InsertImpersonation{
					ActorUsername: "actor",
					PrincipalKind: dbtype.PrincipalKindUser,
					PrincipalUser: new("ahead"),
					StartedAt:     d.now(),
					ExpiresAt:     d.now().Add(time.Hour),
				})

				return err
			},
			postAssertions: []string{
				`SELECT CreatedAt = UpdatedAt AND CreatedAt <= CURRENT_TIMESTAMP() FROM Sessions WHERE Username = 'ahead'`,
			},
		},
		{
			name:          "DestroyImpersonatedSession writes UpdatedAt from the Spanner clock",
			impersonation: true,
			sourceURL: []string{
				"file://testdata/sessions_test/impersonation_schema",
				"file://../../../schema/spanner/impersonation/migrations",
				"file://testdata/sessions_test/commit_timestamps",
				"file://testdata/sessions_test/impersonation_seed",
			},
			write: func(ctx context.Context, d *SessionStorageDriver) error {
				return d.DestroyImpersonatedSession(ctx, ccc.Must(ccc.UUIDFromString("11111111-1111-1111-1111-111111111111")), "Logout")
			},
			postAssertions: []string{
				`SELECT Expired AND UpdatedAt > TIMESTAMP_SUB(CURRENT_TIMESTAMP(), INTERVAL 1 MINUTE) AND UpdatedAt <= CURRENT_TIMESTAMP() FROM Sessions WHERE Id = '11111111-1111-1111-1111-111111111111'`,
			},
		},
		{
			name:          "DestroyImpersonatedSessions writes UpdatedAt from the Spanner clock",
			impersonation: true,
			sourceURL: []string{
				"file://testdata/sessions_test/impersonation_schema",
				"file://../../../schema/spanner/impersonation/migrations",
				"file://testdata/sessions_test/commit_timestamps",
				"file://testdata/sessions_test/impersonation_seed",
			},
			write: func(ctx context.Context, d *SessionStorageDriver) error {
				return d.DestroyImpersonatedSessions(ctx, "alice@example.com")
			},
			postAssertions: []string{
				`SELECT COUNT(*) = 2 FROM Sessions WHERE Id IN ('11111111-1111-1111-1111-111111111111', '44444444-4444-4444-4444-444444444444') AND Expired AND UpdatedAt > TIMESTAMP_SUB(CURRENT_TIMESTAMP(), INTERVAL 1 MINUTE) AND UpdatedAt <= CURRENT_TIMESTAMP()`,
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			ctx := t.Context()
			conn, err := prepareDatabase(ctx, t, tt.sourceURL...)
			if err != nil {
				t.Fatalf("prepareDatabase() error = %v", err)
			}
			d := NewSessionStorageDriver(conn.Client)
			if tt.google {
				d = NewGoogleSessionStorageDriver(conn.Client)
			}
			if tt.impersonation {
				d.SetImpersonation(&ImpersonationConfig{TableName: "SessionImpersonations"})
			}
			d.now = func() time.Time { return time.Now().Add(time.Hour) }
			if tt.commitTimestamps {
				d.EnableCommitTimestamps()
			}

			err = tt.write(ctx, d)
			switch {
			case tt.wantErrContains == "" && err != nil:
				t.Fatalf("write error = %v, want nil", err)
			case tt.wantErrContains != "" && (err == nil || !strings.Contains(err.Error(), tt.wantErrContains)):
				t.Fatalf("write error = %v, want one containing %q", err, tt.wantErrContains)
			}
			runAssertions(ctx, t, conn.Client, tt.postAssertions)
		})
	}
}
