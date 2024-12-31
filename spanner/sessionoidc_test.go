package spanner

import (
	"context"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/cccteam/ccc"
	"github.com/cccteam/session/dbtype"
	"github.com/google/go-cmp/cmp"
)

func Test_client_SessionOIDC(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name      string
		sessionID ccc.UUID
		sourceURL []string
		want      *dbtype.SessionOIDC
		wantErr   bool
	}{
		{
			name:      "fails to get session",
			sessionID: ccc.Must(ccc.UUIDFromString("eb0c72a4-1f32-469e-b51b-7baa589a944c")),
			wantErr:   true,
		},
		{
			name:      "fails to find session",
			sessionID: ccc.Must(ccc.UUIDFromString("5f5d3b2c-5fd0-4d07-aec7-bba3d951b11e")),
			sourceURL: []string{"file://../schema/spanner/oidc/migrations", "file://testdata/sessions_test/valid_sessions"},
			wantErr:   true,
		},
		{
			name:      "success getting session",
			sessionID: ccc.Must(ccc.UUIDFromString("eb0c72a4-1f32-469e-b51b-7baa589a944c")),
			sourceURL: []string{"file://../schema/spanner/oidc/migrations", "file://testdata/sessions_test/valid_sessions"},
			want: &dbtype.SessionOIDC{
				OidcSID: "eb0c72a4-1f32-469e-b51b-7baa589a944c",
				Session: dbtype.Session{
					ID:        ccc.Must(ccc.UUIDFromString("eb0c72a4-1f32-469e-b51b-7baa589a944c")),
					Username:  "test user 2",
					CreatedAt: time.Date(2018, 5, 3, 1, 2, 3, 0, time.UTC),
					UpdatedAt: time.Date(2017, 6, 4, 3, 2, 1, 0, time.UTC),
					Expired:   true,
				},
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			ctx := context.Background()
			conn, err := prepareDatabase(ctx, t, tt.sourceURL...)
			if err != nil {
				t.Fatalf("prepareDatabase() error = %v, wantErr %v", err, false)
			}
			c := &SessionStorageDriver{spanner: conn.Client}

			got, err := c.SessionOIDC(ctx, tt.sessionID)
			if (err != nil) != tt.wantErr {
				t.Errorf("client.Session() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if diff := cmp.Diff(tt.want, got); diff != "" {
				t.Errorf("client.Session() mismatch (-want +got):\n%s", diff)
			}
		})
	}
}

func Test_client_InsertSessionOIDC(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name           string
		insertSession  *dbtype.InsertSessionOIDC
		sourceURL      []string
		wantErr        bool
		preAssertions  []string
		postAssertions []string
	}{
		{
			name: "fails to create session (invalid schema)",
			insertSession: &dbtype.InsertSessionOIDC{
				OidcSID: "oidc session 2",
				InsertSession: dbtype.InsertSession{
					Username:  "test user 2",
					CreatedAt: time.Date(2018, 5, 3, 1, 2, 3, 0, time.UTC),
					UpdatedAt: time.Date(2017, 6, 4, 3, 2, 1, 0, time.UTC),
					Expired:   true,
				},
			},
			sourceURL: []string{"file://testdata/sessions_test/invalid_schema"},
			wantErr:   true,
		},
		{
			name: "success creating session",
			insertSession: &dbtype.InsertSessionOIDC{
				OidcSID: "oidc session 2",
				InsertSession: dbtype.InsertSession{
					Username:  "test user 2",
					CreatedAt: time.Date(2018, 5, 3, 1, 2, 3, 0, time.UTC),
					UpdatedAt: time.Date(2017, 6, 4, 3, 2, 1, 0, time.UTC),
					Expired:   true,
				},
			},
			sourceURL: []string{"file://../schema/spanner/oidc/migrations", "file://testdata/sessions_test/valid_sessions"},
			preAssertions: []string{
				`SELECT COUNT(*) = 2 FROM Sessions WHERE username = 'test user 2'`,
				`SELECT COUNT(*) = 0 FROM Sessions WHERE Username = 'test user 2' AND OidcSid = 'random'`,
			},
			postAssertions: []string{
				`SELECT COUNT(*) = 3 FROM Sessions WHERE username = 'test user 2'`,
				`
				SELECT COUNT(*) = 1 FROM Sessions 
				WHERE Id = '%s'
					AND Username = 'test user 2'
					AND OidcSid = 'oidc session 2'
					AND CreatedAt = TIMESTAMP '2018-05-03 01:02:03 UTC'
					AND UpdatedAt = TIMESTAMP '2017-06-04 03:02:01 UTC'
					AND Expired = true`,
			},
			wantErr: false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			ctx := context.Background()
			conn, err := prepareDatabase(ctx, t, tt.sourceURL...)
			if err != nil {
				t.Fatalf("prepareDatabase() error = %v, wantErr %v", err, false)
			}
			c := &SessionStorageDriver{spanner: conn.Client}

			runAssertions(ctx, t, conn.Client, tt.preAssertions)

			got, err := c.InsertSessionOIDC(ctx, tt.insertSession)
			if err != nil != tt.wantErr {
				t.Errorf("client.InsertSession() error = %v, wantErr %v", err, tt.wantErr)
				return
			}

			for i, query := range tt.postAssertions {
				if strings.Contains(query, "%s") {
					tt.postAssertions[i] = fmt.Sprintf(query, got.String())
				}
			}

			runAssertions(ctx, t, conn.Client, tt.postAssertions)
		})
	}
}

func Test_client_UpdateSessionActivity(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name      string
		sessionID ccc.UUID
		sourceURL []string
		wantErr   bool
	}{
		{
			name:      "fails to update session activity (invalid schema)",
			sessionID: ccc.Must(ccc.UUIDFromString("eb0c72a4-1f32-469e-b51b-7baa589a944c")),
			sourceURL: []string{"file://testdata/sessions_test/invalid_schema"},
			wantErr:   true,
		},
		{
			name:      "fails to find session",
			sessionID: ccc.Must(ccc.UUIDFromString("ed0c72a4-1f32-469e-b51b-7baa589a945c")),
			sourceURL: []string{"file://../schema/spanner/oidc/migrations", "file://testdata/sessions_test/valid_sessions"},
			wantErr:   true,
		},
		{
			name:      "success updating session activity",
			sessionID: ccc.Must(ccc.UUIDFromString("eb0c72a4-1f32-469e-b51b-7baa589a944c")),
			sourceURL: []string{"file://../schema/spanner/oidc/migrations", "file://testdata/sessions_test/valid_sessions"},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			ctx := context.Background()
			conn, err := prepareDatabase(ctx, t, tt.sourceURL...)
			if err != nil {
				t.Fatalf("prepareDatabase() error = %v, wantErr %v", err, false)
			}
			c := &SessionStorageDriver{spanner: conn.Client}

			preExecTime := time.Now()
			if !tt.wantErr {
				runAssertions(ctx, t, conn.Client, []string{fmt.Sprintf(`SELECT UpdatedAt < '%s' FROM Sessions WHERE  Id = '%s'`, preExecTime.Format(time.RFC3339), tt.sessionID)})
			}
			if err := c.UpdateSessionActivity(ctx, tt.sessionID); (err != nil) != tt.wantErr {
				t.Errorf("client.UpdateSessionActivity() error = %v, wantErr %v", err, tt.wantErr)
			}
			if !tt.wantErr {
				runAssertions(ctx, t, conn.Client, []string{fmt.Sprintf(`SELECT UpdatedAt > '%s' FROM Sessions WHERE  Id = '%s'`, preExecTime.Format(time.RFC3339), tt.sessionID)})
			}
		})
	}
}

func Test_client_DestroySession(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name           string
		sessionID      ccc.UUID
		sourceURL      []string
		wantErr        bool
		preAssertions  []string
		postAssertions []string
	}{
		{
			name:      "fails to destroy session (invalid schema)",
			sessionID: ccc.Must(ccc.UUIDFromString("38bd570b-1280-421b-888e-a63f0ca35be7")),
			sourceURL: []string{"file://testdata/sessions_test/invalid_schema"},
			wantErr:   true,
		},
		{
			name:      "success without destroying the session (not found)",
			sessionID: ccc.Must(ccc.UUIDFromString("52dd570b-1280-421b-888e-a63f0ca35be9")),
			sourceURL: []string{"file://../schema/spanner/oidc/migrations", "file://testdata/sessions_test/valid_sessions"},
			preAssertions: []string{
				`SELECT COUNT(*) = 3 FROM Sessions WHERE Expired = false`,
				`SELECT COUNT(*) = 0 FROM Sessions WHERE Id = 'session1'`,
			},
			postAssertions: []string{
				`SELECT COUNT(*) = 3 FROM Sessions WHERE Expired = false`,
			},
		},
		{
			name:      "success destroying session",
			sessionID: ccc.Must(ccc.UUIDFromString("38bd570b-1280-421b-888e-a63f0ca35be7")),
			sourceURL: []string{"file://../schema/spanner/oidc/migrations", "file://testdata/sessions_test/valid_sessions"},
			preAssertions: []string{
				`SELECT Expired = false FROM Sessions WHERE Id = '38bd570b-1280-421b-888e-a63f0ca35be7'`,
			},
			postAssertions: []string{
				`SELECT Expired = true FROM Sessions WHERE Id = '38bd570b-1280-421b-888e-a63f0ca35be7'`,
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			ctx := context.Background()
			conn, err := prepareDatabase(ctx, t, tt.sourceURL...)
			if err != nil {
				t.Fatalf("prepareDatabase() error = %v, wantErr %v", err, false)
			}
			c := &SessionStorageDriver{spanner: conn.Client}

			runAssertions(ctx, t, conn.Client, tt.preAssertions)
			if err := c.DestroySession(ctx, tt.sessionID); (err != nil) != tt.wantErr {
				t.Errorf("client.DestroySession() error = %v, wantErr %v", err, tt.wantErr)
			}
			runAssertions(ctx, t, conn.Client, tt.postAssertions)
		})
	}
}

func Test_client_DestroySessionOIDC(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name           string
		oidcSID        string
		sourceURL      []string
		wantErr        bool
		preAssertions  []string
		postAssertions []string
	}{
		{
			name:    "fails to destroy session",
			oidcSID: "38bd570b-1280-421b-888e-a63f0ca35be7",
			wantErr: true,
		},
		{
			name:      "success without destroying sessions",
			oidcSID:   "oidc session4",
			sourceURL: []string{"file://../schema/spanner/oidc/migrations", "file://testdata/sessions_test/valid_sessions"},
			preAssertions: []string{
				`SELECT COUNT(*) = 0 FROM Sessions WHERE OidcSid = 'oidc session4'`,
				`SELECT COUNT(*) = 3 FROM Sessions WHERE Expired = false`,
			},
			postAssertions: []string{
				`SELECT COUNT(*) = 3 FROM Sessions WHERE Expired = false`,
			},
		},
		{
			name:      "success destroying sessions",
			oidcSID:   "aa817d69-f550-474b-8eae-7b29da32e3a8",
			sourceURL: []string{"file://../schema/spanner/oidc/migrations", "file://testdata/sessions_test/valid_sessions"},
			preAssertions: []string{
				`SELECT Username = 'test user 1' FROM Sessions WHERE OidcSid = 'aa817d69-f550-474b-8eae-7b29da32e3a8'`,
				`SELECT COUNT(*) = 1 FROM Sessions WHERE Username = 'test user 1' AND Expired = true`,
				`SELECT COUNT(*) = 2 FROM Sessions WHERE Username = 'test user 1' AND Expired = false`,
				`SELECT COUNT(*) = 1 FROM Sessions WHERE Username <> 'test user 1' AND Expired = false`,
			},
			postAssertions: []string{
				`SELECT COUNT(*) = 3 FROM Sessions WHERE Username = 'test user 1' AND Expired = true`,
				`SELECT COUNT(*) = 0 FROM Sessions WHERE Username = 'test user 1' AND Expired = false`,
				`SELECT COUNT(*) = 1 FROM Sessions WHERE Username <> 'test user 1' AND Expired = false`,
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			ctx := context.Background()
			conn, err := prepareDatabase(ctx, t, tt.sourceURL...)
			if err != nil {
				t.Fatalf("prepareDatabase() error = %v, wantErr %v", err, false)
			}
			c := &SessionStorageDriver{spanner: conn.Client}

			runAssertions(ctx, t, conn.Client, tt.preAssertions)
			if err := c.DestroySessionOIDC(ctx, tt.oidcSID); (err != nil) != tt.wantErr {
				t.Errorf("client.DestroySessionOIDC() error = %v, wantErr %v", err, tt.wantErr)
			}
			runAssertions(ctx, t, conn.Client, tt.postAssertions)
		})
	}
}
