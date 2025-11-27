package spanner

import (
	"context"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/cccteam/session/internal/dbtype"
)

func Test_client_InsertSessionOIDC(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name           string
		insertSession  *dbtype.InsertOIDCSession
		sourceURL      []string
		wantErr        bool
		preAssertions  []string
		postAssertions []string
	}{
		{
			name: "fails to create session (invalid schema)",
			insertSession: &dbtype.InsertOIDCSession{
				OidcSID: "00000000-0000-0000-0000-000000000001",
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
			insertSession: &dbtype.InsertOIDCSession{
				OidcSID: "00000000-0000-0000-0000-000000000001",
				InsertSession: dbtype.InsertSession{
					Username:  "test user 2",
					CreatedAt: time.Date(2018, 5, 3, 1, 2, 3, 0, time.UTC),
					UpdatedAt: time.Date(2017, 6, 4, 3, 2, 1, 0, time.UTC),
					Expired:   true,
				},
			},
			sourceURL: []string{"file://../../../schema/spanner/oidc/migrations", "file://testdata/sessions_test/oidc_valid_sessions"},
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
					AND OidcSid = '00000000-0000-0000-0000-000000000001'
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
			c := NewSessionStorageDriver(conn.Client)

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
			sourceURL: []string{"file://../../../schema/spanner/oidc/migrations", "file://testdata/sessions_test/oidc_valid_sessions"},
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
			sourceURL: []string{"file://../../../schema/spanner/oidc/migrations", "file://testdata/sessions_test/oidc_valid_sessions"},
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
			c := NewSessionStorageDriver(conn.Client)

			runAssertions(ctx, t, conn.Client, tt.preAssertions)
			if err := c.DestroySessionOIDC(ctx, tt.oidcSID); (err != nil) != tt.wantErr {
				t.Errorf("client.DestroySessionOIDC() error = %v, wantErr %v", err, tt.wantErr)
			}
			runAssertions(ctx, t, conn.Client, tt.postAssertions)
		})
	}
}
