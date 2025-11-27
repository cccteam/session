package postgres

import (
	"context"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/cccteam/session/internal/dbtype"
)

const PostgresTimestampFormat = "2006-01-02 15:04:05.999999999-07"

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
			name: "success creating session",
			insertSession: &dbtype.InsertOIDCSession{
				OidcSID: "oidc session",
				InsertSession: dbtype.InsertSession{
					Username:  "test user 2",
					CreatedAt: time.Date(2024, 1, 2, 3, 4, 5, 0, time.UTC),
					UpdatedAt: time.Date(2024, 1, 2, 3, 4, 5, 0, time.UTC),
				},
			},
			sourceURL: []string{"file://../../../schema/postgresql/oidc/migrations"},
			preAssertions: []string{
				`SELECT COUNT(*) = 0 FROM "Sessions"`,
			},
			postAssertions: []string{
				`SELECT COUNT(*) = 1 FROM "Sessions"
				 WHERE "Id" = '%s'
					 AND "Username" = 'test user 2'
					 AND "OidcSid" = 'oidc session'
					 AND "CreatedAt" = '2024-01-02 03:04:05+00:00'
					 AND "UpdatedAt" = '2024-01-02 03:04:05+00:00'
					 AND "Expired" = false`,
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
			c := NewSessionStorageDriver(conn.Pool)

			runAssertions(ctx, t, conn.Pool, tt.preAssertions)

			id, err := c.InsertSessionOIDC(ctx, tt.insertSession)
			if err != nil != tt.wantErr {
				t.Errorf("client.InsertSession() error = %v, wantErr %v", err, tt.wantErr)
				return
			}

			for i, query := range tt.postAssertions {
				if strings.Contains(query, "%s") {
					tt.postAssertions[i] = fmt.Sprintf(query, id.String())
				}
			}

			runAssertions(ctx, t, conn.Pool, tt.postAssertions)
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
			oidcSID: "oidc session 38bd570b-1280-421b-888e-a63f0ca35be7",
			wantErr: true,
		},
		{
			name:      "success without destroying sessions",
			oidcSID:   "oidc session4",
			sourceURL: []string{"file://../../../schema/postgresql/oidc/migrations", "file://testdata/sessions_test/valid_sessions"},
			preAssertions: []string{
				`SELECT COUNT(*) = 0 FROM "Sessions" WHERE "OidcSid" = 'oidc session4'`,
				`SELECT COUNT(*) = 3 FROM "Sessions" WHERE "Expired" = false`,
			},
			postAssertions: []string{
				`SELECT COUNT(*) = 3 FROM "Sessions" WHERE "Expired" = false`,
			},
		},
		{
			name:      "success destroying sessions",
			oidcSID:   "oidc session aa817d69-f550-474b-8eae-7b29da32e3a8",
			sourceURL: []string{"file://../../../schema/postgresql/oidc/migrations", "file://testdata/sessions_test/valid_sessions"},
			preAssertions: []string{
				`SELECT "Username" = 'test user 1' FROM "Sessions" WHERE "OidcSid" = 'oidc session aa817d69-f550-474b-8eae-7b29da32e3a8'`,
				`SELECT COUNT(*) = 1               FROM "Sessions" WHERE "Username" = 'test user 1' AND "Expired" = true`,
				`SELECT COUNT(*) = 2               FROM "Sessions" WHERE "Username" = 'test user 1' AND "Expired" = false`,
				`SELECT COUNT(*) = 1               FROM "Sessions" WHERE "Username" <> 'test user 1' AND "Expired" = false`,
			},
			postAssertions: []string{
				`SELECT COUNT(*) = 3 FROM "Sessions" WHERE "Username" = 'test user 1' AND "Expired" = true`,
				`SELECT COUNT(*) = 0 FROM "Sessions" WHERE "Username" = 'test user 1' AND "Expired" = false`,
				`SELECT COUNT(*) = 1 FROM "Sessions" WHERE "Username" <> 'test user 1' AND "Expired" = false`,
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
			c := NewSessionStorageDriver(conn.Pool)

			runAssertions(ctx, t, conn.Pool, tt.preAssertions)
			if err := c.DestroySessionOIDC(ctx, tt.oidcSID); (err != nil) != tt.wantErr {
				t.Errorf("client.DestroySessionOIDC() error = %v, wantErr %v", err, tt.wantErr)
			}
			runAssertions(ctx, t, conn.Pool, tt.postAssertions)
		})
	}
}
