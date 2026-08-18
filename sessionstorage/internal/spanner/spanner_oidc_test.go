package spanner

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"reflect"
	"strings"
	"testing"
	"time"

	"cloud.google.com/go/spanner"
	"github.com/cccteam/session/internal/dbtype"
	"github.com/cccteam/session/sessioninfo"
	"github.com/go-playground/errors/v5"
)

// oidcCustomData matches the oidc_custom_columns_schema custom data table.
type oidcCustomData struct {
	CustomString string `spanner:"CustomString"`
	CustomInt    int64  `spanner:"CustomInt"`
}

func Test_client_InsertSessionOIDC(t *testing.T) {
	t.Parallel()

	rawClaims := json.RawMessage(`{"preferred_username":"test user 2","oid":"abc-123","name":"Test User"}`)

	tests := []struct {
		name           string
		insertSession  *dbtype.InsertOIDCSession
		req            sessioninfo.NewSessionRequest
		resolver       func(ctx context.Context, txn *spanner.ReadWriteTransaction, req sessioninfo.NewSessionRequest) (any, error)
		withConfig     bool
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
			req:       sessioninfo.NewSessionRequest{Reason: sessioninfo.ReasonLogin, Username: "test user 2"},
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
			req:       sessioninfo.NewSessionRequest{Reason: sessioninfo.ReasonLogin, Username: "test user 2"},
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
		{
			name: "resolver receives raw claims and writes custom data atomically",
			insertSession: &dbtype.InsertOIDCSession{
				OidcSID: "00000000-0000-0000-0000-000000000002",
				InsertSession: dbtype.InsertSession{
					Username:  "claims user",
					CreatedAt: time.Now(),
					UpdatedAt: time.Now(),
				},
			},
			req: sessioninfo.NewSessionRequest{Reason: sessioninfo.ReasonLogin, Username: "claims user", Claims: rawClaims},
			resolver: func(_ context.Context, _ *spanner.ReadWriteTransaction, req sessioninfo.NewSessionRequest) (any, error) {
				if !bytes.Equal(req.Claims, rawClaims) {
					return nil, errors.Newf("unexpected claims: %s", string(req.Claims))
				}
				var c struct {
					Oid string `json:"oid"`
				}
				if err := json.Unmarshal(req.Claims, &c); err != nil {
					return nil, errors.Wrap(err, "json.Unmarshal()")
				}

				return &oidcCustomData{CustomString: c.Oid}, nil
			},
			withConfig: true,
			sourceURL:  []string{"file://testdata/sessions_test/oidc_custom_columns_schema"},
			preAssertions: []string{
				`SELECT COUNT(*) = 0 FROM Sessions`,
			},
			postAssertions: []string{
				`SELECT COUNT(*) = 1 FROM Sessions`,
				`SELECT COUNT(*) = 1 FROM SessionCustomData WHERE CustomString = 'abc-123'`,
			},
		},
		{
			name: "atomicity: resolver error aborts OIDC session insert",
			insertSession: &dbtype.InsertOIDCSession{
				OidcSID: "00000000-0000-0000-0000-000000000003",
				InsertSession: dbtype.InsertSession{
					Username:  "abort user",
					CreatedAt: time.Now(),
					UpdatedAt: time.Now(),
				},
			},
			req: sessioninfo.NewSessionRequest{Reason: sessioninfo.ReasonLogin, Username: "abort user", Claims: rawClaims},
			resolver: func(_ context.Context, _ *spanner.ReadWriteTransaction, _ sessioninfo.NewSessionRequest) (any, error) {
				return nil, errors.New("resolver failure")
			},
			withConfig: true,
			sourceURL:  []string{"file://testdata/sessions_test/oidc_custom_columns_schema"},
			wantErr:    true,
			preAssertions: []string{
				`SELECT COUNT(*) = 0 FROM Sessions`,
			},
			postAssertions: []string{
				`SELECT COUNT(*) = 0 FROM Sessions`,
				`SELECT COUNT(*) = 0 FROM SessionCustomData`,
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
			if tt.withConfig {
				c.SetCustomSessionData(&CustomSessionDataConfig{
					TableName: "SessionCustomData",
					Codec:     mustCodec(reflect.TypeFor[oidcCustomData]()),
					Resolver:  tt.resolver,
				})
			}

			runAssertions(ctx, t, conn.Client, tt.preAssertions)

			got, err := c.InsertSessionOIDC(ctx, tt.insertSession, &tt.req)
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
