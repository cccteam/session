package postgres

import (
	"context"
	"reflect"
	"testing"
	"time"

	"github.com/cccteam/ccc"
	"github.com/cccteam/session/internal/dbtype"
	"github.com/cccteam/session/sessioninfo"
	"github.com/go-playground/errors/v5"
	"github.com/jackc/pgx/v5"
)

func TestSessionStorageDriver_InsertSessionGoogleOIDC_GoogleOIDCUsers(t *testing.T) {
	t.Parallel()

	sourceURL := []string{"file://../../../schema/postgresql/oidc-google/migrations", "file://testdata/sessions_test/google_oidc_users"}

	newInsertSession := func(username string) *dbtype.InsertSession {
		return &dbtype.InsertSession{
			Username:  username,
			CreatedAt: time.Now(),
			UpdatedAt: time.Now(),
		}
	}

	googleUserDataConfig := func(hook func(ctx context.Context, txn pgx.Tx, req *sessioninfo.NewSessionRequest, current any) (any, error)) *CustomUserDataConfig {
		return &CustomUserDataConfig{
			TableName: "OIDCUserData",
			Codec:     mustCodec(reflect.TypeFor[oidcUserTestData]()),
			Hook:      hook,
		}
	}

	tests := []struct {
		name           string
		req            sessioninfo.NewSessionRequest
		userDataConfig *CustomUserDataConfig
		sessionConfig  *CustomSessionDataConfig
		wantErr        bool
		wantUserID     bool
		postAssertions []string
	}{
		{
			name: "first login provisions the anchor row",
			req:  sessioninfo.NewSessionRequest{Reason: sessioninfo.ReasonLogin, Username: "new@example.com", Sub: "sub-new", Hd: "example.com"},
			postAssertions: []string{
				`SELECT COUNT(*) = 1 FROM "GoogleOIDCUsers" WHERE "Sub" = 'sub-new' AND "Hd" = 'example.com' AND "Username" = 'new@example.com'`,
				`SELECT COUNT(*) = 1 FROM "Sessions" WHERE "Username" = 'new@example.com'`,
			},
			wantUserID: true,
		},
		{
			name: "existing anchor is renamed in place with Hd refreshed, not duplicated",
			req:  sessioninfo.NewSessionRequest{Reason: sessioninfo.ReasonLogin, Username: "new@example.com", Sub: "sub-existing", Hd: "renamed.example.com"},
			postAssertions: []string{
				`SELECT COUNT(*) = 1 FROM "GoogleOIDCUsers"`,
				`SELECT COUNT(*) = 1 FROM "GoogleOIDCUsers"
					WHERE "Id" = '11111111-2222-3333-4444-555555555555' AND "Username" = 'new@example.com'
					AND "Hd" = 'renamed.example.com' AND "UpdatedAt" > "CreatedAt"`,
			},
			wantUserID: true,
		},
		{
			name:    "missing sub claim aborts the login",
			req:     sessioninfo.NewSessionRequest{Reason: sessioninfo.ReasonLogin, Username: "new@example.com", Hd: "example.com"},
			wantErr: true,
			postAssertions: []string{
				`SELECT COUNT(*) = 1 FROM "GoogleOIDCUsers"`,
				`SELECT COUNT(*) = 0 FROM "Sessions"`,
			},
		},
		{
			name:    "missing hd claim aborts the login",
			req:     sessioninfo.NewSessionRequest{Reason: sessioninfo.ReasonLogin, Username: "new@example.com", Sub: "sub-new"},
			wantErr: true,
			postAssertions: []string{
				`SELECT COUNT(*) = 1 FROM "GoogleOIDCUsers"`,
				`SELECT COUNT(*) = 0 FROM "Sessions"`,
			},
		},
		{
			name: "hook provisions user data on first login (current is nil)",
			req:  sessioninfo.NewSessionRequest{Reason: sessioninfo.ReasonLogin, Username: "new@example.com", Sub: "sub-new", Hd: "example.com"},
			userDataConfig: googleUserDataConfig(func(_ context.Context, _ pgx.Tx, req *sessioninfo.NewSessionRequest, current any) (any, error) {
				if current != nil {
					return nil, errors.Newf("expected nil current on first login, got %+v", current)
				}
				if req.UserID.IsNil() {
					return nil, errors.New("expected req.UserID to be populated before the hook runs")
				}

				return &oidcUserTestData{Email: ptr(req.Username)}, nil
			}),
			postAssertions: []string{
				`SELECT COUNT(*) = 1 FROM "OIDCUserData" d JOIN "GoogleOIDCUsers" u ON d."UserId" = u."Id"
					WHERE u."Sub" = 'sub-new' AND d."Email" = 'new@example.com'`,
				`SELECT COUNT(*) = 1 FROM "Sessions"`,
			},
			wantUserID: true,
		},
		{
			name: "hook error aborts everything: no session, no anchor change",
			req:  sessioninfo.NewSessionRequest{Reason: sessioninfo.ReasonLogin, Username: "renamed@example.com", Sub: "sub-existing", Hd: "example.com"},
			userDataConfig: googleUserDataConfig(func(_ context.Context, _ pgx.Tx, _ *sessioninfo.NewSessionRequest, _ any) (any, error) {
				return nil, errors.New("hook failure")
			}),
			wantErr: true,
			postAssertions: []string{
				`SELECT COUNT(*) = 0 FROM "Sessions"`,
				`SELECT COUNT(*) = 1 FROM "GoogleOIDCUsers" WHERE "Username" = 'old@example.com'`,
			},
		},
		{
			name: "session data resolver runs after the anchor upsert and sees the durable key",
			req:  sessioninfo.NewSessionRequest{Reason: sessioninfo.ReasonLogin, Username: "new@example.com", Sub: "sub-new", Hd: "example.com"},
			sessionConfig: &CustomSessionDataConfig{
				TableName: "SessionCustomData",
				Codec:     mustCodec(reflect.TypeFor[sessionUserRefData]()),
				Resolver: func(_ context.Context, _ pgx.Tx, req *sessioninfo.NewSessionRequest) (any, error) {
					if req.UserID.IsNil() {
						return nil, errors.New("expected req.UserID to be populated before the resolver runs")
					}

					return &sessionUserRefData{UserIDRef: ptr(req.UserID.String())}, nil
				},
			},
			postAssertions: []string{
				`SELECT COUNT(*) = 1 FROM "SessionCustomData" c JOIN "GoogleOIDCUsers" u ON c."UserIdRef" = u."Id"::text WHERE u."Sub" = 'sub-new'`,
			},
			wantUserID: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			ctx := t.Context()
			conn, err := prepareDatabase(ctx, t, sourceURL...)
			if err != nil {
				t.Fatalf("prepareDatabase() error = %v, wantErr %v", err, false)
			}
			c := NewGoogleSessionStorageDriver(conn.Pool)
			c.EnableOIDCUsers()
			if tt.userDataConfig != nil {
				c.SetCustomUserData(tt.userDataConfig)
			}
			if tt.sessionConfig != nil {
				c.SetCustomSessionData(tt.sessionConfig)
			}

			_, err = c.InsertSessionGoogleOIDC(ctx, newInsertSession(tt.req.Username), &tt.req)
			if (err != nil) != tt.wantErr {
				t.Fatalf("SessionStorageDriver.InsertSessionGoogleOIDC() error = %v, wantErr %v", err, tt.wantErr)
			}
			if tt.wantUserID {
				if tt.req.UserID.IsNil() {
					t.Error("SessionStorageDriver.InsertSessionGoogleOIDC() did not populate req.UserID")
				} else if got, err := c.GoogleOIDCUserBySub(ctx, tt.req.Sub); err != nil {
					t.Errorf("SessionStorageDriver.GoogleOIDCUserBySub() error = %v", err)
				} else if got.ID != tt.req.UserID {
					t.Errorf("req.UserID = %s, want anchor id %s", tt.req.UserID, got.ID)
				}
			}
			runAssertions(ctx, t, conn.Pool, tt.postAssertions)
		})
	}
}

func TestSessionStorageDriver_GoogleOIDCUserReads(t *testing.T) {
	t.Parallel()

	ctx := t.Context()
	conn, err := prepareDatabase(ctx, t, "file://../../../schema/postgresql/oidc-google/migrations", "file://testdata/sessions_test/google_oidc_users")
	if err != nil {
		t.Fatalf("prepareDatabase() error = %v, wantErr %v", err, false)
	}
	c := NewGoogleSessionStorageDriver(conn.Pool)

	anchorID := ccc.Must(ccc.UUIDFromString("11111111-2222-3333-4444-555555555555"))

	byID, err := c.GoogleOIDCUser(ctx, anchorID)
	if err != nil {
		t.Fatalf("SessionStorageDriver.GoogleOIDCUser() error = %v", err)
	}
	if byID.Sub != "sub-existing" || byID.Hd != "example.com" || byID.Username != "old@example.com" {
		t.Errorf("SessionStorageDriver.GoogleOIDCUser() = %+v", byID)
	}

	bySub, err := c.GoogleOIDCUserBySub(ctx, "sub-existing")
	if err != nil {
		t.Fatalf("SessionStorageDriver.GoogleOIDCUserBySub() error = %v", err)
	}
	if bySub.ID != anchorID {
		t.Errorf("SessionStorageDriver.GoogleOIDCUserBySub() ID = %s, want %s", bySub.ID, anchorID)
	}

	if _, err := c.GoogleOIDCUser(ctx, ccc.Must(ccc.UUIDFromString("99999999-9999-9999-9999-999999999999"))); err == nil {
		t.Error("SessionStorageDriver.GoogleOIDCUser() error = nil for unknown id, want not found")
	}
	if _, err := c.GoogleOIDCUserBySub(ctx, "sub-unknown"); err == nil {
		t.Error("SessionStorageDriver.GoogleOIDCUserBySub() error = nil for unknown sub, want not found")
	}
}

func TestSessionStorageDriver_ProviderGuards(t *testing.T) {
	t.Parallel()

	ctx := t.Context()

	azure := NewSessionStorageDriver(nil)
	if _, err := azure.InsertSessionGoogleOIDC(ctx, &dbtype.InsertSession{}, &sessioninfo.NewSessionRequest{}); err == nil {
		t.Error("SessionStorageDriver.InsertSessionGoogleOIDC() error = nil on a non-Google driver, want error")
	}

	google := NewGoogleSessionStorageDriver(nil)
	if _, err := google.InsertSessionOIDC(ctx, &dbtype.InsertOIDCSession{}, &sessioninfo.NewSessionRequest{}); err == nil {
		t.Error("SessionStorageDriver.InsertSessionOIDC() error = nil on a Google driver, want error")
	}
}
