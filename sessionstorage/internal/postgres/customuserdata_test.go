package postgres

import (
	"context"
	"reflect"
	"testing"
	"time"

	"github.com/cccteam/ccc"
	"github.com/cccteam/ccc/securehash"
	"github.com/cccteam/httpio"
	"github.com/cccteam/session/internal/dbtype"
	"github.com/cccteam/session/sessioninfo"
	"github.com/go-playground/errors/v5"
	"github.com/google/go-cmp/cmp"
	"github.com/jackc/pgx/v5"
)

// userTestData matches the users_test/custom_user_data UserCustomData table.
type userTestData struct {
	Locale     *string `db:"Locale"`
	Theme      *string `db:"Theme"`
	LoginCount *int64  `db:"LoginCount"`
}

// oidcUserTestData matches the sessions_test/oidc_users OIDCUserData table.
type oidcUserTestData struct {
	Email       *string `db:"Email"`
	DisplayName *string `db:"DisplayName"`
	Theme       *string `db:"Theme"`
}

// sessionUserRefData matches the sessions_test/oidc_users SessionCustomData table.
type sessionUserRefData struct {
	UserIDRef *string `db:"UserIdRef"`
}

var (
	dataUserID   = ccc.Must(ccc.UUIDFromString("27b43588-b743-4133-8730-e0439065a844"))
	noDataUserID = ccc.Must(ccc.UUIDFromString("54918893-2342-4621-8673-79520a84b84f"))
)

func userDataConfig() *CustomUserDataConfig {
	return &CustomUserDataConfig{
		TableName: "UserCustomData",
		Codec:     mustCodec(reflect.TypeFor[userTestData]()),
	}
}

func TestSessionStorageDriver_CreateUser_CustomUserData(t *testing.T) {
	t.Parallel()

	hash, err := securehash.New(securehash.Argon2()).Hash("password")
	if err != nil {
		t.Fatal(err)
	}

	sourceURL := []string{"file://../../../schema/postgresql/migrations", "file://testdata/users_test/custom_user_data"}

	tests := []struct {
		name           string
		withConfig     bool
		customData     any
		wantErr        bool
		postAssertions []string
	}{
		{
			name:       "user and custom data row land together",
			withConfig: true,
			customData: &userTestData{Locale: ptr("fr-FR"), LoginCount: ptr(int64(1))},
			postAssertions: []string{
				`SELECT COUNT(*) = 1 FROM "SessionUsers" WHERE "Username" = 'newUser'`,
				`SELECT COUNT(*) = 1 FROM "UserCustomData" d JOIN "SessionUsers" u ON d."UserId" = u."Id"
					WHERE u."Username" = 'newUser' AND d."Locale" = 'fr-FR' AND d."LoginCount" = 1 AND d."Theme" IS NULL`,
			},
		},
		{
			name:       "custom data without a config is rejected before any insert",
			withConfig: false,
			customData: &userTestData{Locale: ptr("fr-FR")},
			wantErr:    true,
			postAssertions: []string{
				`SELECT COUNT(*) = 0 FROM "SessionUsers" WHERE "Username" = 'newUser'`,
			},
		},
		{
			name:       "nil custom data performs a plain insert",
			withConfig: true,
			postAssertions: []string{
				`SELECT COUNT(*) = 1 FROM "SessionUsers" WHERE "Username" = 'newUser'`,
				`SELECT COUNT(*) = 0 FROM "UserCustomData" d JOIN "SessionUsers" u ON d."UserId" = u."Id" WHERE u."Username" = 'newUser'`,
			},
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
			c := NewSessionStorageDriver(conn.Pool)
			if tt.withConfig {
				c.SetCustomUserData(userDataConfig())
			}

			_, err = c.CreateUser(ctx, &dbtype.InsertSessionUser{Username: "newUser", PasswordHash: hash}, tt.customData)
			if (err != nil) != tt.wantErr {
				t.Errorf("SessionStorageDriver.CreateUser() error = %v, wantErr %v", err, tt.wantErr)
			}
			runAssertions(ctx, t, conn.Pool, tt.postAssertions)
		})
	}
}

func TestSessionStorageDriver_CustomUserData(t *testing.T) {
	t.Parallel()

	sourceURL := []string{"file://../../../schema/postgresql/migrations", "file://testdata/users_test/custom_user_data"}

	tests := []struct {
		name       string
		withConfig bool
		userID     ccc.UUID
		want       any
		wantErr    bool
	}{
		{
			name:       "existing row scans into U",
			withConfig: true,
			userID:     dataUserID,
			want:       &userTestData{Locale: ptr("en-AU"), Theme: ptr("dark"), LoginCount: ptr(int64(3))},
		},
		{
			name:       "user without a row yields zero-value U",
			withConfig: true,
			userID:     noDataUserID,
			want:       &userTestData{},
		},
		{
			name:    "no config is an error",
			userID:  dataUserID,
			wantErr: true,
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
			c := NewSessionStorageDriver(conn.Pool)
			if tt.withConfig {
				c.SetCustomUserData(userDataConfig())
			}

			got, err := c.CustomUserData(ctx, tt.userID)
			if (err != nil) != tt.wantErr {
				t.Fatalf("SessionStorageDriver.CustomUserData() error = %v, wantErr %v", err, tt.wantErr)
			}
			if !tt.wantErr {
				if diff := cmp.Diff(tt.want, got); diff != "" {
					t.Errorf("SessionStorageDriver.CustomUserData() mismatch (-want +got):\n%s", diff)
				}
			}
		})
	}
}

func TestSessionStorageDriver_UpdateCustomUserData(t *testing.T) {
	t.Parallel()

	sourceURL := []string{"file://../../../schema/postgresql/migrations", "file://testdata/users_test/custom_user_data"}

	tests := []struct {
		name           string
		withConfig     bool
		userID         ccc.UUID
		mutate         func(data any) error
		wantErr        bool
		wantErrMsg     string
		postAssertions []string
	}{
		{
			name:       "read-modify-write preserves untouched fields",
			withConfig: true,
			userID:     dataUserID,
			mutate: func(data any) error {
				typed, ok := data.(*userTestData)
				if !ok {
					return errors.Newf("unexpected mutate data type %T", data)
				}
				typed.Theme = ptr("light")

				return nil
			},
			postAssertions: []string{
				`SELECT COUNT(*) = 1 FROM "UserCustomData"
					WHERE "UserId" = '27b43588-b743-4133-8730-e0439065a844'
					AND "Theme" = 'light' AND "Locale" = 'en-AU' AND "LoginCount" = 3`,
			},
		},
		{
			name:       "creates the row for a user without one",
			withConfig: true,
			userID:     noDataUserID,
			mutate: func(data any) error {
				typed, ok := data.(*userTestData)
				if !ok {
					return errors.Newf("unexpected mutate data type %T", data)
				}
				if typed.Locale != nil || typed.Theme != nil || typed.LoginCount != nil {
					return errors.New("expected zero-value U for a user without a row")
				}
				typed.Locale = ptr("de-DE")

				return nil
			},
			postAssertions: []string{
				`SELECT COUNT(*) = 1 FROM "UserCustomData"
					WHERE "UserId" = '54918893-2342-4621-8673-79520a84b84f' AND "Locale" = 'de-DE'`,
			},
		},
		{
			name:       "unknown user aborts with not found",
			withConfig: true,
			userID:     ccc.Must(ccc.UUIDFromString("99999999-9999-9999-9999-999999999999")),
			mutate:     func(any) error { return nil },
			wantErr:    true,
			wantErrMsg: `user id "99999999-9999-9999-9999-999999999999" does not exist`,
			postAssertions: []string{
				`SELECT COUNT(*) = 1 FROM "UserCustomData"`,
			},
		},
		{
			name:       "mutate error aborts with nothing written",
			withConfig: true,
			userID:     dataUserID,
			mutate:     func(any) error { return errors.New("mutate failure") },
			wantErr:    true,
			postAssertions: []string{
				`SELECT COUNT(*) = 1 FROM "UserCustomData"
					WHERE "UserId" = '27b43588-b743-4133-8730-e0439065a844' AND "Theme" = 'dark'`,
			},
		},
		{
			name:    "no config is an error",
			userID:  dataUserID,
			mutate:  func(any) error { return nil },
			wantErr: true,
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
			c := NewSessionStorageDriver(conn.Pool)
			if tt.withConfig {
				c.SetCustomUserData(userDataConfig())
			}

			err = c.UpdateCustomUserData(ctx, tt.userID, tt.mutate)
			if (err != nil) != tt.wantErr {
				t.Fatalf("SessionStorageDriver.UpdateCustomUserData() error = %v, wantErr %v", err, tt.wantErr)
			}
			if tt.wantErrMsg != "" && httpio.Message(err) != tt.wantErrMsg {
				t.Errorf("SessionStorageDriver.UpdateCustomUserData() error message = %s, want %s", httpio.Message(err), tt.wantErrMsg)
			}
			runAssertions(ctx, t, conn.Pool, tt.postAssertions)
		})
	}
}

func TestSessionStorageDriver_DeleteUser_CustomUserDataCascade(t *testing.T) {
	t.Parallel()

	ctx := t.Context()
	conn, err := prepareDatabase(ctx, t, "file://../../../schema/postgresql/migrations", "file://testdata/users_test/custom_user_data")
	if err != nil {
		t.Fatalf("prepareDatabase() error = %v, wantErr %v", err, false)
	}
	c := NewSessionStorageDriver(conn.Pool)
	c.SetCustomUserData(userDataConfig())

	runAssertions(ctx, t, conn.Pool, []string{`SELECT COUNT(*) = 1 FROM "UserCustomData"`})
	if err := c.DeleteUser(ctx, dataUserID); err != nil {
		t.Fatalf("SessionStorageDriver.DeleteUser() error = %v", err)
	}
	runAssertions(ctx, t, conn.Pool, []string{`SELECT COUNT(*) = 0 FROM "UserCustomData"`})
}

func TestSessionStorageDriver_UpdateCustomSessionData_SessionGate(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name       string
		sessionID  ccc.UUID
		wantErrMsg string
	}{
		{
			name:       "unknown session aborts with not found",
			sessionID:  ccc.Must(ccc.UUIDFromString("99999999-9999-9999-9999-999999999999")),
			wantErrMsg: `session "99999999-9999-9999-9999-999999999999" not found`,
		},
		{
			name:       "expired session is rejected",
			sessionID:  ccc.Must(ccc.UUIDFromString("22222222-2222-2222-2222-222222222222")),
			wantErrMsg: "cannot update custom session data for an expired session",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			ctx := t.Context()
			conn, err := prepareDatabase(ctx, t, "file://testdata/sessions_test/custom_columns_schema")
			if err != nil {
				t.Fatalf("prepareDatabase() error = %v, wantErr %v", err, false)
			}
			c := NewSessionStorageDriver(conn.Pool)
			c.SetCustomSessionData(&CustomSessionDataConfig{
				TableName: "SessionCustomData",
				Codec:     mustCodec(reflect.TypeFor[customStringData]()),
			})

			err = c.UpdateCustomSessionData(ctx, tt.sessionID, func(any) error { return nil })
			if err == nil {
				t.Fatal("SessionStorageDriver.UpdateCustomSessionData() error = nil, want error")
			}
			if httpio.Message(err) != tt.wantErrMsg {
				t.Errorf("SessionStorageDriver.UpdateCustomSessionData() error message = %s, want %s", httpio.Message(err), tt.wantErrMsg)
			}
			// The gate must abort before the write: the expired session's row is untouched.
			runAssertions(ctx, t, conn.Pool, []string{
				`SELECT COUNT(*) = 1 FROM "SessionCustomData"
					WHERE "SessionId" = '22222222-2222-2222-2222-222222222222' AND "CustomString" = 'viewer'`,
			})
		})
	}
}

func TestSessionStorageDriver_InsertSessionOIDC_OIDCUsers(t *testing.T) {
	t.Parallel()

	sourceURL := []string{"file://../../../schema/postgresql/oidc/migrations", "file://testdata/sessions_test/oidc_users"}

	newInsertSession := func(username string) *dbtype.InsertOIDCSession {
		return &dbtype.InsertOIDCSession{
			OidcSID: "oidc-sid-1",
			InsertSession: dbtype.InsertSession{
				Username:  username,
				CreatedAt: time.Now(),
				UpdatedAt: time.Now(),
			},
		}
	}

	oidcUserDataConfig := func(hook func(ctx context.Context, txn pgx.Tx, req *sessioninfo.NewSessionRequest, current any) (any, error)) *CustomUserDataConfig {
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
			req:  sessioninfo.NewSessionRequest{Reason: sessioninfo.ReasonLogin, Username: "new@example.com", Tid: "tid-1", Oid: "oid-new"},
			postAssertions: []string{
				`SELECT COUNT(*) = 1 FROM "OIDCUsers" WHERE "Tid" = 'tid-1' AND "Oid" = 'oid-new' AND "Username" = 'new@example.com'`,
				`SELECT COUNT(*) = 1 FROM "Sessions" WHERE "Username" = 'new@example.com'`,
			},
			wantUserID: true,
		},
		{
			name: "existing anchor is renamed in place, not duplicated",
			req:  sessioninfo.NewSessionRequest{Reason: sessioninfo.ReasonLogin, Username: "new@example.com", Tid: "tid-1", Oid: "oid-existing"},
			postAssertions: []string{
				`SELECT COUNT(*) = 1 FROM "OIDCUsers"`,
				`SELECT COUNT(*) = 1 FROM "OIDCUsers"
					WHERE "Id" = '11111111-2222-3333-4444-555555555555' AND "Username" = 'new@example.com' AND "UpdatedAt" > "CreatedAt"`,
			},
			wantUserID: true,
		},
		{
			name:    "missing oid claim aborts the login",
			req:     sessioninfo.NewSessionRequest{Reason: sessioninfo.ReasonLogin, Username: "new@example.com", Tid: "tid-1"},
			wantErr: true,
			postAssertions: []string{
				`SELECT COUNT(*) = 1 FROM "OIDCUsers"`,
				`SELECT COUNT(*) = 0 FROM "Sessions"`,
			},
		},
		{
			name: "hook provisions user data on first login (current is nil)",
			req:  sessioninfo.NewSessionRequest{Reason: sessioninfo.ReasonLogin, Username: "new@example.com", Tid: "tid-1", Oid: "oid-new"},
			userDataConfig: oidcUserDataConfig(func(_ context.Context, _ pgx.Tx, req *sessioninfo.NewSessionRequest, current any) (any, error) {
				if current != nil {
					return nil, errors.Newf("expected nil current on first login, got %+v", current)
				}
				if req.UserID.IsNil() {
					return nil, errors.New("expected req.UserID to be populated before the hook runs")
				}

				return &oidcUserTestData{Email: ptr(req.Username)}, nil
			}),
			postAssertions: []string{
				`SELECT COUNT(*) = 1 FROM "OIDCUserData" d JOIN "OIDCUsers" u ON d."UserId" = u."Id"
					WHERE u."Oid" = 'oid-new' AND d."Email" = 'new@example.com'`,
				`SELECT COUNT(*) = 1 FROM "Sessions"`,
			},
			wantUserID: true,
		},
		{
			name: "hook refresh starts from current and preserves app-owned fields",
			req:  sessioninfo.NewSessionRequest{Reason: sessioninfo.ReasonLogin, Username: "renamed@example.com", Tid: "tid-1", Oid: "oid-existing"},
			userDataConfig: oidcUserDataConfig(func(_ context.Context, _ pgx.Tx, req *sessioninfo.NewSessionRequest, current any) (any, error) {
				typed, ok := current.(*oidcUserTestData)
				if !ok {
					return nil, errors.Newf("expected *oidcUserTestData current, got %T", current)
				}
				typed.Email = ptr(req.Username)

				return typed, nil
			}),
			postAssertions: []string{
				`SELECT COUNT(*) = 1 FROM "OIDCUserData"
					WHERE "UserId" = '11111111-2222-3333-4444-555555555555'
					AND "Email" = 'renamed@example.com' AND "DisplayName" = 'Old Name' AND "Theme" = 'dark'`,
			},
			wantUserID: true,
		},
		{
			name: "hook nil return leaves the row untouched",
			req:  sessioninfo.NewSessionRequest{Reason: sessioninfo.ReasonLogin, Username: "old@example.com", Tid: "tid-1", Oid: "oid-existing"},
			userDataConfig: oidcUserDataConfig(func(_ context.Context, _ pgx.Tx, _ *sessioninfo.NewSessionRequest, _ any) (any, error) {
				return nil, nil
			}),
			postAssertions: []string{
				`SELECT COUNT(*) = 1 FROM "OIDCUserData"
					WHERE "UserId" = '11111111-2222-3333-4444-555555555555' AND "Email" = 'old@example.com'`,
				`SELECT COUNT(*) = 1 FROM "Sessions"`,
			},
			wantUserID: true,
		},
		{
			name: "hook error aborts everything: no session, no anchor change",
			req:  sessioninfo.NewSessionRequest{Reason: sessioninfo.ReasonLogin, Username: "renamed@example.com", Tid: "tid-1", Oid: "oid-existing"},
			userDataConfig: oidcUserDataConfig(func(_ context.Context, _ pgx.Tx, _ *sessioninfo.NewSessionRequest, _ any) (any, error) {
				return nil, errors.New("hook failure")
			}),
			wantErr: true,
			postAssertions: []string{
				`SELECT COUNT(*) = 0 FROM "Sessions"`,
				`SELECT COUNT(*) = 1 FROM "OIDCUsers" WHERE "Username" = 'old@example.com'`,
			},
		},
		{
			name: "session data resolver runs after the anchor upsert and sees the durable key",
			req:  sessioninfo.NewSessionRequest{Reason: sessioninfo.ReasonLogin, Username: "new@example.com", Tid: "tid-1", Oid: "oid-new"},
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
				`SELECT COUNT(*) = 1 FROM "SessionCustomData" c JOIN "OIDCUsers" u ON c."UserIdRef" = u."Id"::text WHERE u."Oid" = 'oid-new'`,
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
			c := NewSessionStorageDriver(conn.Pool)
			c.EnableOIDCUsers()
			if tt.userDataConfig != nil {
				c.SetCustomUserData(tt.userDataConfig)
			}
			if tt.sessionConfig != nil {
				c.SetCustomSessionData(tt.sessionConfig)
			}

			_, err = c.InsertSessionOIDC(ctx, newInsertSession(tt.req.Username), &tt.req)
			if (err != nil) != tt.wantErr {
				t.Fatalf("SessionStorageDriver.InsertSessionOIDC() error = %v, wantErr %v", err, tt.wantErr)
			}
			if tt.wantUserID {
				if tt.req.UserID.IsNil() {
					t.Error("SessionStorageDriver.InsertSessionOIDC() did not populate req.UserID")
				} else if got, err := c.OIDCUserByKey(ctx, tt.req.Tid, tt.req.Oid); err != nil {
					t.Errorf("SessionStorageDriver.OIDCUserByKey() error = %v", err)
				} else if got.ID != tt.req.UserID {
					t.Errorf("req.UserID = %s, want anchor id %s", tt.req.UserID, got.ID)
				}
			}
			runAssertions(ctx, t, conn.Pool, tt.postAssertions)
		})
	}
}

func TestSessionStorageDriver_OIDCUserReads(t *testing.T) {
	t.Parallel()

	ctx := t.Context()
	conn, err := prepareDatabase(ctx, t, "file://../../../schema/postgresql/oidc/migrations", "file://testdata/sessions_test/oidc_users")
	if err != nil {
		t.Fatalf("prepareDatabase() error = %v, wantErr %v", err, false)
	}
	c := NewSessionStorageDriver(conn.Pool)

	anchorID := ccc.Must(ccc.UUIDFromString("11111111-2222-3333-4444-555555555555"))

	byID, err := c.OIDCUser(ctx, anchorID)
	if err != nil {
		t.Fatalf("SessionStorageDriver.OIDCUser() error = %v", err)
	}
	if byID.Tid != "tid-1" || byID.Oid != "oid-existing" || byID.Username != "old@example.com" {
		t.Errorf("SessionStorageDriver.OIDCUser() = %+v", byID)
	}

	byKey, err := c.OIDCUserByKey(ctx, "tid-1", "oid-existing")
	if err != nil {
		t.Fatalf("SessionStorageDriver.OIDCUserByKey() error = %v", err)
	}
	if byKey.ID != anchorID {
		t.Errorf("SessionStorageDriver.OIDCUserByKey() ID = %s, want %s", byKey.ID, anchorID)
	}

	if _, err := c.OIDCUser(ctx, ccc.Must(ccc.UUIDFromString("99999999-9999-9999-9999-999999999999"))); err == nil {
		t.Error("SessionStorageDriver.OIDCUser() error = nil for unknown id, want not found")
	}
	if _, err := c.OIDCUserByKey(ctx, "tid-1", "oid-unknown"); err == nil {
		t.Error("SessionStorageDriver.OIDCUserByKey() error = nil for unknown key, want not found")
	}
}
