package spanner

import (
	"context"
	"fmt"
	"reflect"
	"testing"
	"time"

	"cloud.google.com/go/spanner"
	"github.com/cccteam/ccc"
	"github.com/cccteam/ccc/securehash"
	"github.com/cccteam/httpio"
	"github.com/cccteam/session/internal/dbtype"
	"github.com/cccteam/session/sessioninfo"
	"github.com/go-playground/errors/v5"
	"github.com/google/go-cmp/cmp"
)

func TestClient_FullMigration(t *testing.T) {
	t.Parallel()

	type args struct {
		sourceURL string
	}
	tests := []struct {
		name string
		args args
	}{
		{
			name: "FullMigration OIDC",
			args: args{
				sourceURL: "file://../../../schema/spanner/oidc/migrations",
			},
		},
		{
			name: "FullMigration",
			args: args{
				sourceURL: "file://../../../schema/spanner/migrations",
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			db, err := prepareDatabase(t.Context(), t, tt.args.sourceURL)
			if (err != nil) != false {
				t.Fatalf("prepareDatabase() error = %v, wantErr %v", err, false)
			}

			if err := db.MigrateDown(tt.args.sourceURL); err != nil {
				t.Fatalf("db.MigrateDown() error = %v, wantErr %v", err, false)
			}
		})
	}
}

func TestSessionStorageDriver_SetSessionTableName(t *testing.T) {
	t.Parallel()
	c := NewSessionStorageDriver(nil)
	c.SetSessionTableName("NewSessionTable")
	if c.sessionTableName != "NewSessionTable" {
		t.Errorf("SetSessionTableName() = %v, want %v", c.sessionTableName, "NewSessionTable")
	}
}

func TestSessionStorageDriver_SetUserTableName(t *testing.T) {
	t.Parallel()
	c := NewSessionStorageDriver(nil)
	c.SetUserTableName("NewUserTable")
	if c.userTableName != "NewUserTable" {
		t.Errorf("SetUserTableName() = %v, want %v", c.userTableName, "NewUserTable")
	}
}

func TestSessionStorageDriver_Session(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name        string
		sessionID   ccc.UUID
		sourceURL   []string
		wantSession *dbtype.SessionData
		wantErr     bool
	}{
		{
			name:      "success",
			sessionID: ccc.Must(ccc.UUIDFromString("eb0c72a4-1f32-469e-b51b-7baa589a944c")),
			sourceURL: []string{"file://../../../schema/spanner/oidc/migrations", "file://testdata/sessions_test/oidc_valid_sessions"},
			wantSession: &dbtype.SessionData{
				Session: &dbtype.Session{
					ID:       ccc.Must(ccc.UUIDFromString("eb0c72a4-1f32-469e-b51b-7baa589a944c")),
					Username: "test user 2",
					Expired:  true,
				},
			},
		},
		{
			name:      "not found",
			sessionID: ccc.Must(ccc.NewUUID()),
			sourceURL: []string{"file://../../../schema/spanner/oidc/migrations", "file://testdata/sessions_test/oidc_valid_sessions"},
			wantErr:   true,
		},
		{
			name:      "invalid schema",
			sessionID: ccc.Must(ccc.UUIDFromString("eb0c72a4-1f32-469e-b51b-7baa589a944c")),
			sourceURL: []string{"file://testdata/sessions_test/invalid_schema"},
			wantErr:   true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			ctx := t.Context()
			conn, err := prepareDatabase(ctx, t, tt.sourceURL...)
			if err != nil {
				t.Fatalf("prepareDatabase() error = %v, wantErr %v", err, false)
			}
			c := NewSessionStorageDriver(conn.Client)

			gotSession, err := c.Session(ctx, tt.sessionID)
			if (err != nil) != tt.wantErr {
				t.Errorf("SessionStorageDriver.Session() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if tt.wantSession != nil {
				if gotSession.ID != tt.wantSession.ID {
					t.Errorf("SessionStorageDriver.Session() gotSession.ID = %v, want %v", gotSession.ID, tt.wantSession.ID)
				}
				if gotSession.Username != tt.wantSession.Username {
					t.Errorf("SessionStorageDriver.Session() gotSession.Username = %v, want %v", gotSession.Username, tt.wantSession.Username)
				}
				if gotSession.Expired != tt.wantSession.Expired {
					t.Errorf("SessionStorageDriver.Session() gotSession.Expired = %v, want %v", gotSession.Expired, tt.wantSession.Expired)
				}
			}
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
			sourceURL: []string{"file://../../../schema/spanner/oidc/migrations", "file://testdata/sessions_test/oidc_valid_sessions"},
			wantErr:   true,
		},
		{
			name:      "success updating session activity",
			sessionID: ccc.Must(ccc.UUIDFromString("eb0c72a4-1f32-469e-b51b-7baa589a944c")),
			sourceURL: []string{"file://../../../schema/spanner/oidc/migrations", "file://testdata/sessions_test/oidc_valid_sessions"},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			ctx := t.Context()
			conn, err := prepareDatabase(ctx, t, tt.sourceURL...)
			if err != nil {
				t.Fatalf("prepareDatabase() error = %v, wantErr %v", err, false)
			}
			c := NewSessionStorageDriver(conn.Client)

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
			sourceURL: []string{"file://../../../schema/spanner/oidc/migrations", "file://testdata/sessions_test/oidc_valid_sessions"},
			preAssertions: []string{
				`SELECT COUNT(*) = 3 FROM Sessions WHERE Expired = false`,
				`SELECT COUNT(*) = 0 FROM Sessions WHERE Id = '52dd570b-1280-421b-888e-a63f0ca35be9'`,
			},
			postAssertions: []string{
				`SELECT COUNT(*) = 3 FROM Sessions WHERE Expired = false`,
			},
		},
		{
			name:      "success destroying session",
			sessionID: ccc.Must(ccc.UUIDFromString("38bd570b-1280-421b-888e-a63f0ca35be7")),
			sourceURL: []string{"file://../../../schema/spanner/oidc/migrations", "file://testdata/sessions_test/oidc_valid_sessions"},
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

			ctx := t.Context()
			conn, err := prepareDatabase(ctx, t, tt.sourceURL...)
			if err != nil {
				t.Fatalf("prepareDatabase() error = %v, wantErr %v", err, false)
			}
			c := NewSessionStorageDriver(conn.Client)

			runAssertions(ctx, t, conn.Client, tt.preAssertions)
			if err := c.DestroySession(ctx, tt.sessionID); (err != nil) != tt.wantErr {
				t.Errorf("client.DestroySession() error = %v, wantErr %v", err, tt.wantErr)
			}
			runAssertions(ctx, t, conn.Client, tt.postAssertions)
		})
	}
}

func TestSessionStorageDriver_InsertSession(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name           string
		insertSession  *dbtype.InsertSession
		sourceURL      []string
		wantErr        bool
		preAssertions  []string
		postAssertions []string
	}{
		{
			name: "success",
			insertSession: &dbtype.InsertSession{
				Username:  "testuser",
				CreatedAt: time.Now(),
				UpdatedAt: time.Now(),
				Expired:   false,
			},
			sourceURL: []string{"file://../../../schema/spanner/migrations", "file://testdata/sessions_test/valid_sessions"},
			preAssertions: []string{
				`SELECT COUNT(*) = 5 FROM Sessions`,
			},
			postAssertions: []string{
				`SELECT COUNT(*) = 6 FROM Sessions`,
			},
		},
		{
			name: "invalid schema",
			insertSession: &dbtype.InsertSession{
				Username:  "testuser",
				CreatedAt: time.Now(),
				UpdatedAt: time.Now(),
				Expired:   false,
			},
			sourceURL: []string{"file://testdata/sessions_test/invalid_schema"},
			wantErr:   true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			ctx := t.Context()
			conn, err := prepareDatabase(ctx, t, tt.sourceURL...)
			if err != nil {
				t.Fatalf("prepareDatabase() error = %v, wantErr %v", err, false)
			}
			c := NewSessionStorageDriver(conn.Client)

			runAssertions(ctx, t, conn.Client, tt.preAssertions)
			id, err := c.InsertSession(ctx, tt.insertSession, &sessioninfo.NewSessionRequest{Reason: sessioninfo.ReasonLogin, Username: tt.insertSession.Username})
			if (err != nil) != tt.wantErr {
				t.Errorf("SessionStorageDriver.InsertSession() error = %v, wantErr %v", err, tt.wantErr)
				return
			}

			if !tt.wantErr {
				if id == ccc.NilUUID {
					t.Error("SessionStorageDriver.InsertSession() id is nil, want valid UUID")
				}
				runAssertions(ctx, t, conn.Client, []string{fmt.Sprintf(`SELECT COUNT(*) = 1 FROM Sessions WHERE Id = '%s'`, id)})
			}
			runAssertions(ctx, t, conn.Client, tt.postAssertions)
		})
	}
}

func TestSessionStorageDriver_User(t *testing.T) {
	t.Parallel()
	userID := ccc.Must(ccc.UUIDFromString("27b43588-b743-4133-8730-e0439065a844"))
	tests := []struct {
		name           string
		id             ccc.UUID
		sourceURL      []string
		wantUser       *dbtype.SessionUser
		wantErr        bool
		preAssertions  []string
		postAssertions []string
	}{
		{
			name:      "success",
			id:        userID,
			sourceURL: []string{"file://../../../schema/spanner/migrations", "file://testdata/users_test/valid_users"},
			wantUser: &dbtype.SessionUser{
				ID:       userID,
				Username: "testUser",
				Disabled: false,
			},
			preAssertions: []string{
				fmt.Sprintf(`SELECT COUNT(*) = 1 FROM SessionUsers WHERE Id = '%s'`, userID),
			},
		},
		{
			name:      "not found",
			id:        ccc.Must(ccc.NewUUID()),
			sourceURL: []string{"file://../../../schema/spanner/migrations", "file://testdata/users_test/valid_users"},
			wantErr:   true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			ctx := t.Context()
			conn, err := prepareDatabase(ctx, t, tt.sourceURL...)
			if err != nil {
				t.Fatalf("prepareDatabase() error = %v, wantErr %v", err, false)
			}
			c := NewSessionStorageDriver(conn.Client)

			runAssertions(ctx, t, conn.Client, tt.preAssertions)
			gotUser, err := c.User(ctx, tt.id)
			if (err != nil) != tt.wantErr {
				t.Errorf("SessionStorageDriver.User() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if tt.wantUser != nil {
				if gotUser.ID != tt.wantUser.ID {
					t.Errorf("SessionStorageDriver.User() gotUser.ID = %v, want %v", gotUser.ID, tt.wantUser.ID)
				}
				if gotUser.Username != tt.wantUser.Username {
					t.Errorf("SessionStorageDriver.User() gotUser.Username = %v, want %v", gotUser.Username, tt.wantUser.Username)
				}
				if gotUser.Disabled != tt.wantUser.Disabled {
					t.Errorf("SessionStorageDriver.User() gotUser.Disabled = %v, want %v", gotUser.Disabled, tt.wantUser.Disabled)
				}
			}
			runAssertions(ctx, t, conn.Client, tt.postAssertions)
		})
	}
}

func TestSessionStorageDriver_UserByUserName(t *testing.T) {
	t.Parallel()
	userID := ccc.Must(ccc.UUIDFromString("27b43588-b743-4133-8730-e0439065a844"))
	tests := []struct {
		name           string
		username       string
		sourceURL      []string
		wantUser       *dbtype.SessionUser
		wantErr        bool
		preAssertions  []string
		postAssertions []string
	}{
		{
			name:      "found user with case insensitive match",
			username:  "tESTuSer",
			sourceURL: []string{"file://../../../schema/spanner/migrations", "file://testdata/users_test/valid_users"},
			wantUser: &dbtype.SessionUser{
				ID:       userID,
				Username: "testUser",
				Disabled: false,
			},
			preAssertions: []string{
				`SELECT COUNT(*) = 1 FROM SessionUsers WHERE Username = 'testUser'`,
			},
		},
		{
			name:      "success",
			username:  "testUser",
			sourceURL: []string{"file://../../../schema/spanner/migrations", "file://testdata/users_test/valid_users"},
			wantUser: &dbtype.SessionUser{
				ID:       userID,
				Username: "testUser",
				Disabled: false,
			},
			preAssertions: []string{
				`SELECT COUNT(*) = 1 FROM SessionUsers WHERE Username = 'testUser'`,
			},
		},
		{
			name:      "not found",
			username:  "nonexistent",
			sourceURL: []string{"file://../../../schema/spanner/migrations", "file://testdata/users_test/valid_users"},
			wantErr:   true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			ctx := t.Context()
			conn, err := prepareDatabase(ctx, t, tt.sourceURL...)
			if err != nil {
				t.Fatalf("prepareDatabase() error = %v, wantErr %v", err, false)
			}
			c := NewSessionStorageDriver(conn.Client)

			runAssertions(ctx, t, conn.Client, tt.preAssertions)
			gotUser, err := c.UserByUserName(ctx, tt.username)
			if (err != nil) != tt.wantErr {
				t.Errorf("SessionStorageDriver.UserByUserName() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if tt.wantUser != nil {
				if gotUser.ID != tt.wantUser.ID {
					t.Errorf("SessionStorageDriver.UserByUserName() gotUser.ID = %v, want %v", gotUser.ID, tt.wantUser.ID)
				}
				if gotUser.Username != tt.wantUser.Username {
					t.Errorf("SessionStorageDriver.UserByUserName() gotUser.Username = %v, want %v", gotUser.Username, tt.wantUser.Username)
				}
				if gotUser.Disabled != tt.wantUser.Disabled {
					t.Errorf("SessionStorageDriver.UserByUserName() gotUser.Disabled = %v, want %v", gotUser.Disabled, tt.wantUser.Disabled)
				}
			}
			runAssertions(ctx, t, conn.Client, tt.postAssertions)
		})
	}
}

func TestSessionStorageDriver_CreateUser(t *testing.T) {
	t.Parallel()

	hash, err := securehash.New(securehash.Argon2()).Hash("password")
	if err != nil {
		t.Fatal(err)
	}

	tests := []struct {
		name           string
		username       string
		hash           *securehash.Hash
		sourceURL      []string
		wantErr        bool
		wantErrMsg     string
		preAssertions  []string
		postAssertions []string
	}{
		{
			name:      "success",
			username:  "newuser",
			hash:      hash,
			sourceURL: []string{"file://../../../schema/spanner/migrations", "file://testdata/users_test/valid_users"},
			preAssertions: []string{
				`SELECT COUNT(*) = 0 FROM SessionUsers WHERE Username = 'newuser'`,
			},
			postAssertions: []string{
				`SELECT COUNT(*) = 1 FROM SessionUsers WHERE Username = 'newuser'`,
			},
		},
		{
			name:       "user already exists",
			username:   "testuser",
			hash:       hash,
			sourceURL:  []string{"file://../../../schema/spanner/migrations", "file://testdata/users_test/valid_users"},
			wantErr:    true,
			wantErrMsg: `username "testuser" already exists`,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			ctx := t.Context()
			conn, err := prepareDatabase(ctx, t, tt.sourceURL...)
			if err != nil {
				t.Fatalf("prepareDatabase() error = %v, wantErr %v", err, false)
			}
			c := NewSessionStorageDriver(conn.Client)

			user := &dbtype.InsertSessionUser{
				Username:     tt.username,
				PasswordHash: tt.hash,
				Disabled:     false,
			}

			runAssertions(ctx, t, conn.Client, tt.preAssertions)
			_, err = c.CreateUser(ctx, user)
			if (err != nil) != tt.wantErr {
				t.Errorf("SessionStorageDriver.CreateUser() error = %v, wantErr %v", err, tt.wantErr)
			}
			if err != nil && tt.wantErrMsg != "" && httpio.Message(err) != tt.wantErrMsg {
				t.Errorf("SessionStorageDriver.CreateUser() error message = %s, want %s", httpio.Message(err), tt.wantErrMsg)
			}
			runAssertions(ctx, t, conn.Client, tt.postAssertions)
		})
	}
}

func TestSessionStorageDriver_SetUserUsername(t *testing.T) {
	t.Parallel()

	userID := ccc.Must(ccc.UUIDFromString("27b43588-b743-4133-8730-e0439065a844"))
	fullFixtures := []string{
		"file://../../../schema/spanner/migrations",
		"file://testdata/users_test/valid_users",
		"file://testdata/sessions_test/user_sessions",
	}
	usersOnlyFixtures := []string{
		"file://../../../schema/spanner/migrations",
		"file://testdata/users_test/valid_users",
	}

	tests := []struct {
		name           string
		id             ccc.UUID
		newUsername    string
		sourceURL      []string
		wantErr        bool
		wantErrMsg     string
		preAssertions  []string
		postAssertions []string
	}{
		{
			name:        "success updates user and active sessions, leaves expired and other users alone",
			id:          userID,
			newUsername: "<username>",
			sourceURL:   fullFixtures,
			preAssertions: []string{
				`SELECT Username = 'testUser' FROM SessionUsers WHERE Id = '27b43588-b743-4133-8730-e0439065a844'`,
				`SELECT (SELECT COUNT(*) FROM Sessions WHERE Username = 'testUser' AND Expired = FALSE) = 2`,
				`SELECT (SELECT COUNT(*) FROM Sessions WHERE Username = 'testUser' AND Expired = TRUE) = 1`,
			},
			postAssertions: []string{
				`SELECT Username = '<username>' FROM SessionUsers WHERE Id = '27b43588-b743-4133-8730-e0439065a844'`,
				`SELECT (SELECT COUNT(*) FROM Sessions WHERE Username = '<username>' AND Expired = FALSE) = 2`,
				`SELECT (SELECT COUNT(*) FROM Sessions WHERE Username = 'testUser' AND Expired = TRUE) = 1`,
				`SELECT (SELECT COUNT(*) FROM Sessions WHERE Username = 'testUser' AND Expired = FALSE) = 0`,
				`SELECT (SELECT COUNT(*) FROM Sessions WHERE Username = 'disableduser' AND Expired = FALSE) = 1`,
			},
		},
		{
			name:        "success when user has no active sessions",
			id:          userID,
			newUsername: "<username>",
			sourceURL:   usersOnlyFixtures,
			postAssertions: []string{
				`SELECT Username = '<username>' FROM SessionUsers WHERE Id = '27b43588-b743-4133-8730-e0439065a844'`,
			},
		},
		{
			name:        "user not found",
			id:          ccc.Must(ccc.NewUUID()),
			newUsername: "<username>",
			sourceURL:   fullFixtures,
			wantErr:     true,
			postAssertions: []string{
				`SELECT (SELECT COUNT(*) FROM Sessions WHERE Username = 'testUser' AND Expired = FALSE) = 2`,
			},
		},
		{
			name:        "username already exists",
			id:          userID,
			newUsername: "disableduser",
			sourceURL:   fullFixtures,
			wantErr:     true,
			wantErrMsg:  `username "disableduser" already exists`,
			postAssertions: []string{
				`SELECT Username = 'testUser' FROM SessionUsers WHERE Id = '27b43588-b743-4133-8730-e0439065a844'`,
				`SELECT (SELECT COUNT(*) FROM Sessions WHERE Username = 'testUser' AND Expired = FALSE) = 2`,
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			ctx := t.Context()
			conn, err := prepareDatabase(ctx, t, tt.sourceURL...)
			if err != nil {
				t.Fatalf("prepareDatabase() error = %v, wantErr %v", err, false)
			}
			c := NewSessionStorageDriver(conn.Client)

			runAssertions(ctx, t, conn.Client, tt.preAssertions)
			err = c.SetUserUsername(ctx, tt.id, tt.newUsername)
			if (err != nil) != tt.wantErr {
				t.Errorf("SessionStorageDriver.SetUserUsername() error = %v, wantErr %v", err, tt.wantErr)
			}
			if err != nil && tt.wantErrMsg != "" && httpio.Message(err) != tt.wantErrMsg {
				t.Errorf("SessionStorageDriver.SetUserUsername() error message = %q, want %q", httpio.Message(err), tt.wantErrMsg)
			}
			runAssertions(ctx, t, conn.Client, tt.postAssertions)
		})
	}
}

func TestSessionStorageDriver_SetUserPasswordHash(t *testing.T) {
	t.Parallel()

	newHash := &securehash.Hash{}
	if err := newHash.UnmarshalText([]byte("1$12288$3$1$UdvSMfwCubeTKv05/UpxwA==.tr8oe8g0VvfjQp3XpJonme6edSA4diQLLrS64ksf/TM=")); err != nil {
		t.Fatal(err)
	}

	tests := []struct {
		name           string
		id             ccc.UUID
		hash           *securehash.Hash
		sourceURL      []string
		wantErr        bool
		preAssertions  []string
		postAssertions []string
	}{
		{
			name:      "success",
			id:        ccc.Must(ccc.UUIDFromString("27b43588-b743-4133-8730-e0439065a844")),
			hash:      newHash,
			sourceURL: []string{"file://../../../schema/spanner/migrations", "file://testdata/users_test/valid_users"},
			preAssertions: []string{
				`
					SELECT PasswordHash = '1$12288$3$1$k5UDxGNpdI0XrTY59KZvXg==.JNUcFFjrpbAj9pr1L8HkV8aNkeACBbc3SV0SSAjoPwM=' 
					FROM SessionUsers 
					WHERE Id = '27b43588-b743-4133-8730-e0439065a844'
				`,
			},
			postAssertions: []string{
				`
					SELECT PasswordHash = '1$12288$3$1$UdvSMfwCubeTKv05/UpxwA==.tr8oe8g0VvfjQp3XpJonme6edSA4diQLLrS64ksf/TM='  
					FROM SessionUsers
					WHERE Id = '27b43588-b743-4133-8730-e0439065a844'
				`,
			},
		},
		{
			name:      "user not found",
			id:        ccc.Must(ccc.NewUUID()),
			hash:      newHash,
			sourceURL: []string{"file://../../../schema/spanner/migrations", "file://testdata/users_test/valid_users"},
			wantErr:   true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			ctx := t.Context()
			conn, err := prepareDatabase(ctx, t, tt.sourceURL...)
			if err != nil {
				t.Fatalf("prepareDatabase() error = %v, wantErr %v", err, false)
			}
			c := NewSessionStorageDriver(conn.Client)

			runAssertions(ctx, t, conn.Client, tt.preAssertions)
			err = c.SetUserPasswordHash(ctx, tt.id, tt.hash)
			if (err != nil) != tt.wantErr {
				t.Errorf("SessionStorageDriver.SetUserPasswordHash() error = %v, wantErr %v", err, tt.wantErr)
			}
			runAssertions(ctx, t, conn.Client, tt.postAssertions)
		})
	}
}

func TestSessionStorageDriver_DeactivateUser(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name           string
		id             ccc.UUID
		sourceURL      []string
		wantErr        bool
		preAssertions  []string
		postAssertions []string
	}{
		{
			name:      "success",
			id:        ccc.Must(ccc.UUIDFromString("27b43588-b743-4133-8730-e0439065a844")),
			sourceURL: []string{"file://../../../schema/spanner/migrations", "file://testdata/users_test/valid_users"},
			preAssertions: []string{
				`SELECT Disabled = false FROM SessionUsers WHERE Id = '27b43588-b743-4133-8730-e0439065a844'`,
			},
			postAssertions: []string{
				`SELECT Disabled = true FROM SessionUsers WHERE Id = '27b43588-b743-4133-8730-e0439065a844'`,
			},
		},
		{
			name:      "user not found",
			id:        ccc.Must(ccc.NewUUID()),
			sourceURL: []string{"file://../../../schema/spanner/migrations", "file://testdata/users_test/valid_users"},
			wantErr:   true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			ctx := t.Context()
			conn, err := prepareDatabase(ctx, t, tt.sourceURL...)
			if err != nil {
				t.Fatalf("prepareDatabase() error = %v, wantErr %v", err, false)
			}
			c := NewSessionStorageDriver(conn.Client)

			runAssertions(ctx, t, conn.Client, tt.preAssertions)
			err = c.DeactivateUser(ctx, tt.id)
			if (err != nil) != tt.wantErr {
				t.Errorf("SessionStorageDriver.DeactivateUser() error = %v, wantErr %v", err, tt.wantErr)
			}
			runAssertions(ctx, t, conn.Client, tt.postAssertions)
		})
	}
}

func TestSessionStorageDriver_DeleteUser(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name           string
		id             ccc.UUID
		sourceURL      []string
		wantErr        bool
		preAssertions  []string
		postAssertions []string
	}{
		{
			name:      "success",
			id:        ccc.Must(ccc.UUIDFromString("27b43588-b743-4133-8730-e0439065a844")),
			sourceURL: []string{"file://../../../schema/spanner/migrations", "file://testdata/users_test/valid_users"},
			preAssertions: []string{
				`SELECT COUNT(*) = 1 FROM SessionUsers WHERE Id = '27b43588-b743-4133-8730-e0439065a844'`,
			},
			postAssertions: []string{
				`SELECT COUNT(*) = 0 FROM SessionUsers WHERE Id = '27b43588-b743-4133-8730-e0439065a844'`,
			},
		},
		{
			name:      "user not found",
			id:        ccc.Must(ccc.NewUUID()),
			sourceURL: []string{"file://../../../schema/spanner/migrations", "file://testdata/users_test/valid_users"},
			preAssertions: []string{
				`SELECT COUNT(*) = 2 FROM SessionUsers`,
			},
			postAssertions: []string{
				`SELECT COUNT(*) = 2 FROM SessionUsers`,
			},
			wantErr: true,
		},
		{
			name:    "error on invalid schema",
			id:      ccc.Must(ccc.NewUUID()),
			wantErr: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			ctx := t.Context()
			conn, err := prepareDatabase(ctx, t, tt.sourceURL...)
			if err != nil {
				t.Fatalf("prepareDatabase() error = %v, wantErr %v", err, false)
			}
			c := NewSessionStorageDriver(conn.Client)

			runAssertions(ctx, t, conn.Client, tt.preAssertions)
			err = c.DeleteUser(ctx, tt.id)
			if (err != nil) != tt.wantErr {
				t.Errorf("SessionStorageDriver.DeleteUser() error = %v, wantErr %v", err, tt.wantErr)
			}
			runAssertions(ctx, t, conn.Client, tt.postAssertions)
		})
	}
}

func TestSessionStorageDriver_ActivateUser(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name           string
		id             ccc.UUID
		sourceURL      []string
		wantErr        bool
		preAssertions  []string
		postAssertions []string
	}{
		{
			name:      "success",
			id:        ccc.Must(ccc.UUIDFromString("54918893-2342-4621-8673-79520a84b84f")),
			sourceURL: []string{"file://../../../schema/spanner/migrations", "file://testdata/users_test/valid_users"},
			preAssertions: []string{
				`SELECT Disabled = TRUE FROM SessionUsers WHERE Id = '54918893-2342-4621-8673-79520a84b84f'`,
			},
			postAssertions: []string{
				`SELECT Disabled = FALSE FROM SessionUsers WHERE Id = '54918893-2342-4621-8673-79520a84b84f'`,
			},
		},
		{
			name:      "user not found",
			id:        ccc.Must(ccc.NewUUID()),
			sourceURL: []string{"file://../../../schema/spanner/migrations", "file://testdata/users_test/valid_users"},
			wantErr:   true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			ctx := t.Context()
			conn, err := prepareDatabase(ctx, t, tt.sourceURL...)
			if err != nil {
				t.Fatalf("prepareDatabase() error = %v, wantErr %v", err, false)
			}
			c := NewSessionStorageDriver(conn.Client)

			runAssertions(ctx, t, conn.Client, tt.preAssertions)
			err = c.ActivateUser(ctx, tt.id)
			if (err != nil) != tt.wantErr {
				t.Errorf("SessionStorageDriver.ActivateUser() error = %v, wantErr %v", err, tt.wantErr)
			}
			runAssertions(ctx, t, conn.Client, tt.postAssertions)
		})
	}
}

func TestSessionStorageDriver_DestroyAllSessionsForUser(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name           string
		username       string
		sourceURL      []string
		wantErr        bool
		preAssertions  []string
		postAssertions []string
	}{
		{
			name:      "success",
			username:  "test user 1",
			sourceURL: []string{"file://../../../schema/spanner/migrations", "file://testdata/sessions_test/valid_sessions"},
			preAssertions: []string{
				`SELECT COUNT(*) = 2 FROM Sessions WHERE Username = 'test user 1' AND Expired = false`,
			},
			postAssertions: []string{
				`SELECT COUNT(*) = 0 FROM Sessions WHERE Username = 'test user 1' AND Expired = false`,
			},
		},
		{
			name:      "user has no sessions",
			username:  "no_sessions_user",
			sourceURL: []string{"file://../../../schema/spanner/migrations", "file://testdata/sessions_test/valid_sessions"},
			preAssertions: []string{
				`SELECT COUNT(*) = 0 FROM Sessions WHERE Username = 'no_sessions_user'`,
			},
			postAssertions: []string{
				`SELECT COUNT(*) = 0 FROM Sessions WHERE Username = 'no_sessions_user'`,
			},
		},
		{
			name:      "invalid schema",
			username:  "test user",
			sourceURL: []string{"file://testdata/sessions_test/invalid_schema"},
			wantErr:   true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			ctx := t.Context()
			conn, err := prepareDatabase(ctx, t, tt.sourceURL...)
			if err != nil {
				t.Fatalf("prepareDatabase() error = %v, wantErr %v", err, false)
			}
			c := NewSessionStorageDriver(conn.Client)

			runAssertions(ctx, t, conn.Client, tt.preAssertions)
			err = c.DestroyAllUserSessions(ctx, tt.username)
			if (err != nil) != tt.wantErr {
				t.Errorf("SessionStorageDriver.DestroyAllSessionsForUser() error = %v, wantErr %v", err, tt.wantErr)
			}
			runAssertions(ctx, t, conn.Client, tt.postAssertions)
		})
	}
}

// mustCodec builds a codec for the given struct type, panicking on error so test
// tables can construct configs inline; codec validation is covered by the dbtype
// unit tests.
func mustCodec(structType reflect.Type) *dbtype.CustomDataCodec {
	codec, err := dbtype.NewCustomDataCodec(structType, dbtype.SpannerTagKey)
	if err != nil {
		panic(err)
	}

	return codec
}

// customTestData covers each supported Spanner column type in the test schema.
type customTestData struct {
	CustomString    string    `spanner:"CustomString"`
	CustomInt       int64     `spanner:"CustomInt"`
	CustomBool      bool      `spanner:"CustomBool"`
	CustomFloat     float64   `spanner:"CustomFloat"`
	CustomTimestamp time.Time `spanner:"CustomTimestamp"`
}

// customNullableTestData mirrors customTestData with nullable field types, per the
// contract that columns holding NULL must map to nullable Go types.
type customNullableTestData struct {
	CustomString    spanner.NullString  `spanner:"CustomString"`
	CustomInt       spanner.NullInt64   `spanner:"CustomInt"`
	CustomBool      spanner.NullBool    `spanner:"CustomBool"`
	CustomFloat     spanner.NullFloat64 `spanner:"CustomFloat"`
	CustomTimestamp spanner.NullTime    `spanner:"CustomTimestamp"`
}

type customStringData struct {
	CustomString string `spanner:"CustomString"`
}

// customCollisionData maps a column whose name collides with the base session
// table's Expired column.
type customCollisionData struct {
	CustomExpired string `spanner:"Expired"`
}

// customBadColumnData maps a column that does not exist in the test schema.
type customBadColumnData struct {
	Value string `spanner:"DoesNotExist"`
}

func TestSessionStorageDriver_Session_CustomSessionColumns(t *testing.T) {
	t.Parallel()

	customDataConfig := &CustomSessionDataConfig{
		TableName: "SessionCustomData",
		Codec:     mustCodec(reflect.TypeFor[customTestData]()),
	}

	tests := []struct {
		name           string
		sessionID      ccc.UUID
		customData     *CustomSessionDataConfig
		sourceURL      []string
		wantSession    *dbtype.SessionData
		wantCustomData any
		wantErr        bool
	}{
		{
			name:      "success with custom column",
			sessionID: ccc.Must(ccc.UUIDFromString("11111111-1111-1111-1111-111111111111")),
			customData: &CustomSessionDataConfig{
				TableName: "SessionCustomData",
				Codec:     mustCodec(reflect.TypeFor[customStringData]()),
			},
			sourceURL: []string{"file://testdata/sessions_test/custom_columns_schema"},
			wantSession: &dbtype.SessionData{Session: &dbtype.Session{
				ID:       ccc.Must(ccc.UUIDFromString("11111111-1111-1111-1111-111111111111")),
				Username: "custom_user_1",
				Expired:  false,
			}},
			wantCustomData: &customStringData{CustomString: "admin"},
		},
		{
			name:       "success with multiple custom column types",
			sessionID:  ccc.Must(ccc.UUIDFromString("11111111-1111-1111-1111-111111111111")),
			customData: customDataConfig,
			sourceURL:  []string{"file://testdata/sessions_test/custom_columns_schema"},
			wantSession: &dbtype.SessionData{Session: &dbtype.Session{
				ID:       ccc.Must(ccc.UUIDFromString("11111111-1111-1111-1111-111111111111")),
				Username: "custom_user_1",
				Expired:  false,
			}},
			wantCustomData: &customTestData{
				CustomString:    "admin",
				CustomInt:       10,
				CustomBool:      true,
				CustomFloat:     99.5,
				CustomTimestamp: time.Date(2024, 6, 15, 8, 30, 0, 0, time.UTC),
			},
		},
		{
			name:       "success with custom column expired session",
			sessionID:  ccc.Must(ccc.UUIDFromString("22222222-2222-2222-2222-222222222222")),
			customData: customDataConfig,
			sourceURL:  []string{"file://testdata/sessions_test/custom_columns_schema"},
			wantSession: &dbtype.SessionData{Session: &dbtype.Session{
				ID:       ccc.Must(ccc.UUIDFromString("22222222-2222-2222-2222-222222222222")),
				Username: "custom_user_2",
				Expired:  true,
			}},
			wantCustomData: &customTestData{
				CustomString:    "viewer",
				CustomInt:       5,
				CustomBool:      false,
				CustomFloat:     42.0,
				CustomTimestamp: time.Date(2024, 3, 20, 14, 0, 0, 0, time.UTC),
			},
		},
		{
			name:       "session without custom row yields zero-value struct",
			sessionID:  ccc.Must(ccc.UUIDFromString("33333333-3333-3333-3333-333333333333")),
			customData: customDataConfig,
			sourceURL:  []string{"file://testdata/sessions_test/custom_columns_schema"},
			wantSession: &dbtype.SessionData{Session: &dbtype.Session{
				ID:       ccc.Must(ccc.UUIDFromString("33333333-3333-3333-3333-333333333333")),
				Username: "custom_user_3",
				Expired:  false,
			}},
			wantCustomData: &customTestData{},
		},
		{
			name:      "session not found with custom columns",
			sessionID: ccc.Must(ccc.NewUUID()),
			customData: &CustomSessionDataConfig{
				TableName: "SessionCustomData",
				Codec:     mustCodec(reflect.TypeFor[customStringData]()),
			},
			sourceURL: []string{"file://testdata/sessions_test/custom_columns_schema"},
			wantErr:   true,
		},
		{
			name:      "success without custom data config",
			sessionID: ccc.Must(ccc.UUIDFromString("11111111-1111-1111-1111-111111111111")),
			sourceURL: []string{"file://testdata/sessions_test/custom_columns_schema"},
			wantSession: &dbtype.SessionData{Session: &dbtype.Session{
				ID:       ccc.Must(ccc.UUIDFromString("11111111-1111-1111-1111-111111111111")),
				Username: "custom_user_1",
				Expired:  false,
			}},
		},
		{
			name:      "success with custom column name matching base session column",
			sessionID: ccc.Must(ccc.UUIDFromString("11111111-1111-1111-1111-111111111111")),
			customData: &CustomSessionDataConfig{
				TableName: "SessionCustomData",
				Codec:     mustCodec(reflect.TypeFor[customCollisionData]()),
			},
			sourceURL: []string{"file://testdata/sessions_test/custom_columns_collision_schema"},
			wantSession: &dbtype.SessionData{Session: &dbtype.Session{
				ID:       ccc.Must(ccc.UUIDFromString("11111111-1111-1111-1111-111111111111")),
				Username: "collision_user_1",
				Expired:  false,
			}},
			wantCustomData: &customCollisionData{CustomExpired: "custom_not_expired"},
		},
		{
			name:      "success with custom column name matching base session column expired session",
			sessionID: ccc.Must(ccc.UUIDFromString("22222222-2222-2222-2222-222222222222")),
			customData: &CustomSessionDataConfig{
				TableName: "SessionCustomData",
				Codec:     mustCodec(reflect.TypeFor[customCollisionData]()),
			},
			sourceURL: []string{"file://testdata/sessions_test/custom_columns_collision_schema"},
			wantSession: &dbtype.SessionData{Session: &dbtype.Session{
				ID:       ccc.Must(ccc.UUIDFromString("22222222-2222-2222-2222-222222222222")),
				Username: "collision_user_2",
				Expired:  true,
			}},
			wantCustomData: &customCollisionData{CustomExpired: "custom_expired"},
		},
		{
			name:      "NULL columns decode into nullable-typed struct",
			sessionID: ccc.Must(ccc.UUIDFromString("44444444-4444-4444-4444-444444444444")),
			customData: &CustomSessionDataConfig{
				TableName: "SessionCustomData",
				Codec:     mustCodec(reflect.TypeFor[customNullableTestData]()),
			},
			sourceURL: []string{"file://testdata/sessions_test/custom_columns_null_schema"},
			wantSession: &dbtype.SessionData{Session: &dbtype.Session{
				ID:       ccc.Must(ccc.UUIDFromString("44444444-4444-4444-4444-444444444444")),
				Username: "null_user_1",
				Expired:  false,
			}},
			wantCustomData: &customNullableTestData{
				CustomString: spanner.NullString{StringVal: "partial", Valid: true},
			},
		},
		{
			name:       "NULL column into non-nullable field errors",
			sessionID:  ccc.Must(ccc.UUIDFromString("44444444-4444-4444-4444-444444444444")),
			customData: customDataConfig,
			sourceURL:  []string{"file://testdata/sessions_test/custom_columns_null_schema"},
			wantErr:    true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			ctx := t.Context()
			conn, err := prepareDatabase(ctx, t, tt.sourceURL...)
			if err != nil {
				t.Fatalf("prepareDatabase() error = %v, wantErr %v", err, false)
			}
			c := NewSessionStorageDriver(conn.Client)
			if tt.customData != nil {
				c.SetCustomSessionData(tt.customData)
			}

			gotSession, err := c.Session(ctx, tt.sessionID)
			if (err != nil) != tt.wantErr {
				t.Errorf("SessionStorageDriver.Session() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if tt.wantSession != nil {
				if gotSession.ID != tt.wantSession.ID {
					t.Errorf("SessionStorageDriver.Session() gotSession.ID = %v, want %v", gotSession.ID, tt.wantSession.ID)
				}
				if gotSession.Username != tt.wantSession.Username {
					t.Errorf("SessionStorageDriver.Session() gotSession.Username = %v, want %v", gotSession.Username, tt.wantSession.Username)
				}
				if gotSession.Expired != tt.wantSession.Expired {
					t.Errorf("SessionStorageDriver.Session() gotSession.Expired = %v, want %v", gotSession.Expired, tt.wantSession.Expired)
				}
			}
			if tt.wantCustomData != nil {
				if diff := cmp.Diff(tt.wantCustomData, gotSession.CustomData); diff != "" {
					t.Errorf("SessionStorageDriver.Session() CustomData mismatch (-want +got):\n%s", diff)
				}
			} else if !tt.wantErr && gotSession != nil && gotSession.CustomData != nil {
				t.Errorf("SessionStorageDriver.Session() gotSession.CustomData = %v, want nil", gotSession.CustomData)
			}
		})
	}
}

func TestSessionStorageDriver_InsertSession_CustomData(t *testing.T) {
	t.Parallel()

	newSessionRequest := sessioninfo.NewSessionRequest{
		Reason:   sessioninfo.ReasonLogin,
		Username: "newuser",
		UserID:   ccc.Must(ccc.UUIDFromString("99999999-9999-9999-9999-999999999999")),
	}

	tests := []struct {
		name           string
		insertSession  *dbtype.InsertSession
		req            sessioninfo.NewSessionRequest
		config         *CustomSessionDataConfig
		sourceURL      []string
		wantErr        bool
		preAssertions  []string
		postAssertions []string
		wantCustomData any
	}{
		{
			name: "success inserting session with custom data",
			insertSession: &dbtype.InsertSession{
				Username:  "newuser",
				CreatedAt: time.Now(),
				UpdatedAt: time.Now(),
				Expired:   false,
			},
			req: newSessionRequest,
			config: &CustomSessionDataConfig{
				TableName: "SessionCustomData",
				Codec:     mustCodec(reflect.TypeFor[customStringData]()),
				Resolver: func(_ context.Context, _ *spanner.ReadWriteTransaction, _ sessioninfo.NewSessionRequest) (any, error) {
					return &customStringData{CustomString: "editor"}, nil
				},
			},
			sourceURL: []string{"file://testdata/sessions_test/custom_columns_schema"},
			preAssertions: []string{
				`SELECT COUNT(*) = 3 FROM Sessions`,
			},
			postAssertions: []string{
				`SELECT COUNT(*) = 4 FROM Sessions`,
			},
			wantCustomData: &customStringData{CustomString: "editor"},
		},
		{
			name: "success inserting session with multiple custom data types",
			insertSession: &dbtype.InsertSession{
				Username:  "newuser_multi",
				CreatedAt: time.Now(),
				UpdatedAt: time.Now(),
				Expired:   false,
			},
			req: newSessionRequest,
			config: &CustomSessionDataConfig{
				TableName: "SessionCustomData",
				Codec:     mustCodec(reflect.TypeFor[customTestData]()),
				Resolver: func(_ context.Context, _ *spanner.ReadWriteTransaction, _ sessioninfo.NewSessionRequest) (any, error) {
					return &customTestData{
						CustomString:    "manager",
						CustomInt:       42,
						CustomBool:      true,
						CustomFloat:     88.3,
						CustomTimestamp: time.Date(2025, 1, 10, 12, 0, 0, 0, time.UTC),
					}, nil
				},
			},
			sourceURL: []string{"file://testdata/sessions_test/custom_columns_schema"},
			preAssertions: []string{
				`SELECT COUNT(*) = 3 FROM Sessions`,
			},
			postAssertions: []string{
				`SELECT COUNT(*) = 4 FROM Sessions`,
			},
			wantCustomData: &customTestData{
				CustomString:    "manager",
				CustomInt:       42,
				CustomBool:      true,
				CustomFloat:     88.3,
				CustomTimestamp: time.Date(2025, 1, 10, 12, 0, 0, 0, time.UTC),
			},
		},
		{
			name: "resolver receives the new session request",
			insertSession: &dbtype.InsertSession{
				Username:  "reason_user",
				CreatedAt: time.Now(),
				UpdatedAt: time.Now(),
				Expired:   false,
			},
			req: sessioninfo.NewSessionRequest{
				Reason:   sessioninfo.ReasonRegeneration,
				Username: "reason_user",
				UserID:   ccc.Must(ccc.UUIDFromString("88888888-8888-8888-8888-888888888888")),
			},
			config: &CustomSessionDataConfig{
				TableName: "SessionCustomData",
				Codec:     mustCodec(reflect.TypeFor[customStringData]()),
				Resolver: func(_ context.Context, _ *spanner.ReadWriteTransaction, req sessioninfo.NewSessionRequest) (any, error) {
					if req.Reason != sessioninfo.ReasonRegeneration || req.Username != "reason_user" || req.UserID != ccc.Must(ccc.UUIDFromString("88888888-8888-8888-8888-888888888888")) {
						return nil, errors.Newf("unexpected request %+v", req)
					}

					return &customStringData{CustomString: string(req.Reason)}, nil
				},
			},
			sourceURL: []string{"file://testdata/sessions_test/custom_columns_schema"},
			preAssertions: []string{
				`SELECT COUNT(*) = 3 FROM Sessions`,
			},
			postAssertions: []string{
				`SELECT COUNT(*) = 4 FROM Sessions`,
			},
			wantCustomData: &customStringData{CustomString: "Regeneration"},
		},
		{
			name: "atomicity: custom data insert failure rolls back session insert",
			insertSession: &dbtype.InsertSession{
				Username:  "atomic_user",
				CreatedAt: time.Now(),
				UpdatedAt: time.Now(),
				Expired:   false,
			},
			req: newSessionRequest,
			config: &CustomSessionDataConfig{
				TableName: "NonExistentCustomData",
				Codec:     mustCodec(reflect.TypeFor[customStringData]()),
				Resolver: func(_ context.Context, _ *spanner.ReadWriteTransaction, _ sessioninfo.NewSessionRequest) (any, error) {
					return &customStringData{CustomString: "x"}, nil
				},
			},
			sourceURL: []string{"file://testdata/sessions_test/custom_columns_schema"},
			wantErr:   true,
			preAssertions: []string{
				`SELECT COUNT(*) = 3 FROM Sessions`,
			},
			postAssertions: []string{
				`SELECT COUNT(*) = 3 FROM Sessions`,
			},
		},
		{
			name: "atomicity: resolver error aborts session insert",
			insertSession: &dbtype.InsertSession{
				Username:  "resolver_err_user",
				CreatedAt: time.Now(),
				UpdatedAt: time.Now(),
				Expired:   false,
			},
			req: newSessionRequest,
			config: &CustomSessionDataConfig{
				TableName: "SessionCustomData",
				Codec:     mustCodec(reflect.TypeFor[customStringData]()),
				Resolver: func(_ context.Context, _ *spanner.ReadWriteTransaction, _ sessioninfo.NewSessionRequest) (any, error) {
					return nil, errors.New("resolver failure")
				},
			},
			sourceURL: []string{"file://testdata/sessions_test/custom_columns_schema"},
			wantErr:   true,
			preAssertions: []string{
				`SELECT COUNT(*) = 3 FROM Sessions`,
			},
			postAssertions: []string{
				`SELECT COUNT(*) = 3 FROM Sessions`,
			},
		},
		{
			name: "nil resolver degrades to plain insert without custom data row",
			insertSession: &dbtype.InsertSession{
				Username:  "plain_user",
				CreatedAt: time.Now(),
				UpdatedAt: time.Now(),
				Expired:   false,
			},
			req: newSessionRequest,
			config: &CustomSessionDataConfig{
				TableName: "SessionCustomData",
				Codec:     mustCodec(reflect.TypeFor[customStringData]()),
			},
			sourceURL: []string{"file://testdata/sessions_test/custom_columns_schema"},
			preAssertions: []string{
				`SELECT COUNT(*) = 3 FROM Sessions`,
				`SELECT COUNT(*) = 2 FROM SessionCustomData`,
			},
			postAssertions: []string{
				`SELECT COUNT(*) = 4 FROM Sessions`,
				`SELECT COUNT(*) = 2 FROM SessionCustomData`,
			},
		},
		{
			name: "resolver returning nil writes no custom data row",
			insertSession: &dbtype.InsertSession{
				Username:  "nilresolve_user",
				CreatedAt: time.Now(),
				UpdatedAt: time.Now(),
				Expired:   false,
			},
			req: newSessionRequest,
			config: &CustomSessionDataConfig{
				TableName: "SessionCustomData",
				Codec:     mustCodec(reflect.TypeFor[customStringData]()),
				Resolver: func(_ context.Context, _ *spanner.ReadWriteTransaction, _ sessioninfo.NewSessionRequest) (any, error) {
					return nil, nil //nolint:nilnil // nil data means no custom data row
				},
			},
			sourceURL: []string{"file://testdata/sessions_test/custom_columns_schema"},
			preAssertions: []string{
				`SELECT COUNT(*) = 3 FROM Sessions`,
				`SELECT COUNT(*) = 2 FROM SessionCustomData`,
			},
			postAssertions: []string{
				`SELECT COUNT(*) = 4 FROM Sessions`,
				`SELECT COUNT(*) = 2 FROM SessionCustomData`,
			},
		},
		{
			name: "per-call custom data written atomically and resolver skipped",
			insertSession: &dbtype.InsertSession{
				Username:  "percall_user",
				CreatedAt: time.Now(),
				UpdatedAt: time.Now(),
				Expired:   false,
			},
			req: sessioninfo.NewSessionRequest{
				Reason:     sessioninfo.ReasonExternalAuth,
				Username:   "percall_user",
				CustomData: &customStringData{CustomString: "per_call_value"},
			},
			config: &CustomSessionDataConfig{
				TableName: "SessionCustomData",
				Codec:     mustCodec(reflect.TypeFor[customStringData]()),
				Resolver: func(_ context.Context, _ *spanner.ReadWriteTransaction, _ sessioninfo.NewSessionRequest) (any, error) {
					return nil, errors.New("resolver must not run when per-call data is provided")
				},
			},
			sourceURL: []string{"file://testdata/sessions_test/custom_columns_schema"},
			preAssertions: []string{
				`SELECT COUNT(*) = 3 FROM Sessions`,
			},
			postAssertions: []string{
				`SELECT COUNT(*) = 4 FROM Sessions`,
			},
			wantCustomData: &customStringData{CustomString: "per_call_value"},
		},
		{
			name: "per-call custom data without config errors before insert",
			insertSession: &dbtype.InsertSession{
				Username:  "percall_noconfig_user",
				CreatedAt: time.Now(),
				UpdatedAt: time.Now(),
				Expired:   false,
			},
			req: sessioninfo.NewSessionRequest{
				Reason:     sessioninfo.ReasonExternalAuth,
				Username:   "percall_noconfig_user",
				CustomData: &customStringData{CustomString: "x"},
			},
			sourceURL: []string{"file://testdata/sessions_test/custom_columns_schema"},
			wantErr:   true,
			preAssertions: []string{
				`SELECT COUNT(*) = 3 FROM Sessions`,
			},
			postAssertions: []string{
				`SELECT COUNT(*) = 3 FROM Sessions`,
			},
		},
		{
			name: "per-call custom data of the wrong type errors before insert",
			insertSession: &dbtype.InsertSession{
				Username:  "percall_wrongtype_user",
				CreatedAt: time.Now(),
				UpdatedAt: time.Now(),
				Expired:   false,
			},
			req: sessioninfo.NewSessionRequest{
				Reason:     sessioninfo.ReasonExternalAuth,
				Username:   "percall_wrongtype_user",
				CustomData: &customTestData{CustomString: "x"},
			},
			config: &CustomSessionDataConfig{
				TableName: "SessionCustomData",
				Codec:     mustCodec(reflect.TypeFor[customStringData]()),
			},
			sourceURL: []string{"file://testdata/sessions_test/custom_columns_schema"},
			wantErr:   true,
			preAssertions: []string{
				`SELECT COUNT(*) = 3 FROM Sessions`,
			},
			postAssertions: []string{
				`SELECT COUNT(*) = 3 FROM Sessions`,
			},
		},
		{
			name: "atomicity: per-call custom data with bad column rolls back session insert",
			insertSession: &dbtype.InsertSession{
				Username:  "percall_atomic_user",
				CreatedAt: time.Now(),
				UpdatedAt: time.Now(),
				Expired:   false,
			},
			req: sessioninfo.NewSessionRequest{
				Reason:     sessioninfo.ReasonExternalAuth,
				Username:   "percall_atomic_user",
				CustomData: &customBadColumnData{Value: "x"},
			},
			config: &CustomSessionDataConfig{
				TableName: "SessionCustomData",
				Codec:     mustCodec(reflect.TypeFor[customBadColumnData]()),
			},
			sourceURL: []string{"file://testdata/sessions_test/custom_columns_schema"},
			wantErr:   true,
			preAssertions: []string{
				`SELECT COUNT(*) = 3 FROM Sessions`,
			},
			postAssertions: []string{
				`SELECT COUNT(*) = 3 FROM Sessions`,
			},
		},
		{
			name: "success inserting session with custom column name matching base session column",
			insertSession: &dbtype.InsertSession{
				Username:  "collision_insert_user",
				CreatedAt: time.Now(),
				UpdatedAt: time.Now(),
				Expired:   false,
			},
			req: newSessionRequest,
			config: &CustomSessionDataConfig{
				TableName: "SessionCustomData",
				Codec:     mustCodec(reflect.TypeFor[customCollisionData]()),
				Resolver: func(_ context.Context, _ *spanner.ReadWriteTransaction, _ sessioninfo.NewSessionRequest) (any, error) {
					return &customCollisionData{CustomExpired: "custom_value"}, nil
				},
			},
			sourceURL: []string{"file://testdata/sessions_test/custom_columns_collision_schema"},
			preAssertions: []string{
				`SELECT COUNT(*) = 2 FROM Sessions`,
			},
			postAssertions: []string{
				`SELECT COUNT(*) = 3 FROM Sessions`,
			},
			wantCustomData: &customCollisionData{CustomExpired: "custom_value"},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			ctx := t.Context()
			conn, err := prepareDatabase(ctx, t, tt.sourceURL...)
			if err != nil {
				t.Fatalf("prepareDatabase() error = %v, wantErr %v", err, false)
			}
			c := NewSessionStorageDriver(conn.Client)
			if tt.config != nil {
				c.SetCustomSessionData(tt.config)
			}

			runAssertions(ctx, t, conn.Client, tt.preAssertions)
			id, err := c.InsertSession(ctx, tt.insertSession, &tt.req)
			if (err != nil) != tt.wantErr {
				t.Errorf("SessionStorageDriver.InsertSession() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if tt.wantErr {
				runAssertions(ctx, t, conn.Client, tt.postAssertions)
				return
			}

			if id == ccc.NilUUID {
				t.Error("SessionStorageDriver.InsertSession() id is nil, want valid UUID")
			}
			runAssertions(ctx, t, conn.Client, []string{fmt.Sprintf(`SELECT COUNT(*) = 1 FROM Sessions WHERE Id = '%s'`, id)})

			// Read back the session and verify custom data
			if tt.wantCustomData != nil {
				gotSession, err := c.Session(ctx, id)
				if err != nil {
					t.Fatalf("SessionStorageDriver.Session() error = %v", err)
				}
				if diff := cmp.Diff(tt.wantCustomData, gotSession.CustomData); diff != "" {
					t.Errorf("SessionStorageDriver.Session() CustomData mismatch (-want +got):\n%s", diff)
				}
			}

			runAssertions(ctx, t, conn.Client, tt.postAssertions)
		})
	}
}

func TestSessionStorageDriver_UpdateCustomSessionData(t *testing.T) {
	t.Parallel()

	customDataConfig := &CustomSessionDataConfig{
		TableName: "SessionCustomData",
		Codec:     mustCodec(reflect.TypeFor[customTestData]()),
	}

	tests := []struct {
		name           string
		sessionID      string
		config         *CustomSessionDataConfig
		mutate         func(data any) error
		sourceURL      []string
		wantErr        bool
		wantCustomData any
		postAssertions []string
	}{
		{
			name:      "partial mutate preserves untouched fields",
			sessionID: "11111111-1111-1111-1111-111111111111",
			config:    customDataConfig,
			mutate: func(data any) error {
				d, ok := data.(*customTestData)
				if !ok {
					return errors.Newf("mutate received %T, want *customTestData", data)
				}
				d.CustomString = "updated_role"

				return nil
			},
			sourceURL: []string{"file://testdata/sessions_test/custom_columns_schema"},
			wantCustomData: &customTestData{
				CustomString:    "updated_role",
				CustomInt:       10,
				CustomBool:      true,
				CustomFloat:     99.5,
				CustomTimestamp: time.Date(2024, 6, 15, 8, 30, 0, 0, time.UTC),
			},
		},
		{
			name:      "creates row from zero value when none exists",
			sessionID: "33333333-3333-3333-3333-333333333333",
			config:    customDataConfig,
			mutate: func(data any) error {
				d, ok := data.(*customTestData)
				if !ok {
					return errors.Newf("mutate received %T, want *customTestData", data)
				}
				if *d != (customTestData{}) {
					return errors.Newf("mutate received %+v, want zero value", *d)
				}
				d.CustomString = "new_role"
				d.CustomInt = 42

				return nil
			},
			sourceURL: []string{"file://testdata/sessions_test/custom_columns_schema"},
			wantCustomData: &customTestData{
				CustomString: "new_role",
				CustomInt:    42,
			},
		},
		{
			name:      "mutate error writes nothing",
			sessionID: "11111111-1111-1111-1111-111111111111",
			config:    customDataConfig,
			mutate: func(_ any) error {
				return errors.New("mutate failure")
			},
			sourceURL: []string{"file://testdata/sessions_test/custom_columns_schema"},
			wantErr:   true,
			postAssertions: []string{
				`SELECT COUNT(*) = 1 FROM SessionCustomData WHERE SessionId = '11111111-1111-1111-1111-111111111111' AND CustomString = 'admin'`,
			},
		},
		{
			name:      "error when custom data config not set",
			sessionID: "11111111-1111-1111-1111-111111111111",
			mutate: func(_ any) error {
				return nil
			},
			sourceURL: []string{"file://testdata/sessions_test/custom_columns_schema"},
			wantErr:   true,
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
			c := NewSessionStorageDriver(conn.Client)
			if tt.config != nil {
				c.SetCustomSessionData(tt.config)
			}

			sessionID := ccc.Must(ccc.UUIDFromString(tt.sessionID))
			err = c.UpdateCustomSessionData(ctx, sessionID, tt.mutate)
			if (err != nil) != tt.wantErr {
				t.Errorf("SessionStorageDriver.UpdateCustomSessionData() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			runAssertions(ctx, t, conn.Client, tt.postAssertions)
			if tt.wantErr {
				return
			}

			// Read back the session and verify custom data
			if tt.wantCustomData != nil {
				gotSession, err := c.Session(ctx, sessionID)
				if err != nil {
					t.Fatalf("SessionStorageDriver.Session() error = %v", err)
				}
				if diff := cmp.Diff(tt.wantCustomData, gotSession.CustomData); diff != "" {
					t.Errorf("SessionStorageDriver.Session() CustomData mismatch (-want +got):\n%s", diff)
				}
			}
		})
	}
}
