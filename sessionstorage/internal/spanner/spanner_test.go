package spanner

import (
	"context"
	"fmt"
	"testing"
	"time"

	"github.com/cccteam/ccc"
	"github.com/cccteam/ccc/resource"
	"github.com/cccteam/ccc/securehash"
	"github.com/cccteam/httpio"
	"github.com/cccteam/session/internal/dbtype"
	"github.com/cccteam/session/sessioninfo"
	"github.com/go-playground/errors/v5"
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
		wantSession *dbtype.Session
		wantErr     bool
	}{
		{
			name:      "success",
			sessionID: ccc.Must(ccc.UUIDFromString("eb0c72a4-1f32-469e-b51b-7baa589a944c")),
			sourceURL: []string{"file://../../../schema/spanner/oidc/migrations", "file://testdata/sessions_test/oidc_valid_sessions"},
			wantSession: &dbtype.Session{
				ID:       ccc.Must(ccc.UUIDFromString("eb0c72a4-1f32-469e-b51b-7baa589a944c")),
				Username: "test user 2",
				Expired:  true,
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
			id, err := c.InsertSession(ctx, tt.insertSession)
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

	tests := []struct {
		name           string
		id             ccc.UUID
		username       string
		sourceURL      []string
		wantErr        bool
		wantErrMsg     string
		preAssertions  []string
		postAssertions []string
	}{
		{
			name:      "success",
			id:        ccc.Must(ccc.UUIDFromString("27b43588-b743-4133-8730-e0439065a844")),
			username:  "<username>",
			sourceURL: []string{"file://../../../schema/spanner/migrations", "file://testdata/users_test/valid_users"},
			preAssertions: []string{
				`
					SELECT Username = 'testUser'
					FROM SessionUsers 
					WHERE Id = '27b43588-b743-4133-8730-e0439065a844'
				`,
			},
			postAssertions: []string{
				`
					SELECT Username = '<username>'
					FROM SessionUsers
					WHERE Id = '27b43588-b743-4133-8730-e0439065a844'
				`,
			},
		},
		{
			name:      "user not found",
			id:        ccc.Must(ccc.NewUUID()),
			username:  "<username>",
			sourceURL: []string{"file://../../../schema/spanner/migrations", "file://testdata/users_test/valid_users"},
			wantErr:   true,
		},
		{
			name:       "user already exists",
			id:         ccc.Must(ccc.UUIDFromString("27b43588-b743-4133-8730-e0439065a844")),
			username:   "disableduser",
			sourceURL:  []string{"file://../../../schema/spanner/migrations", "file://testdata/users_test/valid_users"},
			wantErr:    true,
			wantErrMsg: `username "disableduser" already exists`,
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
			err = c.SetUserUsername(ctx, tt.id, tt.username)
			if (err != nil) != tt.wantErr {
				t.Errorf("SessionStorageDriver.SetUserUsername() error = %v, wantErr %v", err, tt.wantErr)
			}
			if err != nil && tt.wantErrMsg != "" && httpio.Message(err) != tt.wantErrMsg {
				t.Errorf("SessionStorageDriver.CreateUser() error message = %s, want %s", httpio.Message(err), tt.wantErrMsg)
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

func TestSessionStorageDriver_Session_CustomSessionColumns(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name           string
		sessionID      ccc.UUID
		customColumns  []string
		sourceURL      []string
		wantSession    *dbtype.Session
		wantCustomData map[string]any
		wantErr        bool
	}{
		{
			name:          "success with custom column",
			sessionID:     ccc.Must(ccc.UUIDFromString("11111111-1111-1111-1111-111111111111")),
			customColumns: []string{"CustomString"},
			sourceURL:     []string{"file://testdata/sessions_test/custom_columns_schema"},
			wantSession: &dbtype.Session{
				ID:       ccc.Must(ccc.UUIDFromString("11111111-1111-1111-1111-111111111111")),
				Username: "custom_user_1",
				Expired:  false,
			},
			wantCustomData: map[string]any{
				"CustomString": "admin",
			},
		},
		{
			name:          "success with multiple custom column types",
			sessionID:     ccc.Must(ccc.UUIDFromString("11111111-1111-1111-1111-111111111111")),
			customColumns: []string{"CustomString", "CustomInt", "CustomBool", "CustomFloat", "CustomTimestamp"},
			sourceURL:     []string{"file://testdata/sessions_test/custom_columns_schema"},
			wantSession: &dbtype.Session{
				ID:       ccc.Must(ccc.UUIDFromString("11111111-1111-1111-1111-111111111111")),
				Username: "custom_user_1",
				Expired:  false,
			},
			wantCustomData: map[string]any{
				"CustomString":    "admin",
				"CustomInt":       "10",
				"CustomBool":      true,
				"CustomFloat":     float64(99.5),
				"CustomTimestamp": "2024-06-15T08:30:00Z",
			},
		},
		{
			name:          "success with custom column expired session",
			sessionID:     ccc.Must(ccc.UUIDFromString("22222222-2222-2222-2222-222222222222")),
			customColumns: []string{"CustomString", "CustomInt", "CustomBool", "CustomFloat", "CustomTimestamp"},
			sourceURL:     []string{"file://testdata/sessions_test/custom_columns_schema"},
			wantSession: &dbtype.Session{
				ID:       ccc.Must(ccc.UUIDFromString("22222222-2222-2222-2222-222222222222")),
				Username: "custom_user_2",
				Expired:  true,
			},
			wantCustomData: map[string]any{
				"CustomString":    "viewer",
				"CustomInt":       "5",
				"CustomBool":      false,
				"CustomFloat":     float64(42.0),
				"CustomTimestamp": "2024-03-20T14:00:00Z",
			},
		},
		{
			name:          "session not found with custom columns",
			sessionID:     ccc.Must(ccc.NewUUID()),
			customColumns: []string{"CustomString"},
			sourceURL:     []string{"file://testdata/sessions_test/custom_columns_schema"},
			wantErr:       true,
		},
		{
			name:      "success without custom columns configured",
			sessionID: ccc.Must(ccc.UUIDFromString("11111111-1111-1111-1111-111111111111")),
			sourceURL: []string{"file://testdata/sessions_test/custom_columns_schema"},
			wantSession: &dbtype.Session{
				ID:       ccc.Must(ccc.UUIDFromString("11111111-1111-1111-1111-111111111111")),
				Username: "custom_user_1",
				Expired:  false,
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
			if len(tt.customColumns) > 0 {
				c.SetCustomSessionColumns(tt.customColumns)
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
				if gotSession.CustomData == nil {
					t.Fatal("SessionStorageDriver.Session() gotSession.CustomData is nil, want non-nil")
				}
				for key, wantVal := range tt.wantCustomData {
					gotVal, ok := gotSession.CustomData[key]
					if !ok {
						t.Errorf("SessionStorageDriver.Session() CustomData missing key %q", key)
						continue
					}
					if fmt.Sprintf("%v", gotVal) != fmt.Sprintf("%v", wantVal) {
						t.Errorf("SessionStorageDriver.Session() CustomData[%q] = %v (%T), want %v (%T)", key, gotVal, gotVal, wantVal, wantVal)
					}
				}
			} else if !tt.wantErr && gotSession != nil && gotSession.CustomData != nil {
				t.Errorf("SessionStorageDriver.Session() gotSession.CustomData = %v, want nil", gotSession.CustomData)
			}
		})
	}
}

func TestSessionStorageDriver_InsertCustomSession(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name               string
		insertSession      *dbtype.InsertSession
		customDataResolver dbtype.CustomSessionDataResolver
		customColumns      []string
		sourceURL          []string
		wantErr            bool
		preAssertions      []string
		postAssertions     []string
		wantCustomData     map[string]any
	}{
		{
			name: "success inserting session with custom data",
			insertSession: &dbtype.InsertSession{
				Username:  "newuser",
				CreatedAt: time.Now(),
				UpdatedAt: time.Now(),
				Expired:   false,
			},
			customDataResolver: func(_ context.Context, _ resource.ReadOnlyTransaction) ([]*sessioninfo.CustomData, error) {
				return []*sessioninfo.CustomData{
					{ColumnName: "CustomString", Value: "editor"},
				}, nil
			},
			customColumns: []string{"CustomString"},
			sourceURL:     []string{"file://testdata/sessions_test/custom_columns_schema"},
			preAssertions: []string{
				`SELECT COUNT(*) = 2 FROM Sessions`,
			},
			postAssertions: []string{
				`SELECT COUNT(*) = 3 FROM Sessions`,
			},
			wantCustomData: map[string]any{
				"CustomString": "editor",
			},
		},
		{
			name: "success inserting session with multiple custom data types",
			insertSession: &dbtype.InsertSession{
				Username:  "newuser_multi",
				CreatedAt: time.Now(),
				UpdatedAt: time.Now(),
				Expired:   false,
			},
			customDataResolver: func(_ context.Context, _ resource.ReadOnlyTransaction) ([]*sessioninfo.CustomData, error) {
				return []*sessioninfo.CustomData{
					{ColumnName: "CustomString", Value: "manager"},
					{ColumnName: "CustomInt", Value: int64(42)},
					{ColumnName: "CustomBool", Value: true},
					{ColumnName: "CustomFloat", Value: float64(88.3)},
					{ColumnName: "CustomTimestamp", Value: time.Date(2025, 1, 10, 12, 0, 0, 0, time.UTC)},
				}, nil
			},
			customColumns: []string{"CustomString", "CustomInt", "CustomBool", "CustomFloat", "CustomTimestamp"},
			sourceURL:     []string{"file://testdata/sessions_test/custom_columns_schema"},
			preAssertions: []string{
				`SELECT COUNT(*) = 2 FROM Sessions`,
			},
			postAssertions: []string{
				`SELECT COUNT(*) = 3 FROM Sessions`,
			},
			wantCustomData: map[string]any{
				"CustomString":    "manager",
				"CustomInt":       "42",
				"CustomBool":      true,
				"CustomFloat":     float64(88.3),
				"CustomTimestamp": "2025-01-10T12:00:00Z",
			},
		},
		{
			name: "success inserting session without custom data",
			insertSession: &dbtype.InsertSession{
				Username:  "newuser_no_custom",
				CreatedAt: time.Now(),
				UpdatedAt: time.Now(),
				Expired:   false,
			},
			customDataResolver: func(_ context.Context, _ resource.ReadOnlyTransaction) ([]*sessioninfo.CustomData, error) {
				return nil, nil
			},
			sourceURL: []string{"file://testdata/sessions_test/custom_columns_schema"},
			preAssertions: []string{
				`SELECT COUNT(*) = 2 FROM Sessions`,
			},
			postAssertions: []string{
				`SELECT COUNT(*) = 3 FROM Sessions`,
			},
		},
		{
			name: "resolver error rolls back session insert",
			insertSession: &dbtype.InsertSession{
				Username:  "newuser_err",
				CreatedAt: time.Now(),
				UpdatedAt: time.Now(),
				Expired:   false,
			},
			customDataResolver: func(_ context.Context, _ resource.ReadOnlyTransaction) ([]*sessioninfo.CustomData, error) {
				return nil, errors.New("resolver error")
			},
			sourceURL: []string{"file://testdata/sessions_test/custom_columns_schema"},
			wantErr:   true,
			preAssertions: []string{
				`SELECT COUNT(*) = 2 FROM Sessions`,
			},
			postAssertions: []string{
				`SELECT COUNT(*) = 2 FROM Sessions`,
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
			if len(tt.customColumns) > 0 {
				c.SetCustomSessionColumns(tt.customColumns)
			}

			runAssertions(ctx, t, conn.Client, tt.preAssertions)
			id, err := c.InsertCustomSession(ctx, tt.insertSession, tt.customDataResolver)
			if (err != nil) != tt.wantErr {
				t.Errorf("SessionStorageDriver.InsertCustomSession() error = %v, wantErr %v", err, tt.wantErr)
				runAssertions(ctx, t, conn.Client, tt.postAssertions)
				return
			}
			if tt.wantErr {
				runAssertions(ctx, t, conn.Client, tt.postAssertions)
				return
			}

			if id == ccc.NilUUID {
				t.Error("SessionStorageDriver.InsertCustomSession() id is nil, want valid UUID")
			}
			runAssertions(ctx, t, conn.Client, []string{fmt.Sprintf(`SELECT COUNT(*) = 1 FROM Sessions WHERE Id = '%s'`, id)})

			// Read back the session and verify custom data
			if tt.wantCustomData != nil {
				gotSession, err := c.Session(ctx, id)
				if err != nil {
					t.Fatalf("SessionStorageDriver.Session() error = %v", err)
				}
				if gotSession.CustomData == nil {
					t.Fatal("SessionStorageDriver.Session() CustomSessionData is nil, want non-nil")
				}
				for key, wantVal := range tt.wantCustomData {
					gotVal, ok := gotSession.CustomData[key]
					if !ok {
						t.Errorf("SessionStorageDriver.Session() CustomSessionData missing key %q", key)
						continue
					}
					if fmt.Sprintf("%v", gotVal) != fmt.Sprintf("%v", wantVal) {
						t.Errorf("SessionStorageDriver.Session() CustomSessionData[%q] = %v (%T), want %v (%T)", key, gotVal, gotVal, wantVal, wantVal)
					}
				}
			}

			runAssertions(ctx, t, conn.Client, tt.postAssertions)
		})
	}
}
