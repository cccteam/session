package spanner

import (
	"context"
	"fmt"
	"testing"
	"time"

	"github.com/cccteam/ccc"
	"github.com/cccteam/ccc/securehash"
	"github.com/cccteam/session/internal/dbtype"
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
			name: "FullMigration",
			args: args{
				sourceURL: "file://../../../schema/spanner/oidc/migrations",
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()

			db, err := prepareDatabase(ctx, t, tt.args.sourceURL)
			if (err != nil) != false {
				t.Fatalf("prepareDatabase() error = %v, wantErr %v", err, false)
			}

			if err := db.MigrateDown(tt.args.sourceURL); err != nil {
				t.Fatalf("db.MigrateDown() error = %v, wantErr %v", err, false)
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
			sourceURL: []string{"file://../../../schema/spanner/oidc/migrations", "file://testdata/sessions_test/valid_sessions"},
			wantErr:   true,
		},
		{
			name:      "success updating session activity",
			sessionID: ccc.Must(ccc.UUIDFromString("eb0c72a4-1f32-469e-b51b-7baa589a944c")),
			sourceURL: []string{"file://../../../schema/spanner/oidc/migrations", "file://testdata/sessions_test/valid_sessions"},
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
			sourceURL: []string{"file://../../../schema/spanner/oidc/migrations", "file://testdata/sessions_test/valid_sessions"},
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
			sourceURL: []string{"file://../../../schema/spanner/oidc/migrations", "file://testdata/sessions_test/valid_sessions"},
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
			c := NewSessionStorageDriver(conn.Client)

			runAssertions(ctx, t, conn.Client, tt.preAssertions)
			if err := c.DestroySession(ctx, tt.sessionID); (err != nil) != tt.wantErr {
				t.Errorf("client.DestroySession() error = %v, wantErr %v", err, tt.wantErr)
			}
			runAssertions(ctx, t, conn.Client, tt.postAssertions)
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
				Username: "testuser",
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
			ctx := context.Background()
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
			name:      "success",
			username:  "testuser",
			sourceURL: []string{"file://../../../schema/spanner/migrations", "file://testdata/users_test/valid_users"},
			wantUser: &dbtype.SessionUser{
				ID:       userID,
				Username: "testuser",
				Disabled: false,
			},
			preAssertions: []string{
				`SELECT COUNT(*) = 1 FROM SessionUsers WHERE Username = 'testuser'`,
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
			ctx := context.Background()
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

func TestSessionStorageDriver_UpdateUserPasswordHash(t *testing.T) {
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
			ctx := context.Background()
			conn, err := prepareDatabase(ctx, t, tt.sourceURL...)
			if err != nil {
				t.Fatalf("prepareDatabase() error = %v, wantErr %v", err, false)
			}
			c := NewSessionStorageDriver(conn.Client)

			runAssertions(ctx, t, conn.Client, tt.preAssertions)
			err = c.UpdateUserPasswordHash(ctx, tt.id, tt.hash)
			if (err != nil) != tt.wantErr {
				t.Errorf("SessionStorageDriver.UpdateUserPasswordHash() error = %v, wantErr %v", err, tt.wantErr)
			}
			runAssertions(ctx, t, conn.Client, tt.postAssertions)
		})
	}
}
