package postgres

import (
	"fmt"
	"testing"
	"time"

	"github.com/cccteam/ccc"
	"github.com/cccteam/ccc/accesstypes"
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
			name: "FullMigration OIDC",
			args: args{
				sourceURL: "file://../../../schema/postgresql/oidc/migrations",
			},
		},
		{
			name: "FullMigration",
			args: args{
				sourceURL: "file://../../../schema/postgresql/migrations",
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			db, err := prepareDatabase(t.Context(), t, tt.args.sourceURL)
			if (err != nil) != false {
				t.Fatalf("prepareDatabase() error = %v", err)
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
			sourceURL: []string{"file://../../../schema/postgresql/oidc/migrations", "file://testdata/sessions_test/oidc_valid_sessions"},
			wantSession: &dbtype.Session{
				ID:       ccc.Must(ccc.UUIDFromString("eb0c72a4-1f32-469e-b51b-7baa589a944c")),
				Username: "test user 2",
				Expired:  true,
			},
		},
		{
			name:      "not found",
			sessionID: ccc.Must(ccc.NewUUID()),
			sourceURL: []string{"file://../../../schema/postgresql/oidc/migrations", "file://testdata/sessions_test/oidc_valid_sessions"},
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
			c := NewSessionStorageDriver(conn.Pool)

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
			sourceURL: []string{"file://../../../schema/postgresql/oidc/migrations", "file://testdata/sessions_test/oidc_valid_sessions"},
			wantErr:   true,
		},
		{
			name:      "success updating session activity",
			sessionID: ccc.Must(ccc.UUIDFromString("eb0c72a4-1f32-469e-b51b-7baa589a944c")),
			sourceURL: []string{"file://../../../schema/postgresql/oidc/migrations", "file://testdata/sessions_test/oidc_valid_sessions"},
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
			c := NewSessionStorageDriver(conn.Pool)

			preExecTime := time.Now()
			if !tt.wantErr {
				runAssertions(ctx, t, conn.Pool, []string{fmt.Sprintf(`SELECT "UpdatedAt" < '%s' FROM "Sessions" WHERE  "Id" = '%s'`, preExecTime.Format(PostgresTimestampFormat), tt.sessionID)})
			}
			if err := c.UpdateSessionActivity(ctx, tt.sessionID); (err != nil) != tt.wantErr {
				t.Errorf("client.UpdateSessionActivity() error = %v, wantErr %v", err, tt.wantErr)
			}
			if !tt.wantErr {
				runAssertions(ctx, t, conn.Pool, []string{fmt.Sprintf(`SELECT "UpdatedAt" > '%s' FROM "Sessions" WHERE  "Id" = '%s'`, preExecTime.Format(PostgresTimestampFormat), tt.sessionID)})
			}
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
			sourceURL: []string{"file://../../../schema/postgresql/migrations", "file://testdata/sessions_test/valid_sessions"},
			preAssertions: []string{
				`SELECT COUNT(*) = 5 FROM "Sessions"`,
			},
			postAssertions: []string{
				`SELECT COUNT(*) = 6 FROM "Sessions"`,
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
			c := NewSessionStorageDriver(conn.Pool)

			runAssertions(ctx, t, conn.Pool, tt.preAssertions)
			id, err := c.InsertSession(ctx, tt.insertSession)
			if (err != nil) != tt.wantErr {
				t.Errorf("SessionStorageDriver.InsertSession() error = %v, wantErr %v", err, tt.wantErr)
				return
			}

			if !tt.wantErr {
				if id == ccc.NilUUID {
					t.Error("SessionStorageDriver.InsertSession() id is nil, want valid UUID")
				}
				runAssertions(ctx, t, conn.Pool, []string{fmt.Sprintf(`SELECT COUNT(*) = 1 FROM "Sessions" WHERE "Id" = '%s'`, id)})
			}
			runAssertions(ctx, t, conn.Pool, tt.postAssertions)
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
			sourceURL: []string{"file://../../../schema/postgresql/oidc/migrations", "file://testdata/sessions_test/oidc_valid_sessions"},
			preAssertions: []string{
				`SELECT COUNT(*) = 3 FROM "Sessions" WHERE "Expired" = false`,
				`SELECT COUNT(*) = 0 FROM "Sessions" WHERE "Id" = '52dd570b-1280-421b-888e-a63f0ca35be9'`,
			},
			postAssertions: []string{
				`SELECT COUNT(*) = 3 FROM "Sessions" WHERE "Expired" = false`,
			},
		},
		{
			name:      "success destroying session",
			sessionID: ccc.Must(ccc.UUIDFromString("38bd570b-1280-421b-888e-a63f0ca35be7")),
			sourceURL: []string{"file://../../../schema/postgresql/oidc/migrations", "file://testdata/sessions_test/oidc_valid_sessions"},
			preAssertions: []string{
				`SELECT "Expired" = false FROM "Sessions" WHERE "Id" = '38bd570b-1280-421b-888e-a63f0ca35be7'`,
			},
			postAssertions: []string{
				`SELECT "Expired" = true FROM "Sessions" WHERE "Id" = '38bd570b-1280-421b-888e-a63f0ca35be7'`,
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
			c := NewSessionStorageDriver(conn.Pool)

			runAssertions(ctx, t, conn.Pool, tt.preAssertions)
			if err := c.DestroySession(ctx, tt.sessionID); (err != nil) != tt.wantErr {
				t.Errorf("client.DestroySession() error = %v, wantErr %v", err, tt.wantErr)
			}
			runAssertions(ctx, t, conn.Pool, tt.postAssertions)
		})
	}
}

func TestSessionStorageDriver_User(t *testing.T) {
	t.Parallel()

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
			id:        ccc.Must(ccc.UUIDFromString("27b43588-b743-4133-8730-e0439065a844")),
			sourceURL: []string{"file://../../../schema/postgresql/migrations", "file://testdata/users_test/valid_users"},
			wantUser: &dbtype.SessionUser{
				ID:       ccc.Must(ccc.UUIDFromString("27b43588-b743-4133-8730-e0439065a844")),
				Username: "testuser",
				Disabled: false,
			},
			preAssertions: []string{
				`SELECT COUNT(*) = 1 
				FROM "SessionUsers" 
				WHERE "Id" = '27b43588-b743-4133-8730-e0439065a844'`,
			},
		},
		{
			name:      "not found",
			id:        ccc.Must(ccc.NewUUID()),
			sourceURL: []string{"file://../../../schema/postgresql/migrations", "file://testdata/users_test/valid_users"},
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
			c := NewSessionStorageDriver(conn.Pool)

			runAssertions(ctx, t, conn.Pool, tt.preAssertions)
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
			runAssertions(ctx, t, conn.Pool, tt.postAssertions)
		})
	}
}

func TestSessionStorageDriver_UserByUserName(t *testing.T) {
	t.Parallel()

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
			sourceURL: []string{"file://../../../schema/postgresql/migrations", "file://testdata/users_test/valid_users"},
			wantUser: &dbtype.SessionUser{
				ID:       ccc.Must(ccc.UUIDFromString("27b43588-b743-4133-8730-e0439065a844")),
				Username: "testuser",
				Disabled: false,
			},
			preAssertions: []string{
				`SELECT COUNT(*) = 1 
				FROM "SessionUsers" 
				WHERE "Username" = 'testuser'`,
			},
		},
		{
			name:      "not found",
			username:  "nonexistent",
			sourceURL: []string{"file://../../../schema/postgresql/migrations", "file://testdata/users_test/valid_users"},
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
			c := NewSessionStorageDriver(conn.Pool)

			runAssertions(ctx, t, conn.Pool, tt.preAssertions)
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
			runAssertions(ctx, t, conn.Pool, tt.postAssertions)
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
		domain         accesstypes.Domain
		hash           *securehash.Hash
		sourceURL      []string
		wantErr        bool
		preAssertions  []string
		postAssertions []string
	}{
		{
			name:      "success",
			username:  "newuser",
			domain:    "test.com",
			hash:      hash,
			sourceURL: []string{"file://../../../schema/postgresql/migrations", "file://testdata/users_test/valid_users"},
			preAssertions: []string{
				`SELECT COUNT(*) = 0 FROM "SessionUsers" WHERE "Username" = 'newuser'`,
			},
			postAssertions: []string{
				`SELECT COUNT(*) = 1 FROM "SessionUsers" WHERE "Username" = 'newuser' AND "Domain" = 'test.com'`,
			},
		},
		{
			name:      "user already exists",
			username:  "testuser",
			domain:    "test.com",
			hash:      hash,
			sourceURL: []string{"file://../../../schema/postgresql/migrations", "file://testdata/users_test/valid_users"},
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
			c := NewSessionStorageDriver(conn.Pool)

			runAssertions(ctx, t, conn.Pool, tt.preAssertions)
			_, err = c.CreateUser(ctx, tt.username, tt.domain, tt.hash)
			if (err != nil) != tt.wantErr {
				t.Errorf("SessionStorageDriver.CreateUser() error = %v, wantErr %v", err, tt.wantErr)
			}
			runAssertions(ctx, t, conn.Pool, tt.postAssertions)
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
			sourceURL: []string{"file://../../../schema/postgresql/migrations", "file://testdata/users_test/valid_users"},
			preAssertions: []string{
				`
					SELECT "PasswordHash" = '1$12288$3$1$k5UDxGNpdI0XrTY59KZvXg==.JNUcFFjrpbAj9pr1L8HkV8aNkeACBbc3SV0SSAjoPwM=' 
					FROM "SessionUsers" 
					WHERE "Id" = '27b43588-b743-4133-8730-e0439065a844'
				`,
			},
			postAssertions: []string{
				`
					SELECT "PasswordHash" = '1$12288$3$1$UdvSMfwCubeTKv05/UpxwA==.tr8oe8g0VvfjQp3XpJonme6edSA4diQLLrS64ksf/TM='
					FROM "SessionUsers"
					WHERE "Id" = '27b43588-b743-4133-8730-e0439065a844'
				`,
			},
		},
		{
			name:      "user not found",
			id:        ccc.Must(ccc.NewUUID()),
			hash:      newHash,
			sourceURL: []string{"file://../../../schema/postgresql/migrations", "file://testdata/users_test/valid_users"},
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
			c := NewSessionStorageDriver(conn.Pool)

			runAssertions(ctx, t, conn.Pool, tt.preAssertions)
			err = c.SetUserPasswordHash(ctx, tt.id, tt.hash)
			if (err != nil) != tt.wantErr {
				t.Errorf("SessionStorageDriver.SetUserPasswordHash() error = %v, wantErr %v", err, tt.wantErr)
			}
			runAssertions(ctx, t, conn.Pool, tt.postAssertions)
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
			sourceURL: []string{"file://../../../schema/postgresql/migrations", "file://testdata/users_test/valid_users"},
			preAssertions: []string{
				`SELECT "Disabled" = false FROM "SessionUsers" WHERE "Id" = '27b43588-b743-4133-8730-e0439065a844'`,
			},
			postAssertions: []string{
				`SELECT "Disabled" = true FROM "SessionUsers" WHERE "Id" = '27b43588-b743-4133-8730-e0439065a844'`,
			},
		},
		{
			name:      "user not found",
			id:        ccc.Must(ccc.NewUUID()),
			sourceURL: []string{"file://../../../schema/postgresql/migrations", "file://testdata/users_test/valid_users"},
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
			c := NewSessionStorageDriver(conn.Pool)

			runAssertions(ctx, t, conn.Pool, tt.preAssertions)
			err = c.DeactivateUser(ctx, tt.id)
			if (err != nil) != tt.wantErr {
				t.Errorf("SessionStorageDriver.DeactivateUser() error = %v, wantErr %v", err, tt.wantErr)
			}
			runAssertions(ctx, t, conn.Pool, tt.postAssertions)
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
			sourceURL: []string{"file://../../../schema/postgresql/migrations", "file://testdata/users_test/valid_users"},
			preAssertions: []string{
				`SELECT COUNT(*) = 1 FROM "SessionUsers" WHERE "Id" = '27b43588-b743-4133-8730-e0439065a844'`,
			},
			postAssertions: []string{
				`SELECT COUNT(*) = 0 FROM "SessionUsers" WHERE "Id" = '27b43588-b743-4133-8730-e0439065a844'`,
			},
		},
		{
			name:      "user not found",
			id:        ccc.Must(ccc.NewUUID()),
			sourceURL: []string{"file://../../../schema/postgresql/migrations", "file://testdata/users_test/valid_users"},
			preAssertions: []string{
				`SELECT COUNT(*) = 2 FROM "SessionUsers"`,
			},
			postAssertions: []string{
				`SELECT COUNT(*) = 2 FROM "SessionUsers"`,
			},
			wantErr: true,
		},
		{
			name:    "error on invalid scheam",
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
			c := NewSessionStorageDriver(conn.Pool)

			runAssertions(ctx, t, conn.Pool, tt.preAssertions)
			err = c.DeleteUser(ctx, tt.id)
			if (err != nil) != tt.wantErr {
				t.Errorf("SessionStorageDriver.DeleteUser() error = %v, wantErr %v", err, tt.wantErr)
			}
			runAssertions(ctx, t, conn.Pool, tt.postAssertions)
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
			sourceURL: []string{"file://../../../schema/postgresql/migrations", "file://testdata/users_test/valid_users"},
			preAssertions: []string{
				`SELECT "Disabled" = true FROM "SessionUsers" WHERE "Id" = '54918893-2342-4621-8673-79520a84b84f'`,
			},
			postAssertions: []string{
				`SELECT "Disabled" = false FROM "SessionUsers" WHERE "Id" = '54918893-2342-4621-8673-79520a84b84f'`,
			},
		},
		{
			name:      "user not found",
			id:        ccc.Must(ccc.NewUUID()),
			sourceURL: []string{"file://../../../schema/postgresql/migrations", "file://testdata/users_test/valid_users"},
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
			c := NewSessionStorageDriver(conn.Pool)

			runAssertions(ctx, t, conn.Pool, tt.preAssertions)
			err = c.ActivateUser(ctx, tt.id)
			if (err != nil) != tt.wantErr {
				t.Errorf("SessionStorageDriver.ActivateUser() error = %v, wantErr %v", err, tt.wantErr)
			}
			runAssertions(ctx, t, conn.Pool, tt.postAssertions)
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
			sourceURL: []string{"file://../../../schema/postgresql/migrations", "file://testdata/sessions_test/valid_sessions"},
			preAssertions: []string{
				`SELECT COUNT(*) = 2 FROM "Sessions" WHERE "Username" = 'test user 1' AND "Expired" = false`,
			},
			postAssertions: []string{
				`SELECT COUNT(*) = 0 FROM "Sessions" WHERE "Username" = 'test user 1' AND "Expired" = false`,
			},
		},
		{
			name:      "user has no sessions",
			username:  "no_sessions_user",
			sourceURL: []string{"file://../../../schema/postgresql/migrations", "file://testdata/sessions_test/valid_sessions"},
			preAssertions: []string{
				`SELECT COUNT(*) = 0 FROM "Sessions" WHERE "Username" = 'no_sessions_user'`,
			},
			postAssertions: []string{
				`SELECT COUNT(*) = 0 FROM "Sessions" WHERE "Username" = 'no_sessions_user'`,
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
			c := NewSessionStorageDriver(conn.Pool)

			runAssertions(ctx, t, conn.Pool, tt.preAssertions)
			err = c.DestroyAllUserSessions(ctx, tt.username)
			if (err != nil) != tt.wantErr {
				t.Errorf("SessionStorageDriver.DestroyAllSessionsForUser() error = %v, wantErr %v", err, tt.wantErr)
			}
			runAssertions(ctx, t, conn.Pool, tt.postAssertions)
		})
	}
}
