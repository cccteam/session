package postgres

import (
	"testing"

	"github.com/cccteam/ccc/securehash"
	"github.com/cccteam/session/internal/dbtype"
)

// TestSessionStorageDriver_PasswordLessAccount proves a password-less account (an
// account provisioned for external sign-in) round-trips on the shipped schema: it is
// created and read with no hash, gains a password, and loses it again.
func TestSessionStorageDriver_PasswordLessAccount(t *testing.T) {
	t.Parallel()
	ctx := t.Context()

	db, err := prepareDatabase(ctx, t, "file://../../../schema/postgresql/migrations")
	if err != nil {
		t.Fatalf("prepareDatabase() error = %v", err)
	}
	driver := NewSessionStorageDriver(db.Pool)

	user, err := driver.CreateUser(ctx, &dbtype.InsertSessionUser{Username: "sso-only@example.com"}, nil)
	if err != nil {
		t.Fatalf("CreateUser() without a password error = %v", err)
	}
	assertHash := func(want bool) {
		t.Helper()

		got, err := driver.User(ctx, user.ID)
		if err != nil {
			t.Fatalf("User() error = %v", err)
		}
		if (got.PasswordHash != nil) != want {
			t.Errorf("User().PasswordHash = %v, want set %v", got.PasswordHash, want)
		}
	}
	assertHash(false)

	hash, err := securehash.New(securehash.Argon2()).Hash("password")
	if err != nil {
		t.Fatal(err)
	}
	if err := driver.SetUserPasswordHash(ctx, user.ID, hash); err != nil {
		t.Fatalf("SetUserPasswordHash() error = %v", err)
	}
	assertHash(true)

	if err := driver.SetUserPasswordHash(ctx, user.ID, nil); err != nil {
		t.Fatalf("SetUserPasswordHash(nil) error = %v", err)
	}
	assertHash(false)
}
