package drivertest

import (
	"bytes"
	"context"
	"testing"

	"github.com/cccteam/ccc"
	"github.com/cccteam/ccc/securehash"
	"github.com/cccteam/httpio"
	"github.com/cccteam/session/internal/dbtype"
	"github.com/cccteam/session/sessioninfo"
)

// testUserAccounts pins the user row as the user-management surface reads it: the
// password change mark travels with the insert, CreatedAt is the database's time at
// the insert, LastSignInAt is nil before the first sign-in, and the users list orders
// by username without regard to case, each user as stored.
func testUserAccounts(ctx context.Context, t *testing.T, h *AuthHarness) {
	in := h.New(ctx, t, Auth, AuthConfig{Auth: true, AuthEvents: true})
	hasher := securehash.New(securehash.Argon2())
	temporary, err := hasher.Hash("temporary")
	if err != nil {
		t.Fatal(err)
	}

	// An operator creates a user with a temporary password: the mark is stored with the
	// insert, CreatedAt is the commit's time, and there is no sign-in yet.
	w := startWindow(h.ClockLead)
	pat, err := in.Driver.CreateUser(ctx, &dbtype.InsertSessionUser{Username: "Pat@lakeside.edu", PasswordHash: temporary, PasswordChangeRequired: true}, nil)
	w.done()
	if err != nil {
		t.Fatalf("CreateUser() error = %v", err)
	}
	if !pat.PasswordChangeRequired || pat.LastSignInAt != nil || pat.Username != "Pat@lakeside.edu" {
		t.Errorf("CreateUser() = %+v, want the mark, the username as given and no sign-in", pat)
	}
	w.assertStamped(t, "CreateUser().CreatedAt", pat.CreatedAt)
	alex := createUser(ctx, t, in.Driver, "alex@lakeside.edu")
	if alex.PasswordChangeRequired || alex.PasswordHash != nil {
		t.Errorf("CreateUser() of a password-less user = %+v, want no mark", alex)
	}

	// The list is every user by username, without regard to case, as stored.
	users, err := in.Driver.Users(ctx)
	if err != nil {
		t.Fatalf("Users() error = %v", err)
	}
	if len(users) != 2 || users[0].ID != alex.ID || users[1].ID != pat.ID {
		t.Fatalf("Users() = %v, want alex then Pat", usernames(users))
	}
	if !users[1].PasswordChangeRequired || !users[1].CreatedAt.Equal(pat.CreatedAt) || users[1].LastSignInAt != nil || !sameHash(users[1].PasswordHash, temporary) {
		t.Errorf("Users()[1] = %+v, want Pat as created", users[1])
	}
}

// testUserPasswordSet pins SetUserPassword: the hash and the mark land in one write,
// cleared for a password the user chose, set for one an operator reset; an unknown
// user is NotFound.
func testUserPasswordSet(ctx context.Context, t *testing.T, h *AuthHarness) {
	in := h.New(ctx, t, Auth, AuthConfig{Auth: true})
	hasher := securehash.New(securehash.Argon2())
	temporary, err := hasher.Hash("temporary")
	if err != nil {
		t.Fatal(err)
	}
	pat, err := in.Driver.CreateUser(ctx, &dbtype.InsertSessionUser{Username: "pat@lakeside.edu", PasswordHash: temporary, PasswordChangeRequired: true}, nil)
	if err != nil {
		t.Fatalf("CreateUser() error = %v", err)
	}

	// The user changes the password: the new hash and the cleared mark land in one write.
	chosen, err := hasher.Hash("chosen")
	if err != nil {
		t.Fatal(err)
	}
	if err := in.Driver.SetUserPassword(ctx, pat.ID, chosen, false); err != nil {
		t.Fatalf("SetUserPassword() error = %v", err)
	}
	changed, err := in.Driver.User(ctx, pat.ID)
	if err != nil {
		t.Fatalf("User() error = %v", err)
	}
	if changed.PasswordChangeRequired || !sameHash(changed.PasswordHash, chosen) || !changed.CreatedAt.Equal(pat.CreatedAt) {
		t.Errorf("User() after the change = %+v, want the chosen hash, no mark and the creation time kept", changed)
	}

	// An operator resets it: the mark is set again with the temporary hash.
	if err := in.Driver.SetUserPassword(ctx, pat.ID, temporary, true); err != nil {
		t.Fatalf("SetUserPassword() error = %v", err)
	}
	if reset, err := in.Driver.User(ctx, pat.ID); err != nil || !reset.PasswordChangeRequired || !sameHash(reset.PasswordHash, temporary) {
		t.Errorf("User() after the reset = %+v, %v; want the temporary hash and the mark", reset, err)
	}
	if err := in.Driver.SetUserPassword(ctx, ccc.Must(ccc.NewUUID()), chosen, false); !httpio.HasNotFound(err) {
		t.Errorf("SetUserPassword() of an unknown user error = %v, want NotFound", err)
	}
}

// testUserLastSignIn pins LastSignInAt: nil before the first sign-in; the database's
// time at TouchUserSignIn, which the Auth calls once a sign-in has committed, as a write
// of its own (inside the sign-in's transaction the update would deadlock two sign-ins
// of one user on PostgreSQL); untouched by the flow itself and by a session the
// application starts; CreatedAt never moves.
func testUserLastSignIn(ctx context.Context, t *testing.T, h *AuthHarness) {
	in := h.New(ctx, t, Auth, AuthConfig{Auth: true, AuthEvents: true})
	pat := passwordUser(ctx, t, in.Driver, "pat@lakeside.edu")
	alex := createUser(ctx, t, in.Driver, "alex@lakeside.edu")
	if pat.LastSignInAt != nil {
		t.Fatalf("CreateUser().LastSignInAt = %v, want nil before the first sign-in", pat.LastSignInAt)
	}

	// The flow writes the session, not the user.
	req := &sessioninfo.NewSessionRequest{
		Reason: sessioninfo.ReasonLogin, Username: pat.Username, UserID: pat.ID,
		Identity: &sessioninfo.Identity{Method: sessioninfo.MethodPassword, Subject: pat.ID.String()},
	}
	sessionID, err := in.SignIn(ctx, newInsertSession(pat.Username), req)
	if err != nil {
		t.Fatalf("SignIn() error = %v", err)
	}
	if signedIn, err := in.Driver.User(ctx, pat.ID); err != nil || signedIn.LastSignInAt != nil {
		t.Errorf("User().LastSignInAt after the flow alone = %v, %v; want nil: the touch is the store's own write", signedIn.LastSignInAt, err)
	}

	// The touch stamps the database's time, after the session's.
	w := startWindow(h.ClockLead)
	if err := in.Driver.TouchUserSignIn(ctx, pat.ID); err != nil {
		t.Fatalf("TouchUserSignIn() error = %v", err)
	}
	w.done()
	touched, err := in.Driver.User(ctx, pat.ID)
	if err != nil {
		t.Fatalf("User() error = %v", err)
	}
	if touched.LastSignInAt == nil {
		t.Fatal("User().LastSignInAt = nil after the touch, want the database's time")
	}
	w.assertStamped(t, "User().LastSignInAt", *touched.LastSignInAt)
	if session := mustSession(ctx, t, in.Driver, sessionID); touched.LastSignInAt.Before(session.CreatedAt) {
		t.Errorf("User().LastSignInAt = %v, want no earlier than the session's creation %v", *touched.LastSignInAt, session.CreatedAt)
	}
	if !touched.CreatedAt.Equal(pat.CreatedAt) {
		t.Errorf("User().CreatedAt = %v after the touch, want %v untouched", touched.CreatedAt, pat.CreatedAt)
	}
	if err := in.Driver.TouchUserSignIn(ctx, ccc.Must(ccc.NewUUID())); !httpio.HasNotFound(err) {
		t.Errorf("TouchUserSignIn() of an unknown user error = %v, want NotFound", err)
	}

	// A session the application starts (a regeneration) is no sign-in.
	if _, err := in.Driver.InsertSession(ctx, newInsertSession(pat.Username), &sessioninfo.NewSessionRequest{Reason: sessioninfo.ReasonRegeneration, Username: pat.Username, UserID: pat.ID}); err != nil {
		t.Fatalf("InsertSession() error = %v", err)
	}
	if regenerated, err := in.Driver.User(ctx, pat.ID); err != nil || !regenerated.LastSignInAt.Equal(*touched.LastSignInAt) {
		t.Errorf("User().LastSignInAt after a regeneration = %v, %v; want %v untouched", regenerated.LastSignInAt, err, *touched.LastSignInAt)
	}
	if never, err := in.Driver.User(ctx, alex.ID); err != nil || never.LastSignInAt != nil {
		t.Errorf("User() of a user who never signed in = %+v, %v; want no sign-in", never, err)
	}
}

// usernames lists users' usernames, for a failure message.
func usernames(users []*dbtype.SessionUser) []string {
	names := make([]string, len(users))
	for i, u := range users {
		names[i] = u.Username
	}

	return names
}

// sameHash reports whether two hashes are the same stored value.
func sameHash(got, want *securehash.Hash) bool {
	if got == nil || want == nil {
		return got == want
	}
	g, err := got.MarshalText()
	if err != nil {
		return false
	}
	w, err := want.MarshalText()
	if err != nil {
		return false
	}

	return bytes.Equal(g, w)
}
