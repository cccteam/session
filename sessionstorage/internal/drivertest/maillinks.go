package drivertest

import (
	"context"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/cccteam/ccc"
	"github.com/cccteam/httpio"
	"github.com/cccteam/session/internal/dbtype"
	"github.com/cccteam/session/sessioninfo"
	"github.com/cccteam/session/signin"
	"github.com/go-playground/errors/v5"
	"github.com/google/go-cmp/cmp"
	"github.com/google/go-cmp/cmp/cmpopts"
)

// A user's email address is held in two states, unverified and verified, and is unique
// among every address held; the mail links table holds the single-use links the
// library mails. These cases pin both on every backend, and the sign-in flow's
// acceptance of an invitation: consumed in the resolution's transaction, granted once
// it has committed.

// mailLinkOpts compares mail links, nil and empty slices alike, leaving out the two
// times the database writes.
var mailLinkOpts = cmp.Options{cmpopts.EquateEmpty(), cmpopts.IgnoreFields(dbtype.MailLink{}, "CreatedAt", "ConsumedAt")}

// newMailLink is a link of kind to email that expires in an hour, its CreatedAt and
// ConsumedAt carrying values the insert must ignore.
func newMailLink(kind dbtype.MailLinkKind, email string, hash []byte) *dbtype.MailLink {
	ignored := time.Date(2000, 1, 1, 0, 0, 0, 0, time.UTC)

	return &dbtype.MailLink{
		ID: ccc.Must(ccc.NewUUID()), TokenHash: hash, Kind: kind, Email: email,
		CreatedAt: ignored, ExpiresAt: time.Now().Add(time.Hour).Truncate(time.Microsecond), ConsumedAt: &ignored,
	}
}

// insertInvitation inserts an invitation to email, into tenant with roles.
func insertInvitation(ctx context.Context, t *testing.T, d AuthDriver, email, tenant string, roles []string, hash []byte) *dbtype.MailLink {
	t.Helper()

	link := newMailLink(dbtype.MailLinkInvitation, email, hash)
	link.Tenant, link.RoleNames = tenant, roles
	if err := d.InsertMailLink(ctx, link); err != nil {
		t.Fatalf("InsertMailLink() error = %v", err)
	}

	return link
}

// invitationOf is the invitation a sign-in carries for link.
func invitationOf(link *dbtype.MailLink) *sessioninfo.Invitation {
	return &sessioninfo.Invitation{ID: link.ID, Email: link.Email, Tenant: link.Tenant, RoleNames: link.RoleNames, InvitedBy: link.InvitedBy, ExpiresAt: link.ExpiresAt}
}

// acceptances records what the invitation acceptor was handed, in memory: the acceptor
// runs outside any transaction, once the consumption has committed, the way an
// application writes its membership store through that store's own client.
type acceptances struct {
	mu  sync.Mutex
	got map[string]string
}

func newAcceptances() *acceptances {
	return &acceptances{got: map[string]string{}}
}

// hook is the acceptor: it records who accepted what under accepted:<address>.
func (a *acceptances) hook(_ context.Context, userID ccc.UUID, username string, inv *sessioninfo.Invitation) error {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.got["accepted:"+inv.Email] = userID.String() + " " + username + " " + inv.Tenant + " " + strings.Join(inv.RoleNames, ",")

	return nil
}

// recorded answers what the acceptor was handed under key.
func (a *acceptances) recorded(key string) (value string, found bool) {
	a.mu.Lock()
	defer a.mu.Unlock()
	value, found = a.got[key]

	return value, found
}

// assertAccepted fails unless the acceptor was handed key=want.
func assertAccepted(t *testing.T, a *acceptances, key, want string) {
	t.Helper()

	got, found := a.recorded(key)
	if !found || got != want {
		t.Errorf("acceptances[%q] = %q (found %v), want %q", key, got, found, want)
	}
}

// mustUser reads a user by id.
func mustUser(ctx context.Context, t *testing.T, d AuthDriver, id ccc.UUID) *dbtype.SessionUser {
	t.Helper()

	user, err := d.User(ctx, id)
	if err != nil {
		t.Fatalf("User() error = %v", err)
	}

	return user
}

// assertEmail fails unless user holds email in the verified state wanted; a nil email
// means none.
func assertEmail(t *testing.T, what string, user *dbtype.SessionUser, email *string, verified bool) {
	t.Helper()

	switch {
	case email == nil && user.Email != nil:
		t.Errorf("%s: Email = %q, want none", what, *user.Email)
	case email != nil && (user.Email == nil || *user.Email != *email):
		t.Errorf("%s: Email = %v, want %q", what, user.Email, *email)
	}
	if got := user.EmailVerifiedAt != nil; got != verified {
		t.Errorf("%s: EmailVerifiedAt = %v, want verified %v", what, user.EmailVerifiedAt, verified)
	}
}

func testUserEmail(ctx context.Context, t *testing.T, h *AuthHarness) {
	in := h.New(ctx, t, Auth, AuthConfig{Auth: true})

	// An operator creates a user with an address: stored as given, unverified, and
	// found without regard to case.
	pat, err := in.Driver.CreateUser(ctx, &dbtype.InsertSessionUser{Username: "pat", Email: strPtr("Pat.Lee@Lakeside.edu")}, nil)
	if err != nil {
		t.Fatalf("CreateUser() with an address error = %v", err)
	}
	assertEmail(t, "CreateUser()", pat, strPtr("Pat.Lee@Lakeside.edu"), false)
	if found, err := in.Driver.UserByEmail(ctx, "pat.lee@lakeside.edu"); err != nil || found.ID != pat.ID {
		t.Errorf("UserByEmail() = %v, %v; want pat", found, err)
	}
	if _, err := in.Driver.UserByEmail(ctx, "nobody@lakeside.edu"); !httpio.HasNotFound(err) {
		t.Errorf("UserByEmail() of an address nobody holds error = %v, want NotFound", err)
	}

	// The address is unique among every address held, verified or not, whatever the
	// case; a verified mark needs an address.
	if _, err := in.Driver.CreateUser(ctx, &dbtype.InsertSessionUser{Username: "alex", Email: strPtr("PAT.LEE@lakeside.edu")}, nil); !httpio.HasConflict(err) {
		t.Errorf("CreateUser() with an address another user holds error = %v, want Conflict", err)
	}
	if _, err := in.Driver.CreateUser(ctx, &dbtype.InsertSessionUser{Username: "alex", EmailVerified: true}, nil); !httpio.HasBadRequest(err) {
		t.Errorf("CreateUser() with a verified mark and no address error = %v, want BadRequest", err)
	}
	alex := createUser(ctx, t, in.Driver, "alex")
	assertEmail(t, "CreateUser() without an address", alex, nil, false)

	// An entry by hand reserves an address, unverified; one another user holds is
	// refused; nil takes it off; an unknown user is NotFound.
	if err := in.Driver.SetUserEmail(ctx, alex.ID, strPtr("alex@lakeside.edu")); err != nil {
		t.Fatalf("SetUserEmail() error = %v", err)
	}
	assertEmail(t, "User() after SetUserEmail()", mustUser(ctx, t, in.Driver, alex.ID), strPtr("alex@lakeside.edu"), false)
	if err := in.Driver.SetUserEmail(ctx, alex.ID, strPtr("pat.lee@lakeside.edu")); !httpio.HasConflict(err) {
		t.Errorf("SetUserEmail() to an address another user holds error = %v, want Conflict", err)
	}
	if err := in.Driver.SetUserEmail(ctx, alex.ID, nil); err != nil {
		t.Fatalf("SetUserEmail(nil) error = %v", err)
	}
	assertEmail(t, "User() after SetUserEmail(nil)", mustUser(ctx, t, in.Driver, alex.ID), nil, false)
	if err := in.Driver.SetUserEmail(ctx, ccc.Must(ccc.NewUUID()), strPtr("x@lakeside.edu")); !httpio.HasNotFound(err) {
		t.Errorf("SetUserEmail() of an unknown user error = %v, want NotFound", err)
	}

	// A sign-up creates the user with the address verified, at the database's time, and
	// the list reads the columns.
	w := startWindow(h.ClockLead)
	sam, err := in.Driver.CreateUser(ctx, &dbtype.InsertSessionUser{Username: "sam", Email: strPtr("sam@lakeside.edu"), EmailVerified: true}, nil)
	w.done()
	if err != nil {
		t.Fatalf("CreateUser() with a verified address error = %v", err)
	}
	assertEmail(t, "CreateUser() verified", sam, strPtr("sam@lakeside.edu"), true)
	w.assertStamped(t, "CreateUser().EmailVerifiedAt", *sam.EmailVerifiedAt)
	users, err := in.Driver.Users(ctx)
	if err != nil || len(users) != 3 {
		t.Fatalf("Users() = %d users, %v; want 3", len(users), err)
	}
	for _, u := range users {
		if u.ID == sam.ID {
			assertEmail(t, "Users()[sam]", u, strPtr("sam@lakeside.edu"), true)
		}
	}
}

func testUserEmailVerified(ctx context.Context, t *testing.T, h *AuthHarness) {
	in := h.New(ctx, t, Auth, AuthConfig{Auth: true})
	pat := createUser(ctx, t, in.Driver, "pat")
	alex, err := in.Driver.CreateUser(ctx, &dbtype.InsertSessionUser{Username: "alex", Email: strPtr("alex@lakeside.edu")}, nil)
	if err != nil {
		t.Fatalf("CreateUser() error = %v", err)
	}

	// The person proved they read the address: written verified at the database's time.
	w := startWindow(h.ClockLead)
	if err := in.Driver.VerifyUserEmail(ctx, pat.ID, "pat@lakeside.edu"); err != nil {
		t.Fatalf("VerifyUserEmail() error = %v", err)
	}
	w.done()
	verified := mustUser(ctx, t, in.Driver, pat.ID)
	assertEmail(t, "User() after VerifyUserEmail()", verified, strPtr("pat@lakeside.edu"), true)
	w.assertStamped(t, "User().EmailVerifiedAt", *verified.EmailVerifiedAt)

	// A later verification replaces the address; the time moves.
	if err := in.Driver.VerifyUserEmail(ctx, pat.ID, "pat.lee@lakeside.edu"); err != nil {
		t.Fatalf("second VerifyUserEmail() error = %v", err)
	}
	replaced := mustUser(ctx, t, in.Driver, pat.ID)
	assertEmail(t, "User() after the second VerifyUserEmail()", replaced, strPtr("pat.lee@lakeside.edu"), true)
	if replaced.EmailVerifiedAt.Before(*verified.EmailVerifiedAt) {
		t.Errorf("EmailVerifiedAt = %v after the second verification, want no earlier than %v", *replaced.EmailVerifiedAt, *verified.EmailVerifiedAt)
	}

	// An address another user holds, even unverified, is refused; its holder verifies
	// it; an unknown user is NotFound.
	if err := in.Driver.VerifyUserEmail(ctx, pat.ID, "ALEX@lakeside.edu"); !httpio.HasConflict(err) {
		t.Errorf("VerifyUserEmail() of an address another user holds error = %v, want Conflict", err)
	}
	if err := in.Driver.VerifyUserEmail(ctx, alex.ID, "alex@lakeside.edu"); err != nil {
		t.Fatalf("VerifyUserEmail() of the user's own reserved address error = %v", err)
	}
	assertEmail(t, "User() after the holder verified", mustUser(ctx, t, in.Driver, alex.ID), strPtr("alex@lakeside.edu"), true)
	if err := in.Driver.VerifyUserEmail(ctx, ccc.Must(ccc.NewUUID()), "x@lakeside.edu"); !httpio.HasNotFound(err) {
		t.Errorf("VerifyUserEmail() of an unknown user error = %v, want NotFound", err)
	}

	// An entry by hand over a verified address leaves it unverified: the operator typed it.
	if err := in.Driver.SetUserEmail(ctx, alex.ID, strPtr("alex.new@lakeside.edu")); err != nil {
		t.Fatalf("SetUserEmail() error = %v", err)
	}
	assertEmail(t, "User() after SetUserEmail() over a verified address", mustUser(ctx, t, in.Driver, alex.ID), strPtr("alex.new@lakeside.edu"), false)
}

func testClaimVerifiedEmail(ctx context.Context, t *testing.T, h *AuthHarness) {
	in := h.New(ctx, t, Auth, AuthConfig{Auth: true})
	pat := createUser(ctx, t, in.Driver, "pat")
	alex, err := in.Driver.CreateUser(ctx, &dbtype.InsertSessionUser{Username: "alex", Email: strPtr("alex@lakeside.edu")}, nil)
	if err != nil {
		t.Fatalf("CreateUser() error = %v", err)
	}
	sam := createUser(ctx, t, in.Driver, "sam")

	// A user without an address takes the method's verified one.
	if claimed, err := in.Driver.ClaimVerifiedEmail(ctx, pat.ID, "pat@lakeside.edu"); err != nil || !claimed {
		t.Fatalf("ClaimVerifiedEmail() = %v, %v; want claimed", claimed, err)
	}
	assertEmail(t, "User() after the claim", mustUser(ctx, t, in.Driver, pat.ID), strPtr("pat@lakeside.edu"), true)

	// A verified address stays: another claim changes nothing.
	if claimed, err := in.Driver.ClaimVerifiedEmail(ctx, pat.ID, "other@lakeside.edu"); err != nil || claimed {
		t.Errorf("ClaimVerifiedEmail() over a verified address = %v, %v; want not claimed", claimed, err)
	}
	assertEmail(t, "User() after the second claim", mustUser(ctx, t, in.Driver, pat.ID), strPtr("pat@lakeside.edu"), true)

	// An address another user holds, even unverified, is never taken.
	if claimed, err := in.Driver.ClaimVerifiedEmail(ctx, sam.ID, "ALEX@lakeside.edu"); err != nil || claimed {
		t.Errorf("ClaimVerifiedEmail() of another user's address = %v, %v; want not claimed", claimed, err)
	}
	assertEmail(t, "User() of the claimer", mustUser(ctx, t, in.Driver, sam.ID), nil, false)
	assertEmail(t, "User() of the holder", mustUser(ctx, t, in.Driver, alex.ID), strPtr("alex@lakeside.edu"), false)

	// The holder's own unverified address is verified by the claim.
	if claimed, err := in.Driver.ClaimVerifiedEmail(ctx, alex.ID, "alex@lakeside.edu"); err != nil || !claimed {
		t.Errorf("ClaimVerifiedEmail() of the user's own reserved address = %v, %v; want claimed", claimed, err)
	}
	assertEmail(t, "User() after the holder's claim", mustUser(ctx, t, in.Driver, alex.ID), strPtr("alex@lakeside.edu"), true)
	if claimed, err := in.Driver.ClaimVerifiedEmail(ctx, ccc.Must(ccc.NewUUID()), "x@lakeside.edu"); err != nil || claimed {
		t.Errorf("ClaimVerifiedEmail() of an unknown user = %v, %v; want not claimed and no error", claimed, err)
	}
}

func testUsernameIsEmail(ctx context.Context, t *testing.T, h *AuthHarness) {
	in := h.New(ctx, t, AuthUsernameIsEmail, AuthConfig{Auth: true})

	// The address is the username, derived by the database, unverified until proven.
	pat := createUser(ctx, t, in.Driver, "Pat@lakeside.edu")
	assertEmail(t, "CreateUser()", pat, strPtr("Pat@lakeside.edu"), false)
	if found, err := in.Driver.UserByEmail(ctx, "pat@LAKESIDE.edu"); err != nil || found.ID != pat.ID {
		t.Errorf("UserByEmail() = %v, %v; want pat", found, err)
	}
	if _, err := in.Driver.CreateUser(ctx, &dbtype.InsertSessionUser{Username: "alex@lakeside.edu", Email: strPtr("other@lakeside.edu")}, nil); !httpio.HasBadRequest(err) {
		t.Errorf("CreateUser() with an address that is not the username error = %v, want BadRequest", err)
	}
	alex, err := in.Driver.CreateUser(ctx, &dbtype.InsertSessionUser{Username: "alex@lakeside.edu", Email: strPtr("ALEX@lakeside.edu"), EmailVerified: true}, nil)
	if err != nil {
		t.Fatalf("CreateUser() with the username as the address error = %v", err)
	}
	assertEmail(t, "CreateUser() verified", alex, strPtr("alex@lakeside.edu"), true)

	// A rename and an entry by hand are refused: the address changes through a link.
	if err := in.Driver.SetUserUsername(ctx, pat.ID, "patricia@lakeside.edu"); !httpio.HasConflict(err) {
		t.Errorf("SetUserUsername() error = %v, want Conflict", err)
	}
	if err := in.Driver.SetUserEmail(ctx, pat.ID, strPtr("patricia@lakeside.edu")); !httpio.HasConflict(err) {
		t.Errorf("SetUserEmail() error = %v, want Conflict", err)
	}

	// A verified address renames the user, with its live sessions, at the database's time.
	sessionID, err := in.Driver.InsertSession(ctx, newInsertSession(pat.Username), &sessioninfo.NewSessionRequest{Reason: sessioninfo.ReasonLogin, Username: pat.Username, UserID: pat.ID})
	if err != nil {
		t.Fatalf("InsertSession() error = %v", err)
	}
	w := startWindow(h.ClockLead)
	if err := in.Driver.VerifyUserEmail(ctx, pat.ID, "patricia@lakeside.edu"); err != nil {
		t.Fatalf("VerifyUserEmail() error = %v", err)
	}
	w.done()
	renamed := mustUser(ctx, t, in.Driver, pat.ID)
	if renamed.Username != "patricia@lakeside.edu" {
		t.Errorf("User().Username = %q after the verification, want the address", renamed.Username)
	}
	assertEmail(t, "User() after the verification", renamed, strPtr("patricia@lakeside.edu"), true)
	w.assertStamped(t, "User().EmailVerifiedAt", *renamed.EmailVerifiedAt)
	if sess := mustSession(ctx, t, in.Driver, sessionID); sess.Username != "patricia@lakeside.edu" {
		t.Errorf("Session().Username = %q after the verification, want the new name", sess.Username)
	}
	if err := in.Driver.VerifyUserEmail(ctx, pat.ID, "alex@lakeside.edu"); !httpio.HasConflict(err) {
		t.Errorf("VerifyUserEmail() of another user's address error = %v, want Conflict", err)
	}

	// A method's verified address is claimed only when it is the username.
	sam := createUser(ctx, t, in.Driver, "sam@lakeside.edu")
	if claimed, err := in.Driver.ClaimVerifiedEmail(ctx, sam.ID, "other@lakeside.edu"); err != nil || claimed {
		t.Errorf("ClaimVerifiedEmail() of an address that is not the username = %v, %v; want not claimed", claimed, err)
	}
	if claimed, err := in.Driver.ClaimVerifiedEmail(ctx, sam.ID, "SAM@lakeside.edu"); err != nil || !claimed {
		t.Errorf("ClaimVerifiedEmail() of the username = %v, %v; want claimed", claimed, err)
	}
	assertEmail(t, "User() after the claim", mustUser(ctx, t, in.Driver, sam.ID), strPtr("sam@lakeside.edu"), true)
}

func testMailLinkRoundTrip(ctx context.Context, t *testing.T, h *AuthHarness) {
	in := h.New(ctx, t, Auth, AuthConfig{Auth: true})
	user := createUser(ctx, t, in.Driver, "pat@lakeside.edu")
	inviter := createUser(ctx, t, in.Driver, "admin@lakeside.edu")

	invitation := newMailLink(dbtype.MailLinkInvitation, "new@lakeside.edu", tokenHash(1))
	invitation.Tenant, invitation.RoleNames, invitation.InvitedBy = "lakeside", []string{"Teacher", "Coach"}, ccc.NullUUIDFromUUID(inviter.ID)
	verification := newMailLink(dbtype.MailLinkVerification, "pat.lee@lakeside.edu", tokenHash(2))
	verification.UserID = ccc.NullUUIDFromUUID(user.ID)
	signUp := newMailLink(dbtype.MailLinkSignUp, "someone@example.com", tokenHash(3))

	for _, tt := range []struct {
		name string
		link *dbtype.MailLink
	}{
		{name: "an invitation with its tenant, roles and sender", link: invitation},
		{name: "a verification of an address for a user", link: verification},
		{name: "a sign-up", link: signUp},
	} {
		t.Run(tt.name, func(t *testing.T) {
			w := startWindow(h.ClockLead)
			if err := in.Driver.InsertMailLink(ctx, tt.link); err != nil {
				t.Fatalf("InsertMailLink() error = %v", err)
			}
			w.done()

			got, err := in.Driver.MailLinkByToken(ctx, tt.link.TokenHash, time.Now())
			if err != nil {
				t.Fatalf("MailLinkByToken() error = %v", err)
			}
			if diff := cmp.Diff(tt.link, got, mailLinkOpts); diff != "" {
				t.Errorf("MailLinkByToken() mismatch (-want +got):\n%s", diff)
			}
			w.assertStamped(t, "MailLinkByToken().CreatedAt", got.CreatedAt)
			if got.ConsumedAt != nil {
				t.Errorf("MailLinkByToken().ConsumedAt = %v, want nil", got.ConsumedAt)
			}
		})
	}
	if _, err := in.Driver.MailLinkByToken(ctx, tokenHash(9), time.Now()); !httpio.HasNotFound(err) {
		t.Errorf("MailLinkByToken() of an unknown token error = %v, want NotFound", err)
	}
	if err := in.Driver.InsertMailLink(ctx, newMailLink("reminder", "x@lakeside.edu", tokenHash(4))); err == nil {
		t.Error("InsertMailLink() of an unknown kind error = nil, want a refusal")
	}
}

func testMailLinkConsumedOnce(ctx context.Context, t *testing.T, h *AuthHarness) {
	in := h.New(ctx, t, Auth, AuthConfig{Auth: true})
	first := insertInvitation(ctx, t, in.Driver, "first@lakeside.edu", "lakeside", nil, tokenHash(1))
	second := insertInvitation(ctx, t, in.Driver, "second@lakeside.edu", "", []string{"Admin"}, tokenHash(2))
	verification := newMailLink(dbtype.MailLinkVerification, "pat@lakeside.edu", tokenHash(3))
	verification.UserID = ccc.NullUUIDFromUUID(createUser(ctx, t, in.Driver, "pat").ID)
	if err := in.Driver.InsertMailLink(ctx, verification); err != nil {
		t.Fatalf("InsertMailLink() error = %v", err)
	}

	// The live invitations are listed, oldest first, and no other kind.
	live, err := in.Driver.LiveMailLinks(ctx, dbtype.MailLinkInvitation, time.Now())
	if err != nil || len(live) != 2 || live[0].ID != first.ID || live[1].ID != second.ID {
		t.Fatalf("LiveMailLinks() = %v, %v; want the two invitations, oldest first", live, err)
	}

	// Consumed by token, once, at the database's time.
	w := startWindow(h.ClockLead)
	if err := in.Driver.ConsumeMailLink(ctx, first.TokenHash, time.Now()); err != nil {
		t.Fatalf("ConsumeMailLink() error = %v", err)
	}
	w.done()
	if consumedAt := h.MailLinkConsumedAt(ctx, t, in.Raw, first.TokenHash); consumedAt == nil {
		t.Error("ConsumedAt = nil after ConsumeMailLink(), want the database's time")
	} else {
		w.assertStamped(t, "ConsumedAt", *consumedAt)
	}
	if err := in.Driver.ConsumeMailLink(ctx, first.TokenHash, time.Now()); !httpio.HasNotFound(err) {
		t.Errorf("second ConsumeMailLink() error = %v, want NotFound: a link is consumed once", err)
	}
	if _, err := in.Driver.MailLinkByToken(ctx, first.TokenHash, time.Now()); !httpio.HasNotFound(err) {
		t.Errorf("MailLinkByToken() of a consumed link error = %v, want NotFound", err)
	}

	// Revoked by id, once.
	if err := in.Driver.RevokeMailLink(ctx, second.ID, time.Now()); err != nil {
		t.Fatalf("RevokeMailLink() error = %v", err)
	}
	if err := in.Driver.RevokeMailLink(ctx, second.ID, time.Now()); !httpio.HasNotFound(err) {
		t.Errorf("second RevokeMailLink() error = %v, want NotFound", err)
	}
	if err := in.Driver.RevokeMailLink(ctx, ccc.Must(ccc.NewUUID()), time.Now()); !httpio.HasNotFound(err) {
		t.Errorf("RevokeMailLink() of an unknown id error = %v, want NotFound", err)
	}
	if live, err := in.Driver.LiveMailLinks(ctx, dbtype.MailLinkInvitation, time.Now()); err != nil || len(live) != 0 {
		t.Errorf("LiveMailLinks() after both ended = %v, %v; want none", live, err)
	}
	if live, err := in.Driver.LiveMailLinks(ctx, dbtype.MailLinkVerification, time.Now()); err != nil || len(live) != 1 {
		t.Errorf("LiveMailLinks() of verifications = %v, %v; want the one", live, err)
	}
}

func testMailLinkExpired(ctx context.Context, t *testing.T, h *AuthHarness) {
	in := h.New(ctx, t, Auth, AuthConfig{Auth: true})
	link := insertInvitation(ctx, t, in.Driver, "pat@lakeside.edu", "lakeside", nil, tokenHash(1))
	later := link.ExpiresAt.Add(time.Second)

	if _, err := in.Driver.MailLinkByToken(ctx, link.TokenHash, later); !httpio.HasNotFound(err) {
		t.Errorf("MailLinkByToken() after expiry error = %v, want NotFound", err)
	}
	if err := in.Driver.ConsumeMailLink(ctx, link.TokenHash, later); !httpio.HasNotFound(err) {
		t.Errorf("ConsumeMailLink() after expiry error = %v, want NotFound", err)
	}
	if err := in.Driver.RevokeMailLink(ctx, link.ID, later); !httpio.HasNotFound(err) {
		t.Errorf("RevokeMailLink() after expiry error = %v, want NotFound", err)
	}
	if live, err := in.Driver.LiveMailLinks(ctx, dbtype.MailLinkInvitation, later); err != nil || len(live) != 0 {
		t.Errorf("LiveMailLinks() after expiry = %v, %v; want none", live, err)
	}
	// The row is still live before its expiry.
	if _, err := in.Driver.MailLinkByToken(ctx, link.TokenHash, time.Now()); err != nil {
		t.Errorf("MailLinkByToken() before expiry error = %v", err)
	}
}

func testMailLinkCascade(ctx context.Context, t *testing.T, h *AuthHarness) {
	in := h.New(ctx, t, Auth, AuthConfig{Auth: true})
	gone := createUser(ctx, t, in.Driver, "gone@lakeside.edu")
	verification := newMailLink(dbtype.MailLinkVerification, "gone.new@lakeside.edu", tokenHash(1))
	verification.UserID = ccc.NullUUIDFromUUID(gone.ID)
	if err := in.Driver.InsertMailLink(ctx, verification); err != nil {
		t.Fatalf("InsertMailLink() error = %v", err)
	}
	invitation := insertInvitation(ctx, t, in.Driver, "other@lakeside.edu", "", nil, tokenHash(2))

	if err := in.Driver.DeleteUser(ctx, gone.ID); err != nil {
		t.Fatalf("DeleteUser() error = %v", err)
	}
	if _, err := in.Driver.MailLinkByToken(ctx, verification.TokenHash, time.Now()); !httpio.HasNotFound(err) {
		t.Errorf("MailLinkByToken() of the deleted user's verification error = %v, want NotFound: the link goes with its user", err)
	}
	if _, err := in.Driver.MailLinkByToken(ctx, invitation.TokenHash, time.Now()); err != nil {
		t.Errorf("MailLinkByToken() of an invitation error = %v, want it kept: it belongs to no user", err)
	}
}

func testInvitationSignIn(ctx context.Context, t *testing.T, h *AuthHarness) {
	rec := newAcceptances()
	in := h.New(ctx, t, AuthWithAppTables, AuthConfig{Auth: true, Accounts: signin.InvitedUsersOnly, Accept: rec.hook})

	// A stranger with an invitation is provisioned under the invited-users-only rule,
	// with the invitation's address verified, and the hook's grant follows the commit.
	const name = "pat.lee@lakeside.edu"
	link := insertInvitation(ctx, t, in.Driver, name, "lakeside", []string{"Teacher"}, tokenHash(1))
	identity := entra("oid-pat", name)
	req := &sessioninfo.NewSessionRequest{Reason: sessioninfo.ReasonLogin, Username: name, Identity: identity, Invitation: invitationOf(link)}
	err := signInRequest(ctx, in, req)
	assertProvisioned(ctx, t, in.Driver, err, req, identity, "tenant-1")
	if !req.Invitation.Accepted {
		t.Error("Invitation.Accepted = false after the sign-in, want accepted")
	}
	pat := mustUser(ctx, t, in.Driver, req.UserID)
	assertEmail(t, "the provisioned user", pat, strPtr(name), true)
	assertAccepted(t, rec, "accepted:"+name, pat.ID.String()+" "+name+" lakeside Teacher")
	if consumedAt := h.MailLinkConsumedAt(ctx, t, in.Raw, link.TokenHash); consumedAt == nil {
		t.Error("the invitation's ConsumedAt = nil after the sign-in, want consumed")
	}

	// An existing user signing in with an invitation accepts it too, and takes its
	// address when they hold none.
	alex := createUser(ctx, t, in.Driver, "alex@lakeside.edu")
	alexIdentity := entra("oid-alex", "alex@lakeside.edu")
	mustLink(ctx, t, in.Driver, alex.ID, alexIdentity)
	alexLink := insertInvitation(ctx, t, in.Driver, "alex.contact@lakeside.edu", "", []string{"Admin"}, tokenHash(2))
	alexReq := &sessioninfo.NewSessionRequest{Reason: sessioninfo.ReasonLogin, Username: alex.Username, Identity: alexIdentity, Invitation: invitationOf(alexLink)}
	if err := signInRequest(ctx, in, alexReq); err != nil {
		t.Fatalf("sign-in of a linked user with an invitation error = %v", err)
	}
	if !alexReq.Invitation.Accepted {
		t.Error("Invitation.Accepted = false for the linked user, want accepted")
	}
	assertEmail(t, "the linked user", mustUser(ctx, t, in.Driver, alex.ID), strPtr("alex.contact@lakeside.edu"), true)
	assertAccepted(t, rec, "accepted:alex.contact@lakeside.edu", alex.ID.String()+" alex@lakeside.edu  Admin")

	// An invitation to an address another user holds grants, but writes no address.
	if _, err := in.Driver.CreateUser(ctx, &dbtype.InsertSessionUser{Username: "sam", Email: strPtr("taken@lakeside.edu")}, nil); err != nil {
		t.Fatalf("CreateUser() error = %v", err)
	}
	takenLink := insertInvitation(ctx, t, in.Driver, "taken@lakeside.edu", "lakeside", []string{"Coach"}, tokenHash(3))
	newIdentity := entra("oid-new", "new@lakeside.edu")
	newReq := &sessioninfo.NewSessionRequest{Reason: sessioninfo.ReasonLogin, Username: "new@lakeside.edu", Identity: newIdentity, Invitation: invitationOf(takenLink)}
	err = signInRequest(ctx, in, newReq)
	assertProvisioned(ctx, t, in.Driver, err, newReq, newIdentity, "tenant-1")
	if !newReq.Invitation.Accepted {
		t.Error("Invitation.Accepted = false when the address is held elsewhere, want accepted")
	}
	assertEmail(t, "the user provisioned by an invitation to a held address", mustUser(ctx, t, in.Driver, newReq.UserID), nil, false)
	assertAccepted(t, rec, "accepted:taken@lakeside.edu", newReq.UserID.String()+" new@lakeside.edu lakeside Coach")
}

func testInvitationDead(ctx context.Context, t *testing.T, h *AuthHarness) {
	const name = "pat.lee@lakeside.edu"

	// A member of the directory signs in whatever became of the invitation: nothing
	// is granted and no address written.
	rec := newAcceptances()
	member := h.New(ctx, t, AuthWithAppTables, AuthConfig{Auth: true, Accounts: signin.MembersOfDirectory, Accept: rec.hook})
	link := insertInvitation(ctx, t, member.Driver, name, "lakeside", []string{"Teacher"}, tokenHash(1))
	if err := member.Driver.ConsumeMailLink(ctx, link.TokenHash, time.Now()); err != nil {
		t.Fatalf("ConsumeMailLink() error = %v", err)
	}
	identity := entra("oid-pat", name)
	req := &sessioninfo.NewSessionRequest{Reason: sessioninfo.ReasonLogin, Username: name, Identity: identity, Invitation: invitationOf(link)}
	err := signInRequest(ctx, member, req)
	assertProvisioned(ctx, t, member.Driver, err, req, identity, "tenant-1")
	if req.Invitation.Accepted {
		t.Error("Invitation.Accepted = true for a dead invitation, want false")
	}
	assertEmail(t, "the member provisioned beside a dead invitation", mustUser(ctx, t, member.Driver, req.UserID), nil, false)
	if _, found := rec.recorded("accepted:" + name); found {
		t.Error("the hook ran for a dead invitation, want nothing granted")
	}

	// Under the invited-users-only rule the invitation was the admission: a dead one
	// refuses the sign-in and provisions nothing.
	invited := h.New(ctx, t, AuthWithAppTables, AuthConfig{Auth: true, Accounts: signin.InvitedUsersOnly, Accept: rec.hook})
	deadLink := insertInvitation(ctx, t, invited.Driver, name, "lakeside", []string{"Teacher"}, tokenHash(2))
	if err := invited.Driver.ConsumeMailLink(ctx, deadLink.TokenHash, time.Now()); err != nil {
		t.Fatalf("ConsumeMailLink() error = %v", err)
	}
	deadReq := &sessioninfo.NewSessionRequest{Reason: sessioninfo.ReasonLogin, Username: name, Identity: identity, Invitation: invitationOf(deadLink)}
	err = signInRequest(ctx, invited, deadReq)
	assertRefused(t, err, sessioninfo.RefusedInvitationExpired, signin.ErrInvitationExpired)
	assertNoUser(ctx, t, invited.Driver, name)
	assertNoLink(ctx, t, invited.Driver, identity)
	if _, found := rec.recorded("accepted:" + name); found {
		t.Error("the hook ran for a dead invitation, want nothing granted")
	}
}

func testInvitationHookFails(ctx context.Context, t *testing.T, h *AuthHarness) {
	const name = "pat.lee@lakeside.edu"
	in := h.New(ctx, t, AuthWithAppTables, AuthConfig{
		Auth: true, Accounts: signin.InvitedUsersOnly,
		Accept: func(context.Context, ccc.UUID, string, *sessioninfo.Invitation) error {
			return errors.New("the seat could not be granted")
		},
	})
	link := insertInvitation(ctx, t, in.Driver, name, "lakeside", []string{"Teacher"}, tokenHash(1))
	identity := entra("oid-pat", name)
	req := &sessioninfo.NewSessionRequest{Reason: sessioninfo.ReasonLogin, Username: name, Identity: identity, Invitation: invitationOf(link)}

	// The hook runs once the resolution has committed: the sign-in ends with its
	// error and writes no session, the user it provisioned and the consumed
	// invitation stay, so the link is dead and the person is invited again.
	err := signInRequest(ctx, in, req)
	if err == nil {
		t.Fatal("sign-in error = nil, want the hook's failure")
	}
	var refusal *sessioninfo.LoginRefusal
	if errors.As(err, &refusal) {
		t.Errorf("sign-in error = %v, want the hook's error, not a refusal", err)
	}
	if req.Invitation.Accepted {
		t.Error("Invitation.Accepted = true after the hook failed, want false")
	}
	if _, err := in.Driver.UserByUserName(ctx, name); err != nil {
		t.Errorf("UserByUserName(%q) after the hook failed error = %v, want the provisioned user: the resolution committed", name, err)
	}
	if _, err := in.Driver.MailLinkByToken(ctx, link.TokenHash, time.Now()); !httpio.HasNotFound(err) {
		t.Errorf("MailLinkByToken() after the hook failed error = %v, want NotFound: the invitation was consumed", err)
	}
}

func testInvitationAcceptedByHand(ctx context.Context, t *testing.T, h *AuthHarness) {
	rec := newAcceptances()
	in := h.New(ctx, t, AuthWithAppTables, AuthConfig{Auth: true, Accept: rec.hook})

	// A password sign-in accepts the invitation it carries, in a transaction of its own.
	pat := passwordUser(ctx, t, in.Driver, "pat")
	link := insertInvitation(ctx, t, in.Driver, "pat@lakeside.edu", "lakeside", []string{"Teacher"}, tokenHash(1))
	req := &sessioninfo.NewSessionRequest{
		Reason: sessioninfo.ReasonLogin, Username: pat.Username, UserID: pat.ID,
		Identity: &sessioninfo.Identity{Method: sessioninfo.MethodPassword, Subject: pat.ID.String()}, Invitation: invitationOf(link),
	}
	if err := signInRequest(ctx, in, req); err != nil {
		t.Fatalf("password sign-in with an invitation error = %v", err)
	}
	if !req.Invitation.Accepted {
		t.Error("Invitation.Accepted = false after the password sign-in, want accepted")
	}
	assertEmail(t, "the password user", mustUser(ctx, t, in.Driver, pat.ID), strPtr("pat@lakeside.edu"), true)
	assertAccepted(t, rec, "accepted:pat@lakeside.edu", pat.ID.String()+" pat lakeside Teacher")
	if _, err := in.Driver.MailLinkByToken(ctx, link.TokenHash, time.Now()); !httpio.HasNotFound(err) {
		t.Errorf("MailLinkByToken() after the acceptance error = %v, want NotFound", err)
	}

	// An acceptance by hand, for a person already signed in, does the same, once.
	alex := createUser(ctx, t, in.Driver, "alex")
	alexLink := insertInvitation(ctx, t, in.Driver, "alex@lakeside.edu", "", []string{"Admin"}, tokenHash(2))
	inv := invitationOf(alexLink)
	if err := in.Accept(ctx, alex.ID, alex.Username, inv); err != nil {
		t.Fatalf("Accept() error = %v", err)
	}
	if !inv.Accepted {
		t.Error("Invitation.Accepted = false after Accept(), want accepted")
	}
	assertEmail(t, "the user who accepted by hand", mustUser(ctx, t, in.Driver, alex.ID), strPtr("alex@lakeside.edu"), true)
	assertAccepted(t, rec, "accepted:alex@lakeside.edu", alex.ID.String()+" alex  Admin")
	if err := in.Accept(ctx, alex.ID, alex.Username, invitationOf(alexLink)); !httpio.HasNotFound(err) {
		t.Errorf("second Accept() error = %v, want NotFound: an invitation is accepted once", err)
	}
}
