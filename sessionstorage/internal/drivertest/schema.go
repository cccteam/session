package drivertest

import (
	"context"
	"testing"
	"time"

	"github.com/cccteam/ccc"
	"github.com/cccteam/httpio"
	"github.com/cccteam/session/internal/dbtype"
	"github.com/cccteam/session/sessioninfo"
)

// The shipped auth schema holds its own integrity: a session belongs to an existing user
// by foreign key, and deleting a user takes its sessions, their events and its links
// with it. These cases prove the DDL as shipped on both backends, and the upgrade set
// from the legacy Azure layout.

func testDeleteUserCascades(ctx context.Context, t *testing.T, h *AuthHarness) {
	in := h.New(ctx, t, Auth, AuthConfig{Auth: true, AuthEvents: true})
	gone := createUser(ctx, t, in.Driver, "gone@lakeside.edu")
	stays := createUser(ctx, t, in.Driver, "stays@lakeside.edu")
	mustLink(ctx, t, in.Driver, gone.ID, lakeside("idp_gone"))
	keptLink := mustLink(ctx, t, in.Driver, stays.ID, lakeside("idp_stays"))

	goneSession, _, err := signIn(ctx, in, lakeside("idp_gone"), sessioninfo.ReasonLogin)
	if err != nil {
		t.Fatalf("sign-in of the user to delete error = %v", err)
	}
	staysSession, _, err := signIn(ctx, in, lakeside("idp_stays"), sessioninfo.ReasonLogin)
	if err != nil {
		t.Fatalf("sign-in of the other user error = %v", err)
	}
	if n := h.CountAuthEvents(ctx, t, in.Raw, goneSession); n != 1 {
		t.Fatalf("auth events of the session to delete = %d, want 1", n)
	}

	if err := in.Driver.DeleteUser(ctx, gone.ID); err != nil {
		t.Fatalf("DeleteUser() error = %v", err)
	}

	if _, err := in.Driver.Session(ctx, goneSession); !httpio.HasNotFound(err) {
		t.Errorf("Session() of the deleted user's session error = %v, want NotFound: the session row goes with its user", err)
	}
	if n := h.CountAuthEvents(ctx, t, in.Raw, goneSession); n != 0 {
		t.Errorf("auth events of the deleted user's session = %d, want 0: they go with the session row", n)
	}
	assertNoLink(ctx, t, in.Driver, lakeside("idp_gone"))
	if sess := mustSession(ctx, t, in.Driver, staysSession); sess.UserID != ccc.NullUUIDFromUUID(stays.ID) {
		t.Errorf("the other user's session = %+v, want it kept under %s", sess, stays.ID)
	}
	if link, err := in.Driver.Identity(ctx, sessioninfo.MethodWorkOS, "conn_lakeside", "idp_stays"); err != nil || link.ID != keptLink.ID {
		t.Errorf("Identity() of the other user's link = %v, %v; want it kept", link, err)
	}
}

func testSessionUserForeignKey(ctx context.Context, t *testing.T, h *AuthHarness) {
	in := h.New(ctx, t, Auth, AuthConfig{Auth: true})
	user := createUser(ctx, t, in.Driver, "pat@lakeside.edu")

	unknown := ccc.Must(ccc.NewUUID())
	if _, err := in.Driver.InsertSession(ctx, newInsertSession("ghost"), &sessioninfo.NewSessionRequest{Reason: sessioninfo.ReasonLogin, Username: "ghost", UserID: unknown}); err == nil {
		t.Error("InsertSession() for a user id that does not exist error = nil, want the schema's refusal")
	}

	// A session with a user, and one with none (a preauth stepping stone), are both inserted.
	if _, err := in.Driver.InsertSession(ctx, newInsertSession(user.Username), &sessioninfo.NewSessionRequest{Reason: sessioninfo.ReasonLogin, Username: user.Username, UserID: user.ID}); err != nil {
		t.Errorf("InsertSession() for an existing user error = %v", err)
	}
	if _, err := in.Driver.InsertSession(ctx, newInsertSession("stepping-stone"), &sessioninfo.NewSessionRequest{Reason: sessioninfo.ReasonPreauth, Username: "stepping-stone"}); err != nil {
		t.Errorf("InsertSession() of a preauth stepping stone error = %v", err)
	}
}

func testUpgradeFromOIDC(ctx context.Context, t *testing.T, h *AuthHarness) {
	in := h.New(ctx, t, AuthFromOIDC, AuthConfig{Auth: true, AuthEvents: true, Impersonation: true})

	// The anchor's rows are users under the same ids, each with its Azure identity.
	old, err := in.Driver.UserByUserName(ctx, "old@lakeside.edu")
	if err != nil || old.ID != AnchoredOld || old.PasswordHash != nil || old.Disabled {
		t.Fatalf("UserByUserName(old) = %+v, %v; want the anchored user under %s, password-less and enabled", old, err, AnchoredOld)
	}
	if other, err := in.Driver.UserByUserName(ctx, "other@lakeside.edu"); err != nil || other.ID != AnchoredOther {
		t.Errorf("UserByUserName(other) = %+v, %v; want the anchored user under %s", other, err, AnchoredOther)
	}
	link, err := in.Driver.Identity(ctx, sessioninfo.MethodAzure, "tid-1", "oid-old")
	if err != nil || link.UserID != AnchoredOld || link.Tenant != nil {
		t.Fatalf("Identity(azure, tid-1, oid-old) = %+v, %v; want a link to %s without a tenant", link, err, AnchoredOld)
	}
	if links, err := in.Driver.IdentitiesByUser(ctx, AnchoredOther); err != nil || len(links) != 1 || links[0].Subject != anchoredOtherSubject {
		t.Errorf("IdentitiesByUser(other) = %v, %v; want the one Azure identity %s", links, err, anchoredOtherSubject)
	}

	// The live legacy session now belongs to its user.
	if sess := mustSession(ctx, t, in.Driver, SeededLegacySession); sess.UserID != ccc.NullUUIDFromUUID(AnchoredOld) || sess.AuthenticatedAt != nil {
		t.Errorf("the seeded legacy session = UserId %v, AuthenticatedAt %v; want %s and no authentication time", sess.UserID, sess.AuthenticatedAt, AnchoredOld)
	}

	// Auth serves the group: the Azure identity signs in through its link, a password
	// user can be created, a sign-in can be held, and an impersonation recorded.
	id, req, err := signIn(ctx, in, anchoredOldIdentity, sessioninfo.ReasonLogin)
	if err != nil || req.UserID != AnchoredOld {
		t.Fatalf("sign-in of the anchored identity = %v, user %v; want a session of %s", err, req.UserID, AnchoredOld)
	}
	if sess := mustSession(ctx, t, in.Driver, id); sess.UserID != ccc.NullUUIDFromUUID(AnchoredOld) || len(sess.AuthEvents) != 1 {
		t.Errorf("the new session = %+v, want it under %s with its sign-in event", sess, AnchoredOld)
	}
	pat := createUser(ctx, t, in.Driver, "pat@lakeside.edu")
	if _, err := in.Driver.InsertSession(ctx, newInsertSession(pat.Username), &sessioninfo.NewSessionRequest{Reason: sessioninfo.ReasonLogin, Username: pat.Username, UserID: pat.ID}); err != nil {
		t.Errorf("InsertSession() of a new password user error = %v", err)
	}
	now := time.Now()
	pending := &dbtype.PendingSignIn{
		ID: ccc.Must(ccc.NewUUID()), TokenHash: make([]byte, 32), Step: sessioninfo.PendingMFA, Identity: *anchoredOldIdentity,
		UserID: ccc.NullUUIDFromUUID(AnchoredOld), Username: "old@lakeside.edu", Events: []sessioninfo.AuthEvent{{Method: sessioninfo.MethodAzure, At: now}},
		CreatedAt: now, ExpiresAt: now.Add(time.Hour),
	}
	if err := in.Driver.InsertPendingSignIn(ctx, pending); err != nil {
		t.Errorf("InsertPendingSignIn() on the upgraded schema error = %v", err)
	}
	if _, err := in.Driver.InsertImpersonatedSession(ctx, newInsertSession(pat.Username),
		&sessioninfo.NewSessionRequest{Reason: sessioninfo.ReasonImpersonation, Username: pat.Username, UserID: pat.ID},
		&dbtype.InsertImpersonation{ActorUsername: "old@lakeside.edu", PrincipalKind: dbtype.PrincipalKindUser, PrincipalUser: strPtr(pat.Username), StartedAt: now, ExpiresAt: now.Add(time.Hour)}); err != nil {
		t.Errorf("InsertImpersonatedSession() on the upgraded schema error = %v", err)
	}
}
