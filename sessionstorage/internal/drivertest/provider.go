package drivertest

import (
	"context"
	"testing"
	"time"

	"github.com/cccteam/ccc"
	"github.com/cccteam/ccc/accesstypes"
	"github.com/cccteam/session/internal/dbtype"
	"github.com/cccteam/session/sessioninfo"
)

// A sign-in's provider session id (an OpenID Connect sid) is recorded with the session
// row, and a provider-initiated logout ends every live session under it: the sign-in's
// own, a regenerated one that kept it, and an impersonation started from it (its record
// ends Logout). A session under another id, or none, stays.

func testProviderSessionLogout(ctx context.Context, t *testing.T, h *AuthHarness) {
	in := h.New(ctx, t, Auth, AuthConfig{Auth: true, Impersonation: true})
	pat := createUser(ctx, t, in.Driver, "pat@lakeside.edu")
	sam := createUser(ctx, t, in.Driver, "sam@lakeside.edu")

	start := func(user *dbtype.SessionUser, sid string) ccc.UUID {
		t.Helper()
		id, err := in.Driver.InsertSession(ctx, newInsertSession(user.Username), &sessioninfo.NewSessionRequest{Reason: sessioninfo.ReasonLogin, Username: user.Username, UserID: user.ID, ProviderSessionID: sid})
		if err != nil {
			t.Fatalf("InsertSession() error = %v", err)
		}

		return id
	}
	now := time.Now()
	imp := dbtype.NewInsertImpersonation(&sessioninfo.Impersonation{Actor: pat.Username, Principal: accesstypes.UserPrincipal(accesstypes.User(sam.Username)), StartedAt: now, ExpiresAt: now.Add(time.Hour)})
	impersonated, err := in.Driver.InsertImpersonatedSession(ctx, newInsertSession(sam.Username),
		&sessioninfo.NewSessionRequest{Reason: sessioninfo.ReasonImpersonation, Username: sam.Username, UserID: sam.ID, ProviderSessionID: "sid-1"}, imp)
	if err != nil {
		t.Fatalf("InsertImpersonatedSession() error = %v", err)
	}

	first := start(pat, "sid-1")
	regenerated := start(pat, "sid-1")
	otherSID := start(pat, "sid-2")
	none := start(sam, "")

	if sess := mustSession(ctx, t, in.Driver, first); sess.ProviderSessionID != "sid-1" {
		t.Errorf("Session().ProviderSessionID = %q, want sid-1 recorded with the row", sess.ProviderSessionID)
	}
	if sess := mustSession(ctx, t, in.Driver, none); sess.ProviderSessionID != "" {
		t.Errorf("Session().ProviderSessionID of a sign-in without one = %q, want empty", sess.ProviderSessionID)
	}

	if err := in.Driver.DestroySessionsByProviderSessionID(ctx, "sid-1"); err != nil {
		t.Fatalf("DestroySessionsByProviderSessionID() error = %v", err)
	}

	for _, tc := range []struct {
		name        string
		id          ccc.UUID
		wantExpired bool
	}{
		{name: "the sign-in's own session", id: first, wantExpired: true},
		{name: "a session regenerated from it", id: regenerated, wantExpired: true},
		{name: "an impersonation started from it", id: impersonated, wantExpired: true},
		{name: "a session under another provider session id", id: otherSID},
		{name: "a session without one", id: none},
	} {
		sess := mustSession(ctx, t, in.Driver, tc.id)
		if sess.Expired != tc.wantExpired {
			t.Errorf("%s: Expired = %v, want %v", tc.name, sess.Expired, tc.wantExpired)
		}
	}
	if sess := mustSession(ctx, t, in.Driver, impersonated); sess.Impersonation == nil || sess.Impersonation.EndedAt == nil || sess.Impersonation.EndReason == nil || *sess.Impersonation.EndReason != string(sessioninfo.ImpersonationEndedByLogout) {
		t.Errorf("the impersonation record = %+v, want ended Logout", sess.Impersonation)
	}

	// A logout for an id no session carries ends nothing and is not an error.
	if err := in.Driver.DestroySessionsByProviderSessionID(ctx, "sid-unknown"); err != nil {
		t.Errorf("DestroySessionsByProviderSessionID() of an unknown id error = %v", err)
	}
	if sess := mustSession(ctx, t, in.Driver, otherSID); sess.Expired {
		t.Error("a session under another provider session id was expired by a logout for an unknown id")
	}
}
