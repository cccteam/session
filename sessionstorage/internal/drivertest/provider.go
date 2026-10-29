package drivertest

import (
	"context"
	"slices"
	"testing"
	"time"

	"github.com/cccteam/ccc"
	"github.com/cccteam/ccc/accesstypes"
	"github.com/cccteam/session/internal/dbtype"
	"github.com/cccteam/session/sessioninfo"
)

// A sign-in's provider session id (an OpenID Connect sid) is recorded with the session
// row under the registration's issuer, and a provider-initiated logout ends every live
// session under that issuer and id: the sign-in's own, a regenerated one that kept
// them, and an impersonation started from it (its record ends Logout). A session under
// another issuer or another id, one without an id, and one with an id but no issuer (a
// legacy session the upgrade carried over) stay. The issuers live sessions carry an id
// under are listed, for a logout that names no issuer; the issuerless session is not.

func testProviderSessionLogout(ctx context.Context, t *testing.T, h *AuthHarness) {
	in := h.New(ctx, t, Auth, AuthConfig{Auth: true, Impersonation: true})
	pat := createUser(ctx, t, in.Driver, "pat@lakeside.edu")
	sam := createUser(ctx, t, in.Driver, "sam@lakeside.edu")

	const lakeside, riverside = "https://login/lakeside", "https://login/riverside"
	start := func(user *dbtype.SessionUser, issuer, sid string) ccc.UUID {
		t.Helper()
		id, err := in.Driver.InsertSession(ctx, newInsertSession(user.Username), &sessioninfo.NewSessionRequest{
			Reason: sessioninfo.ReasonLogin, Username: user.Username, UserID: user.ID, ProviderSessionID: sid, ProviderSessionIssuer: issuer,
		})
		if err != nil {
			t.Fatalf("InsertSession() error = %v", err)
		}

		return id
	}
	imp := dbtype.NewInsertImpersonation(&sessioninfo.Impersonation{Actor: pat.Username, Principal: accesstypes.UserPrincipal(accesstypes.User(sam.Username)), ExpiresAt: time.Now().Add(time.Hour)})
	impersonated, err := in.Driver.InsertImpersonatedSession(ctx, newInsertSession(sam.Username),
		&sessioninfo.NewSessionRequest{Reason: sessioninfo.ReasonImpersonation, Username: sam.Username, UserID: sam.ID, ProviderSessionID: "sid-1", ProviderSessionIssuer: lakeside}, imp)
	if err != nil {
		t.Fatalf("InsertImpersonatedSession() error = %v", err)
	}

	first := start(pat, lakeside, "sid-1")
	regenerated := start(pat, lakeside, "sid-1")
	otherIssuer := start(pat, riverside, "sid-1")
	otherSID := start(pat, lakeside, "sid-2")
	none := start(sam, "", "")
	// A legacy session the upgrade carried over has an id but no issuer.
	issuerless := start(sam, "", "sid-1")

	if sess := mustSession(ctx, t, in.Driver, first); sess.ProviderSessionID != "sid-1" || sess.ProviderSessionIssuer != lakeside {
		t.Errorf("Session() provider session = (%q, %q), want (sid-1, %s) recorded with the row", sess.ProviderSessionID, sess.ProviderSessionIssuer, lakeside)
	}
	if sess := mustSession(ctx, t, in.Driver, none); sess.ProviderSessionID != "" || sess.ProviderSessionIssuer != "" {
		t.Errorf("Session() provider session of a sign-in without one = (%q, %q), want empty", sess.ProviderSessionID, sess.ProviderSessionIssuer)
	}

	if got, err := in.Driver.ProviderSessionIssuers(ctx, "sid-1"); err != nil || !slices.Equal(got, []string{lakeside, riverside}) {
		t.Errorf("ProviderSessionIssuers(sid-1) = %v, %v; want [%s %s]: the issuers live sessions carry the id under, sorted, the issuerless session left out", got, err, lakeside, riverside)
	}
	if got, err := in.Driver.ProviderSessionIssuers(ctx, "sid-unknown"); err != nil || len(got) != 0 {
		t.Errorf("ProviderSessionIssuers(sid-unknown) = %v, %v; want none", got, err)
	}

	if err := in.Driver.DestroySessionsByProviderSessionID(ctx, lakeside, "sid-1"); err != nil {
		t.Fatalf("DestroySessionsByProviderSessionID() error = %v", err)
	}
	if got, err := in.Driver.ProviderSessionIssuers(ctx, "sid-1"); err != nil || !slices.Equal(got, []string{riverside}) {
		t.Errorf("ProviderSessionIssuers(sid-1) after lakeside's logout = %v, %v; want [%s]: an expired session's issuer is no longer listed", got, err, riverside)
	}

	for _, tc := range []struct {
		name        string
		id          ccc.UUID
		wantExpired bool
	}{
		{name: "the sign-in's own session", id: first, wantExpired: true},
		{name: "a session regenerated from it", id: regenerated, wantExpired: true},
		{name: "an impersonation started from it", id: impersonated, wantExpired: true},
		{name: "a session under the same id at another issuer", id: otherIssuer},
		{name: "a session under another provider session id", id: otherSID},
		{name: "a session without one", id: none},
		{name: "a session with the id but no issuer", id: issuerless},
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
	if err := in.Driver.DestroySessionsByProviderSessionID(ctx, lakeside, "sid-unknown"); err != nil {
		t.Errorf("DestroySessionsByProviderSessionID() of an unknown id error = %v", err)
	}
	if sess := mustSession(ctx, t, in.Driver, otherSID); sess.Expired {
		t.Error("a session under another provider session id was expired by a logout for an unknown id")
	}
	// A logout naming no issuer reaches nothing, the issuerless session included.
	if err := in.Driver.DestroySessionsByProviderSessionID(ctx, "", "sid-1"); err != nil {
		t.Errorf("DestroySessionsByProviderSessionID() without an issuer error = %v", err)
	}
	if sess := mustSession(ctx, t, in.Driver, issuerless); sess.Expired {
		t.Error("a session with the id but no issuer was expired by a logout naming no issuer")
	}
}
