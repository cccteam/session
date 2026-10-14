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

// The drivers write no application time into a column that records when something
// happened. A session's CreatedAt and UpdatedAt, its AuthenticatedAt, an auth event's
// OccurredAt, an impersonation record's StartedAt and EndedAt, an identity link's
// CreatedAt and LastUsedAt, a pending sign-in's CreatedAt and ConsumedAt all take the
// database's time: Spanner's commit timestamp, PostgreSQL's transaction time. A column
// that holds a deadline (ExpiresAt) is the caller's and is written as given.
//
// These cases pin what that means on both backends: the time lies within the call that
// wrote it, and everything one write stores shares it exactly. The suite's host is the
// database's host, so the window is checked against the host clock; the sharing is
// checked against nothing but the rows.

// timeWindow brackets a call. The database's time for what the call wrote lies between
// start, truncated to the microsecond the backends store, and the call's return, plus
// the harness's ClockLead: PostgreSQL runs on the host's clock, and so does Spanner in
// production (a commit timestamp lies within the commit), but the Spanner emulator's
// clock hands out strictly increasing microseconds, and a burst of calls pushes it
// ahead of real time by a few milliseconds, which grow over a parallel run. The lower
// bound is strict on every backend: a stamp from before the call is a stale or
// caller-supplied value.
type timeWindow struct {
	start, end time.Time
	lead       time.Duration
}

// startWindow opens a window at the call's start; lead is the harness's ClockLead.
func startWindow(lead time.Duration) *timeWindow {
	return &timeWindow{start: time.Now().Truncate(time.Microsecond), lead: lead}
}

// done closes the window at the call's return.
func (w *timeWindow) done() {
	w.end = time.Now().Add(w.lead)
}

// assertStamped fails unless got is a time the database stamped within the window.
func (w *timeWindow) assertStamped(t *testing.T, name string, got time.Time) {
	t.Helper()

	if got.Before(w.start) || got.After(w.end) {
		t.Errorf("%s = %v, want the database's time, within [%v, %v]", name, got, w.start, w.end)
	}
}

// assertSameTime fails unless got is exactly want: one write, one time.
func assertSameTime(t *testing.T, name string, got, want time.Time) {
	t.Helper()

	if !got.Equal(want) {
		t.Errorf("%s = %v, want exactly %v: one write stamps one time", name, got, want)
	}
}

func testDatabaseTimeOnInsert(ctx context.Context, t *testing.T, h *Harness) {
	inst := h.New(ctx, t, Sessions, Config{Impersonation: true})
	c := inst.Driver

	// A row is created and updated at one time, the database's.
	w := startWindow(h.ClockLead)
	id, err := c.InsertSession(ctx, &dbtype.InsertSession{Username: "pat@lakeside.edu"}, &sessioninfo.NewSessionRequest{Reason: sessioninfo.ReasonLogin, Username: "pat@lakeside.edu"})
	w.done()
	if err != nil {
		t.Fatalf("InsertSession() error = %v", err)
	}
	sess, err := c.Session(ctx, id)
	if err != nil {
		t.Fatalf("Session() error = %v", err)
	}
	w.assertStamped(t, "Session().CreatedAt", sess.CreatedAt)
	assertSameTime(t, "Session().UpdatedAt", sess.UpdatedAt, sess.CreatedAt)

	// An impersonated session's record starts when its row is created.
	imp := &dbtype.InsertImpersonation{ActorUsername: "pat@lakeside.edu", PrincipalKind: dbtype.PrincipalKindUser, PrincipalUser: strPtr("sam@lakeside.edu"), ExpiresAt: time.Now().Add(time.Hour)}
	w = startWindow(h.ClockLead)
	impID, err := c.InsertImpersonatedSession(ctx, &dbtype.InsertSession{Username: "sam@lakeside.edu"}, &sessioninfo.NewSessionRequest{Reason: sessioninfo.ReasonImpersonation, Username: "sam@lakeside.edu"}, imp)
	w.done()
	if err != nil {
		t.Fatalf("InsertImpersonatedSession() error = %v", err)
	}
	impersonated, err := c.Session(ctx, impID)
	if err != nil {
		t.Fatalf("Session() error = %v", err)
	}
	w.assertStamped(t, "Session().CreatedAt", impersonated.CreatedAt)
	assertSameTime(t, "Session().UpdatedAt", impersonated.UpdatedAt, impersonated.CreatedAt)
	if impersonated.Impersonation == nil {
		t.Fatal("Session().Impersonation = nil, want the record")
	}
	assertSameTime(t, "Session().Impersonation.StartedAt", impersonated.Impersonation.StartedAt, impersonated.CreatedAt)

	// Destroying the session moves UpdatedAt and ends the record at that same time.
	w = startWindow(h.ClockLead)
	if err := c.DestroySession(ctx, impID); err != nil {
		t.Fatalf("DestroySession() error = %v", err)
	}
	w.done()
	destroyed, err := c.Session(ctx, impID)
	if err != nil {
		t.Fatalf("Session() error = %v", err)
	}
	if !destroyed.Expired {
		t.Error("Session().Expired = false after DestroySession()")
	}
	w.assertStamped(t, "Session().UpdatedAt after DestroySession()", destroyed.UpdatedAt)
	if !destroyed.UpdatedAt.After(impersonated.UpdatedAt) {
		t.Errorf("Session().UpdatedAt after DestroySession() = %v, want it moved past %v", destroyed.UpdatedAt, impersonated.UpdatedAt)
	}
	endedAt, _ := h.RecordEnd(ctx, t, inst.Raw, impID)
	if endedAt == nil {
		t.Fatal("record EndedAt = nil after DestroySession(), want the database's time")
	}
	assertSameTime(t, "record EndedAt", *endedAt, destroyed.UpdatedAt)
}

func testDatabaseTimeOnDestroyAll(ctx context.Context, t *testing.T, h *Harness) {
	inst := h.New(ctx, t, Sessions, Config{Impersonation: true})
	c := inst.Driver

	const name = "pat@lakeside.edu"
	start := func(username string) ccc.UUID {
		t.Helper()
		id, err := c.InsertSession(ctx, &dbtype.InsertSession{Username: username}, &sessioninfo.NewSessionRequest{Reason: sessioninfo.ReasonLogin, Username: username})
		if err != nil {
			t.Fatalf("InsertSession() error = %v", err)
		}

		return id
	}
	first, second := start(name), start(name)
	imp := &dbtype.InsertImpersonation{ActorUsername: name, PrincipalKind: dbtype.PrincipalKindUser, PrincipalUser: strPtr("sam@lakeside.edu"), ExpiresAt: time.Now().Add(time.Hour)}
	held, err := c.InsertImpersonatedSession(ctx, &dbtype.InsertSession{Username: "sam@lakeside.edu"}, &sessioninfo.NewSessionRequest{Reason: sessioninfo.ReasonImpersonation, Username: "sam@lakeside.edu"}, imp)
	if err != nil {
		t.Fatalf("InsertImpersonatedSession() error = %v", err)
	}

	w := startWindow(h.ClockLead)
	if err := c.DestroyAllUserSessions(ctx, name); err != nil {
		t.Fatalf("DestroyAllUserSessions() error = %v", err)
	}
	w.done()

	// Every session expired in the one transaction carries its one time, and so does
	// the record it ended.
	var expiredAt time.Time
	for _, id := range []ccc.UUID{first, second, held} {
		sess, err := c.Session(ctx, id)
		if err != nil {
			t.Fatalf("Session(%v) error = %v", id, err)
		}
		if !sess.Expired {
			t.Errorf("Session(%v).Expired = false after DestroyAllUserSessions()", id)
		}
		w.assertStamped(t, "Session().UpdatedAt", sess.UpdatedAt)
		if expiredAt.IsZero() {
			expiredAt = sess.UpdatedAt
		}
		assertSameTime(t, "Session().UpdatedAt", sess.UpdatedAt, expiredAt)
	}
	endedAt, _ := h.RecordEnd(ctx, t, inst.Raw, held)
	if endedAt == nil {
		t.Fatal("record EndedAt = nil after DestroyAllUserSessions(), want the database's time")
	}
	assertSameTime(t, "record EndedAt", *endedAt, expiredAt)
}

func testDatabaseTimeOnSignIn(ctx context.Context, t *testing.T, h *AuthHarness) {
	in := h.New(ctx, t, Auth, AuthConfig{Auth: true, AuthEvents: true, Impersonation: true})
	user := createUser(ctx, t, in.Driver, "pat@lakeside.edu")
	identity := lakeside("idp_pat")

	// A link is created and last used at one time, the database's.
	w := startWindow(h.ClockLead)
	link := mustLink(ctx, t, in.Driver, user.ID, identity)
	w.done()
	w.assertStamped(t, "LinkIdentity().CreatedAt", link.CreatedAt)
	assertSameTime(t, "LinkIdentity().LastUsedAt", link.LastUsedAt, link.CreatedAt)

	// The session, its authentication and its events share the insert's time; the
	// link was touched by the resolution that committed before it.
	w = startWindow(h.ClockLead)
	id, _, err := signIn(ctx, in, identity, sessioninfo.ReasonLogin)
	w.done()
	if err != nil {
		t.Fatalf("sign-in error = %v", err)
	}
	sess := mustSession(ctx, t, in.Driver, id)
	w.assertStamped(t, "Session().CreatedAt", sess.CreatedAt)
	assertSameTime(t, "Session().UpdatedAt", sess.UpdatedAt, sess.CreatedAt)
	if sess.AuthenticatedAt == nil {
		t.Fatal("Session().AuthenticatedAt = nil, want the creation time")
	}
	assertSameTime(t, "Session().AuthenticatedAt", *sess.AuthenticatedAt, sess.CreatedAt)
	if len(sess.AuthEvents) != 1 {
		t.Fatalf("Session().AuthEvents = %v, want the sign-in's one event", sess.AuthEvents)
	}
	assertSameTime(t, "Session().AuthEvents[0].At", sess.AuthEvents[0].At, sess.CreatedAt)
	touched, err := in.Driver.Identity(ctx, identity.Method, identity.Connection, identity.Subject)
	if err != nil {
		t.Fatalf("Identity() error = %v", err)
	}
	w.assertStamped(t, "Identity().LastUsedAt", touched.LastUsedAt)
	if touched.LastUsedAt.After(sess.CreatedAt) {
		t.Errorf("Identity().LastUsedAt = %v, want no later than the session's creation %v: the resolution commits first", touched.LastUsedAt, sess.CreatedAt)
	}
	if !touched.CreatedAt.Equal(link.CreatedAt) {
		t.Errorf("Identity().CreatedAt = %v, want the link's %v, untouched by the sign-in", touched.CreatedAt, link.CreatedAt)
	}

	// An impersonated session's event, record and row share the insert's time.
	imp := dbtype.NewInsertImpersonation(&sessioninfo.Impersonation{Actor: user.Username, Principal: accesstypes.RolePrincipal("Viewer"), ExpiresAt: time.Now().Add(time.Hour)})
	w = startWindow(h.ClockLead)
	impID, err := in.Driver.InsertImpersonatedSession(ctx, newInsertSession(user.Username), &sessioninfo.NewSessionRequest{Reason: sessioninfo.ReasonImpersonation, Username: user.Username}, imp)
	w.done()
	if err != nil {
		t.Fatalf("InsertImpersonatedSession() error = %v", err)
	}
	impersonated := mustSession(ctx, t, in.Driver, impID)
	w.assertStamped(t, "Session().CreatedAt", impersonated.CreatedAt)
	if impersonated.Impersonation == nil || len(impersonated.AuthEvents) != 1 {
		t.Fatalf("Session() = %+v, want the record and the impersonation event", impersonated)
	}
	assertSameTime(t, "Session().Impersonation.StartedAt", impersonated.Impersonation.StartedAt, impersonated.CreatedAt)
	assertSameTime(t, "Session().AuthEvents[0].At", impersonated.AuthEvents[0].At, impersonated.CreatedAt)
}

func testDatabaseTimeOnRevocation(ctx context.Context, t *testing.T, h *AuthHarness) {
	in := h.New(ctx, t, Auth, AuthConfig{Auth: true, Impersonation: true})
	pat := createUser(ctx, t, in.Driver, "pat@lakeside.edu")
	sam := createUser(ctx, t, in.Driver, "sam@lakeside.edu")

	start := func(user *dbtype.SessionUser) ccc.UUID {
		t.Helper()
		id, err := in.Driver.InsertSession(ctx, newInsertSession(user.Username), &sessioninfo.NewSessionRequest{Reason: sessioninfo.ReasonLogin, Username: user.Username, UserID: user.ID})
		if err != nil {
			t.Fatalf("InsertSession() error = %v", err)
		}

		return id
	}
	first, second := start(pat), start(pat)
	imp := dbtype.NewInsertImpersonation(&sessioninfo.Impersonation{Actor: pat.Username, Principal: accesstypes.UserPrincipal(accesstypes.User(sam.Username)), ExpiresAt: time.Now().Add(time.Hour)})
	held, err := in.Driver.InsertImpersonatedSession(ctx, newInsertSession(sam.Username), &sessioninfo.NewSessionRequest{Reason: sessioninfo.ReasonImpersonation, Username: sam.Username, UserID: sam.ID}, imp)
	if err != nil {
		t.Fatalf("InsertImpersonatedSession() error = %v", err)
	}

	w := startWindow(h.ClockLead)
	if err := in.Driver.DestroyUserSessions(ctx, pat.ID); err != nil {
		t.Fatalf("DestroyUserSessions() error = %v", err)
	}
	w.done()

	// Every session expired in the one transaction carries its one time, and so does
	// the record it ended.
	var expiredAt time.Time
	for _, id := range []ccc.UUID{first, second, held} {
		sess := mustSession(ctx, t, in.Driver, id)
		if !sess.Expired {
			t.Errorf("Session(%v).Expired = false after DestroyUserSessions()", id)
		}
		w.assertStamped(t, "Session().UpdatedAt", sess.UpdatedAt)
		if expiredAt.IsZero() {
			expiredAt = sess.UpdatedAt
		}
		assertSameTime(t, "Session().UpdatedAt", sess.UpdatedAt, expiredAt)
	}
	record := mustSession(ctx, t, in.Driver, held).Impersonation
	if record == nil || record.EndedAt == nil {
		t.Fatalf("the held session's record = %+v, want it ended", record)
	}
	assertSameTime(t, "Session().Impersonation.EndedAt", *record.EndedAt, expiredAt)
}
