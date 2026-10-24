package session

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"regexp"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/cccteam/ccc"
	"github.com/cccteam/httpio"
	internalcookie "github.com/cccteam/session/internal/cookie"
	"github.com/cccteam/session/internal/signinflow"
	"github.com/cccteam/session/mail"
	"github.com/cccteam/session/sessioninfo"
	"github.com/cccteam/session/sessionstorage"
	"github.com/cccteam/session/sessionstorage/mock/mock_sessionstorage"
	"github.com/go-playground/errors/v5"
	"github.com/google/go-cmp/cmp"
	gomock "go.uber.org/mock/gomock"
)

// mailLinks is the mail links table as the mocked store holds it.
type mailLinks struct {
	mu   sync.Mutex
	rows []*sessionstorage.MailLink
}

// expectMailLinks gives the fixture's store a mail links table and returns it.
func expectMailLinks(f *authFixture) *mailLinks {
	links := &mailLinks{}
	f.store.EXPECT().InsertMailLink(gomock.Any(), gomock.Any()).DoAndReturn(func(_ context.Context, l *sessionstorage.MailLink) error {
		links.mu.Lock()
		defer links.mu.Unlock()
		l.ID = ccc.Must(ccc.NewUUID())
		l.CreatedAt = time.Now()
		row := *l
		links.rows = append(links.rows, &row)

		return nil
	}).AnyTimes()
	f.store.EXPECT().MailLink(gomock.Any(), gomock.Any()).DoAndReturn(func(_ context.Context, hash []byte) (*sessionstorage.MailLink, error) {
		if l := links.live(hash); l != nil {
			row := *l

			return &row, nil
		}

		return nil, httpio.NewNotFoundMessage("no live mail link")
	}).AnyTimes()
	f.store.EXPECT().ConsumeMailLink(gomock.Any(), gomock.Any()).DoAndReturn(func(_ context.Context, hash []byte) error {
		links.mu.Lock()
		defer links.mu.Unlock()
		for _, l := range links.rows {
			if bytes.Equal(l.TokenHash, hash) && l.ConsumedAt == nil {
				now := time.Now()
				l.ConsumedAt = &now

				return nil
			}
		}

		return httpio.NewNotFoundMessage("no live mail link")
	}).AnyTimes()
	f.store.EXPECT().RevokeMailLink(gomock.Any(), gomock.Any()).DoAndReturn(func(_ context.Context, id ccc.UUID) error {
		links.mu.Lock()
		defer links.mu.Unlock()
		for _, l := range links.rows {
			if l.ID == id && l.ConsumedAt == nil {
				now := time.Now()
				l.ConsumedAt = &now

				return nil
			}
		}

		return httpio.NewNotFoundMessage("no live mail link")
	}).AnyTimes()
	f.store.EXPECT().LiveMailLinks(gomock.Any(), gomock.Any()).DoAndReturn(func(_ context.Context, kind sessionstorage.MailLinkKind) ([]*sessionstorage.MailLink, error) {
		links.mu.Lock()
		defer links.mu.Unlock()
		var live []*sessionstorage.MailLink
		for _, l := range links.rows {
			if l.Kind == kind && l.ConsumedAt == nil {
				row := *l
				live = append(live, &row)
			}
		}

		return live, nil
	}).AnyTimes()

	return links
}

// live is the live row holding hash, or nil.
func (m *mailLinks) live(hash []byte) *sessionstorage.MailLink {
	m.mu.Lock()
	defer m.mu.Unlock()
	for _, l := range m.rows {
		if bytes.Equal(l.TokenHash, hash) && l.ConsumedAt == nil && time.Now().Before(l.ExpiresAt) {
			return l
		}
	}

	return nil
}

// last is the last row inserted.
func (m *mailLinks) last(t *testing.T) *sessionstorage.MailLink {
	t.Helper()
	m.mu.Lock()
	defer m.mu.Unlock()
	if len(m.rows) == 0 {
		t.Fatal("no mail link was inserted")
	}

	return m.rows[len(m.rows)-1]
}

// insert adds a row by hand, as an earlier call would have.
func (m *mailLinks) insert(l *sessionstorage.MailLink) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if l.ID.IsNil() {
		l.ID = ccc.Must(ccc.NewUUID())
	}
	m.rows = append(m.rows, l)
}

// testMail is the fixture's mail: a recorder and the settings.
var testMail = MailSettings{Application: "Harbor", LoginURL: "https://harbor.test/login"}

// newMailFixture is an Auth fixture that sends mail to a recorder, with the password
// method registered under passwordOptions.
func newMailFixture(t *testing.T, ctrl *gomock.Controller, passwordOptions ...PasswordOption) (*authFixture, *mail.Recorder, *mailLinks) {
	t.Helper()

	recorder := &mail.Recorder{}
	f := newAuthFixtureWith(t, ctrl, passwordOptions, WithMail(recorder, testMail))

	return f, recorder, expectMailLinks(f)
}

// tokenIn is the token the link in body carries under param.
func tokenIn(t *testing.T, body, param string) string {
	t.Helper()

	m := regexp.MustCompile(`https://harbor\.test/login\?` + param + `=([A-Za-z0-9_-]+)`).FindStringSubmatch(body)
	if m == nil {
		t.Fatalf("no link with ?%s= in the message:\n%s", param, body)
	}

	return m[1]
}

func TestMailSettings_Messages(t *testing.T) {
	t.Parallel()

	m := &mailSettings{settings: testMail}
	for _, tt := range []struct {
		name string
		got  mail.Message
		want mail.Message
	}{
		{
			name: "an invitation: the instruction and link, how long it is good for, then what to do if it was not expected and to keep the link",
			got:  m.invitationMessage("pat@lakeside.edu", "tok_1", 7*24*time.Hour),
			want: mail.Message{To: "pat@lakeside.edu", Subject: "You are invited to Harbor", Text: `You are invited to Harbor.

To accept the invitation, open this link:
https://harbor.test/login?invitation=tok_1

The link is good for 7 days.

Didn't expect this?
If you were not expecting an invitation, ignore this message. Nothing changes.

Keep the link to yourself
Anyone who opens the link can accept the invitation in your place. Don't forward it.
`},
		},
		{
			name: "an address confirmation takes for granted the person added the address",
			got:  m.verificationMessage("pat@lakeside.edu", "tok_2", 6*time.Hour),
			want: mail.Message{To: "pat@lakeside.edu", Subject: "Confirm your email address for Harbor", Text: `You added this address to your Harbor account.

To confirm it, open this link:
https://harbor.test/login?verify=tok_2

The link is good for 6 hours.

Didn't do this?
If you did not add this address, ignore this message. Nothing changes.
`},
		},
		{
			name: "an address another account holds: no link, the account that has it, and what to do if it was not them",
			got:  m.addressHeldMessage("pat@lakeside.edu"),
			want: mail.Message{To: "pat@lakeside.edu", Subject: "Your email address and Harbor", Text: `Someone tried to add this address to another Harbor account, but it already belongs to an account.

If that was you, sign in to the account that has it.

Didn't do this?
If you did not try to add this address, ignore this message. Nothing changes.
`},
		},
		{
			name: "a sign-up link: open it and choose a password, how long it is good for, then the two notices",
			got:  m.signUpMessage("new@lakeside.edu", "tok_3", 6*time.Hour),
			want: mail.Message{To: "new@lakeside.edu", Subject: "Finish creating your Harbor account", Text: `You asked to create a Harbor account with this address.

To finish, open this link and choose your password:
https://harbor.test/login?signUp=tok_3

The link is good for 6 hours.

Didn't do this?
If you did not ask for an account, ignore this message. Nothing changes.

Keep the link to yourself
Anyone who opens the link can create the account in your place. Don't forward it.
`},
		},
		{
			name: "an account that already exists: no link, sign in instead, and what to do if it was not them",
			got:  m.accountExistsMessage("pat@lakeside.edu"),
			want: mail.Message{To: "pat@lakeside.edu", Subject: "You already have a Harbor account", Text: `You asked to create a Harbor account with this address, but there is already an account for it.

Sign in to Harbor to use it. If you forgot how, ask your administrator.

Didn't do this?
If you did not ask for an account, ignore this message. Nothing changes.
`},
		},
	} {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			if diff := cmp.Diff(tt.want, tt.got); diff != "" {
				t.Errorf("message mismatch (-want +got):\n%s", diff)
			}
		})
	}
}

func TestGoodFor(t *testing.T) {
	t.Parallel()

	for _, tt := range []struct {
		d    time.Duration
		want string
	}{
		{d: 10 * time.Second, want: "1 minute"},
		{d: time.Minute, want: "1 minute"},
		{d: 15 * time.Minute, want: "15 minutes"},
		{d: 59*time.Minute + 20*time.Second, want: "59 minutes"},
		{d: 59*time.Minute + 40*time.Second, want: "59 minutes"},
		{d: time.Hour, want: "1 hour"},
		{d: 89 * time.Minute, want: "1 hour"},
		{d: 90 * time.Minute, want: "1 hour"},
		{d: 6 * time.Hour, want: "6 hours"},
		{d: 24 * time.Hour, want: "24 hours"},
		{d: 47 * time.Hour, want: "47 hours"},
		{d: 47*time.Hour + 40*time.Minute, want: "47 hours"},
		{d: 48 * time.Hour, want: "2 days"},
		{d: 7 * 24 * time.Hour, want: "7 days"},
		{d: 7*24*time.Hour + 11*time.Hour, want: "7 days"},
		{d: 7*24*time.Hour + 13*time.Hour, want: "7 days"},
	} {
		t.Run(tt.d.String()+" reads as "+tt.want, func(t *testing.T) {
			t.Parallel()
			if got := goodFor(tt.d); got != tt.want {
				t.Errorf("goodFor(%v) = %q, want %q", tt.d, got, tt.want)
			}
		})
	}
}

// decoded is the JSON object a response carries.
func decoded(t *testing.T, rr *httptest.ResponseRecorder) map[string]any {
	t.Helper()

	var body map[string]any
	if err := json.Unmarshal(rr.Body.Bytes(), &body); err != nil {
		t.Fatalf("json.Unmarshal(%s) error = %v", rr.Body.String(), err)
	}

	return body
}

// signedIn is a request of the session sessionID, carrying cookies, served by h
// straight: the handler validates the session itself, and the invitation cookie is
// read as StartSession reads it.
func (f *authFixture) asUser(h http.Handler, sessionID ccc.UUID, body any, cookies []*http.Cookie) *httptest.ResponseRecorder {
	payload := strings.NewReader("")
	if body != nil {
		raw, _ := json.Marshal(body)
		payload = strings.NewReader(string(raw))
	}
	r := httptest.NewRequestWithContext(context.WithValue(context.Background(), sessioninfo.CTXSessionID, sessionID), http.MethodPost, "/", payload)
	r.Header.Set("Content-Type", "application/json")
	for _, c := range cookies {
		r.AddCookie(c)
	}
	r = r.WithContext(f.auth.withInvitationCookie(r.Context(), r))
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, r)

	return rr
}

// expectSession makes sessionID a live session of user for the store.
func (f *authFixture) expectSession(sessionID ccc.UUID, user *sessionstorage.SessionUser) {
	session := &sessioninfo.SessionData{SessionInfo: &sessioninfo.SessionInfo{ID: sessionID, Username: user.Username, UpdatedAt: time.Now()}, UserID: ccc.NullUUIDFromUUID(user.ID)}
	f.store.EXPECT().Session(gomock.Any(), sessionID).Return(session, nil).AnyTimes()
	f.store.EXPECT().User(gomock.Any(), user.ID).Return(user, nil).AnyTimes()
}

func TestAuth_Invite(t *testing.T) {
	t.Parallel()

	t.Run("an invitation stores its row and mails a link to the login page that carries the token", authInviteCase1)
	t.Run("a message that cannot be sent withdraws the invitation", authInviteCase2)
	t.Run("an address that is not one, and an Auth without mail, are refused", authInviteCase3)
}

func authInviteCase1(t *testing.T) {
	t.Parallel()
	f, recorder, links := newMailFixture(t, gomock.NewController(t))
	inviter := ccc.Must(ccc.NewUUID())

	inv, err := f.auth.API().Invite(context.Background(), &InvitationRequest{Email: "Pat Lee <pat@lakeside.edu>", Tenant: "lakeside", RoleNames: []string{"Teacher"}, InvitedBy: ccc.NullUUIDFromUUID(inviter)})
	if err != nil {
		t.Fatalf("Invite() error = %v", err)
	}
	row := links.last(t)
	if row.Kind != sessionstorage.MailLinkInvitation || row.Email != "pat@lakeside.edu" || row.Tenant != "lakeside" || row.RoleNames[0] != "Teacher" || row.InvitedBy.UUID != inviter {
		t.Errorf("stored link = %+v, want the invitation as requested, the address bare", row)
	}
	if inv.ID != row.ID || inv.Email != row.Email || inv.Tenant != "lakeside" || !inv.ExpiresAt.After(time.Now().Add(6*24*time.Hour)) {
		t.Errorf("Invite() = %+v, want the stored invitation standing seven days", inv)
	}
	msgs := recorder.Messages()
	if len(msgs) != 1 || msgs[0].To != "pat@lakeside.edu" || msgs[0].Subject != "You are invited to Harbor" {
		t.Fatalf("messages = %+v, want one invitation to pat", msgs)
	}
	if hash, ok := linkTokenHash(tokenIn(t, msgs[0].Text, "invitation")); !ok || !bytes.Equal(hash, row.TokenHash) {
		t.Error("the mailed token does not hash to the stored row's token hash")
	}
	if live, err := f.auth.API().Invitations(context.Background()); err != nil || len(live) != 1 || live[0].ID != inv.ID {
		t.Errorf("Invitations() = %v, %v; want the one standing", live, err)
	}
	if err := f.auth.API().RevokeInvitation(context.Background(), inv.ID); err != nil {
		t.Fatalf("RevokeInvitation() error = %v", err)
	}
	if live, err := f.auth.API().Invitations(context.Background()); err != nil || len(live) != 0 {
		t.Errorf("Invitations() after the revocation = %v, %v; want none", live, err)
	}
}

func authInviteCase2(t *testing.T) {
	t.Parallel()
	f, recorder, links := newMailFixture(t, gomock.NewController(t))
	recorder.Err = errors.New("relay down")

	if _, err := f.auth.API().Invite(context.Background(), &InvitationRequest{Email: "pat@lakeside.edu"}); err == nil || !strings.Contains(err.Error(), "could not be sent") {
		t.Fatalf("Invite() error = %v, want the message not sent", err)
	}
	if row := links.last(t); row.ConsumedAt == nil {
		t.Error("the invitation stands after the send failed, want it withdrawn")
	}
}

func authInviteCase3(t *testing.T) {
	t.Parallel()
	f, _, _ := newMailFixture(t, gomock.NewController(t))
	if _, err := f.auth.API().Invite(context.Background(), &InvitationRequest{Email: "pat at lakeside"}); !httpio.HasBadRequest(err) {
		t.Errorf("Invite() of a bad address error = %v, want BadRequest", err)
	}
	plain := newAuthFixture(t, gomock.NewController(t))
	if _, err := plain.auth.API().Invite(context.Background(), &InvitationRequest{Email: "pat@lakeside.edu"}); err == nil || !strings.Contains(err.Error(), "WithMail") {
		t.Errorf("Invite() without mail error = %v, want the wiring named", err)
	}
}

// invitationCookies opens the invitation link.last for the browser and returns the
// cookies it set.
func invitationCookies(t *testing.T, f *authFixture, links *mailLinks, token string) []*http.Cookie {
	t.Helper()

	rr := f.serve(f.auth.Invitation().Open(), http.MethodPost, "/invitation", map[string]string{"token": token}, nil)
	if rr.Code != http.StatusOK {
		t.Fatalf("Open() = %d %s, want 200", rr.Code, rr.Body.String())
	}
	if cookieNamed(rr, defaultInvitationCookieName) == nil {
		t.Fatal("Open() set no invitation cookie")
	}
	_ = links

	return rr.Result().Cookies()
}

func TestAuth_Invitation(t *testing.T) {
	t.Parallel()

	t.Run("opening an invitation answers what it is and sets the cookie; a dead or foreign token is 404", authInvitationCase1)
	t.Run("a signed-in person accepts the invitation the browser carries, in the store's transaction with the hook, and the cookie goes", authInvitationCase2)
	t.Run("an invited person creates an account with a password: the address verified, the sign-in carrying the invitation", authInvitationCase3)
	t.Run("a sign-up from an invitation refuses a short password, a missing username and a missing invitation", authInvitationCase4)
	t.Run("where the username is the address, the sign-up takes the invitation's address as the username", authInvitationCase5)
}

func authInvitationCase1(t *testing.T) {
	t.Parallel()
	f, recorder, links := newMailFixture(t, gomock.NewController(t))
	if _, err := f.auth.API().Invite(context.Background(), &InvitationRequest{Email: "pat@lakeside.edu", Tenant: "lakeside", RoleNames: []string{"Teacher"}}); err != nil {
		t.Fatal(err)
	}
	token := tokenIn(t, recorder.Messages()[0].Text, "invitation")

	rr := f.serve(f.auth.Invitation().Open(), http.MethodPost, "/invitation", map[string]string{"token": token}, nil)
	body := decoded(t, rr)
	if rr.Code != http.StatusOK || body["email"] != "pat@lakeside.edu" || body["tenant"] != "lakeside" || body["signUp"] != true || body["usernameIsEmail"] != false {
		t.Errorf("Open() = %d %s, want the invitation with sign-up offered", rr.Code, rr.Body.String())
	}
	if c := cookieNamed(rr, defaultInvitationCookieName); c == nil || !c.HttpOnly || c.SameSite != http.SameSiteLaxMode || !c.Expires.After(time.Now().Add(6*24*time.Hour)) {
		t.Errorf("invitation cookie = %+v, want HttpOnly, Lax and persistent", c)
	}
	if rr := f.serve(f.auth.Invitation().Open(), http.MethodPost, "/invitation", map[string]string{"token": "not-a-token"}, nil); rr.Code != http.StatusNotFound {
		t.Errorf("Open() of a bad token = %d, want 404", rr.Code)
	}
	if err := f.auth.API().RevokeInvitation(context.Background(), links.rows[0].ID); err != nil {
		t.Fatal(err)
	}
	if rr := f.serve(f.auth.Invitation().Open(), http.MethodPost, "/invitation", map[string]string{"token": token}, nil); rr.Code != http.StatusNotFound {
		t.Errorf("Open() of a revoked invitation = %d, want 404", rr.Code)
	}
}

func authInvitationCase2(t *testing.T) {
	t.Parallel()
	userID, sessionID := newIDs()
	f, recorder, links := newMailFixture(t, gomock.NewController(t))
	f.expectSession(sessionID, &sessionstorage.SessionUser{ID: userID, Username: "pat"})
	hookCalls := 0
	f.auth.SetInvitationAccepted(func(_ context.Context, _ ccc.UUID, username string, _ *sessioninfo.Invitation) error {
		if username != "pat" {
			t.Errorf("hook given username %q, want pat", username)
		}
		hookCalls++

		return nil
	})
	if _, err := f.auth.API().Invite(context.Background(), &InvitationRequest{Email: "pat@lakeside.edu", RoleNames: []string{"Admin"}}); err != nil {
		t.Fatal(err)
	}
	cookies := invitationCookies(t, f, links, tokenIn(t, recorder.Messages()[0].Text, "invitation"))
	f.store.EXPECT().AcceptInvitation(gomock.Any(), userID, "pat", gomock.Any(), gomock.Any()).DoAndReturn(
		func(ctx context.Context, id ccc.UUID, username string, inv *sessioninfo.Invitation, accept signinflow.InvitationAcceptor) error {
			if inv.ID != links.rows[0].ID || inv.RoleNames[0] != "Admin" {
				t.Errorf("AcceptInvitation() given %+v, want the opened invitation", inv)
			}
			if accept == nil {
				t.Error("AcceptInvitation() given no hook, want the Auth's")
			} else if err := accept(ctx, id, username, inv); err != nil {
				t.Errorf("hook error = %v", err)
			}
			inv.Accepted = true

			return nil
		})

	rr := f.asUser(f.auth.Invitation().Accept(), sessionID, nil, cookies)
	if rr.Code != http.StatusOK || decoded(t, rr)["accepted"] != true || hookCalls != 1 {
		t.Errorf("Accept() = %d %s (hook calls %d), want accepted through the hook", rr.Code, rr.Body.String(), hookCalls)
	}
	if c := cookieNamed(rr, defaultInvitationCookieName); c == nil || c.Value != "" {
		t.Error("Accept() left the invitation cookie, want it deleted")
	}
	if rr := f.asUser(f.auth.Invitation().Accept(), sessionID, nil, nil); rr.Code != http.StatusNotFound {
		t.Errorf("Accept() without an invitation = %d, want 404", rr.Code)
	}
}

func authInvitationCase3(t *testing.T) {
	t.Parallel()
	userID, sessionID := newIDs()
	f, recorder, links := newMailFixture(t, gomock.NewController(t))
	if _, err := f.auth.API().Invite(context.Background(), &InvitationRequest{Email: "pat@lakeside.edu", Tenant: "lakeside"}); err != nil {
		t.Fatal(err)
	}
	cookies := invitationCookies(t, f, links, tokenIn(t, recorder.Messages()[0].Text, "invitation"))
	created := &sessionstorage.SessionUser{ID: userID, Username: "patl", Email: strPtr("pat@lakeside.edu")}
	f.store.EXPECT().CreateUser(gomock.Any(), gomock.Any(), nil).DoAndReturn(func(_ context.Context, u *sessionstorage.InsertSessionUser, _ any) (*sessionstorage.SessionUser, error) {
		if u.Username != "patl" || u.PasswordHash == nil || u.Email == nil || *u.Email != "pat@lakeside.edu" || !u.EmailVerified {
			t.Errorf("CreateUser() given %+v, want the chosen username, a hash and the invitation's address verified", u)
		}

		return created, nil
	})
	f.expectSignIn(sessionID, func(req *sessioninfo.NewSessionRequest) {
		if req.Invitation == nil || req.Invitation.ID != links.rows[0].ID || req.UserID != userID || req.Identity.Method != sessioninfo.MethodPassword {
			t.Errorf("SignIn() given %+v with invitation %+v, want the new user's password identity carrying the invitation", req, req.Invitation)
		}
		req.Invitation.Accepted = true
	}, nil)

	rr := f.serve(f.auth.Invitation().SignUp(), http.MethodPost, "/invitation/sign-up", map[string]string{"password": "correct horse", "username": "patl"}, cookies)
	if rr.Code != http.StatusOK || decoded(t, rr)["mfaIsRequired"] != false || cookieNamed(rr, internalcookie.AuthCookieName) == nil {
		t.Errorf("SignUp() = %d %s, want a session", rr.Code, rr.Body.String())
	}
	if c := cookieNamed(rr, defaultInvitationCookieName); c == nil || c.Value != "" {
		t.Error("SignUp() left the invitation cookie, want it deleted")
	}
}

func authInvitationCase4(t *testing.T) {
	t.Parallel()
	f, recorder, links := newMailFixture(t, gomock.NewController(t))
	if _, err := f.auth.API().Invite(context.Background(), &InvitationRequest{Email: "pat@lakeside.edu"}); err != nil {
		t.Fatal(err)
	}
	cookies := invitationCookies(t, f, links, tokenIn(t, recorder.Messages()[0].Text, "invitation"))
	for _, tt := range []struct {
		name    string
		body    map[string]string
		cookies []*http.Cookie
		want    int
	}{
		{name: "short password", body: map[string]string{"password": "short", "username": "patl"}, cookies: cookies, want: http.StatusBadRequest},
		{name: "no username", body: map[string]string{"password": "correct horse"}, cookies: cookies, want: http.StatusBadRequest},
		{name: "no invitation", body: map[string]string{"password": "correct horse", "username": "patl"}, want: http.StatusNotFound},
	} {
		if rr := f.serve(f.auth.Invitation().SignUp(), http.MethodPost, "/invitation/sign-up", tt.body, tt.cookies); rr.Code != tt.want {
			t.Errorf("SignUp() with %s = %d %s, want %d", tt.name, rr.Code, rr.Body.String(), tt.want)
		}
	}
}

func authInvitationCase5(t *testing.T) {
	t.Parallel()
	userID, sessionID := newIDs()
	f, recorder, links := newMailFixture(t, gomock.NewController(t), UsernameIsEmail())
	if _, err := f.auth.API().Invite(context.Background(), &InvitationRequest{Email: "pat@lakeside.edu"}); err != nil {
		t.Fatal(err)
	}
	cookies := invitationCookies(t, f, links, tokenIn(t, recorder.Messages()[0].Text, "invitation"))
	f.store.EXPECT().CreateUser(gomock.Any(), gomock.Any(), nil).DoAndReturn(func(_ context.Context, u *sessionstorage.InsertSessionUser, _ any) (*sessionstorage.SessionUser, error) {
		if u.Username != "pat@lakeside.edu" || !u.EmailVerified {
			t.Errorf("CreateUser() given %+v, want the address as the username, verified", u)
		}

		return &sessionstorage.SessionUser{ID: userID, Username: u.Username}, nil
	})
	f.expectSignIn(sessionID, nil, nil)

	if rr := f.serve(f.auth.Invitation().SignUp(), http.MethodPost, "/invitation/sign-up", map[string]string{"password": "correct horse"}, cookies); rr.Code != http.StatusOK {
		t.Errorf("SignUp() = %d %s, want 200", rr.Code, rr.Body.String())
	}
}

func TestAuth_Email(t *testing.T) {
	t.Parallel()

	t.Run("adding an address mails it a verification link, and following the link writes the address verified", authEmailCase1)
	t.Run("a link counts only for the account that asked", authEmailCase2)
	t.Run("an address another account holds is told so by mail, the screen says nothing; a mailbox is sent three links, then refused", authEmailCase3)
	t.Run("an operator's entry is written unverified; an Auth without mail has no email handlers", authEmailCase4)
	t.Run("where the username is the address, a verified new address renames the user and the rename hook moves what the application keys by it", authEmailCase5)
}

func authEmailCase1(t *testing.T) {
	t.Parallel()
	userID, sessionID := newIDs()
	f, recorder, links := newMailFixture(t, gomock.NewController(t))
	f.expectSession(sessionID, pat(userID))
	f.store.EXPECT().UserByEmail(gomock.Any(), "Pat@Lakeside.edu").Return(nil, httpio.NewNotFoundMessage("none"))

	rr := f.asUser(f.auth.Email().Add(), sessionID, map[string]string{"email": "Pat@Lakeside.edu"}, nil)
	if rr.Code != http.StatusOK {
		t.Fatalf("Add() = %d %s, want 200", rr.Code, rr.Body.String())
	}
	row := links.last(t)
	if row.Kind != sessionstorage.MailLinkVerification || row.UserID.UUID != userID || row.Email != "Pat@Lakeside.edu" {
		t.Errorf("stored link = %+v, want a verification of the address for pat", row)
	}
	msgs := recorder.Messages()
	if len(msgs) != 1 || msgs[0].Subject != "Confirm your email address for Harbor" || msgs[0].To != "Pat@Lakeside.edu" {
		t.Fatalf("messages = %+v, want the verification", msgs)
	}
	token := tokenIn(t, msgs[0].Text, "verify")

	f.store.EXPECT().VerifyUserEmail(gomock.Any(), userID, "Pat@Lakeside.edu").Return(nil)
	rr = f.asUser(f.auth.Email().Verify(), sessionID, map[string]string{"token": token}, nil)
	if rr.Code != http.StatusOK || decoded(t, rr)["email"] != "Pat@Lakeside.edu" {
		t.Errorf("Verify() = %d %s, want the address", rr.Code, rr.Body.String())
	}
	if rr := f.asUser(f.auth.Email().Verify(), sessionID, map[string]string{"token": token}, nil); rr.Code != http.StatusNotFound {
		t.Errorf("second Verify() = %d, want 404: the link was used", rr.Code)
	}
}

func authEmailCase2(t *testing.T) {
	t.Parallel()
	userID, sessionID := newIDs()
	f, _, links := newMailFixture(t, gomock.NewController(t))
	f.expectSession(sessionID, pat(userID))
	other := ccc.Must(ccc.NewUUID())
	token, hash, err := linkToken()
	if err != nil {
		t.Fatal(err)
	}
	links.insert(&sessionstorage.MailLink{TokenHash: hash, Kind: sessionstorage.MailLinkVerification, Email: "x@lakeside.edu", UserID: ccc.NullUUIDFromUUID(other), ExpiresAt: time.Now().Add(time.Hour)})

	if rr := f.asUser(f.auth.Email().Verify(), sessionID, map[string]string{"token": token}, nil); rr.Code != http.StatusNotFound {
		t.Errorf("Verify() of another account's link = %d, want 404", rr.Code)
	}
	if row := links.rows[0]; row.ConsumedAt != nil {
		t.Error("the other account's link was consumed, want it untouched")
	}
}

func authEmailCase3(t *testing.T) {
	t.Parallel()
	userID, sessionID := newIDs()
	f, recorder, links := newMailFixture(t, gomock.NewController(t))
	f.expectSession(sessionID, pat(userID))
	other := ccc.Must(ccc.NewUUID())
	f.store.EXPECT().UserByEmail(gomock.Any(), "taken@lakeside.edu").Return(&sessionstorage.SessionUser{ID: other, Username: "sam", Email: strPtr("taken@lakeside.edu")}, nil).AnyTimes()

	for i := range 3 {
		if rr := f.asUser(f.auth.Email().Add(), sessionID, map[string]string{"email": "taken@lakeside.edu"}, nil); rr.Code != http.StatusOK {
			t.Fatalf("Add() %d = %d %s, want 200", i+1, rr.Code, rr.Body.String())
		}
	}
	msgs := recorder.Messages()
	if len(msgs) != 3 || msgs[0].Subject != "Your email address and Harbor" || !strings.Contains(msgs[0].Text, "already belongs to an account") {
		t.Errorf("messages = %+v, want three notices to the holder", msgs)
	}
	if len(links.rows) != 0 {
		t.Error("a link was stored for an address another account holds, want none")
	}
	rr := f.asUser(f.auth.Email().Add(), sessionID, map[string]string{"email": "taken@lakeside.edu"}, nil)
	if rr.Code != http.StatusTooManyRequests || refusal(t, rr).Code != sessioninfo.RefusedTooManyAttempts {
		t.Errorf("fourth Add() = %d %s, want 429 too_many_attempts", rr.Code, rr.Body.String())
	}
	if rr := f.asUser(f.auth.Email().Add(), sessionID, map[string]string{"email": "not an address"}, nil); rr.Code != http.StatusBadRequest {
		t.Errorf("Add() of a bad address = %d, want 400", rr.Code)
	}
}

func authEmailCase5(t *testing.T) {
	t.Parallel()
	userID, sessionID := newIDs()
	f, recorder, _ := newMailFixture(t, gomock.NewController(t), UsernameIsEmail())
	f.expectSession(sessionID, &sessionstorage.SessionUser{ID: userID, Username: "pat@lakeside.edu"})
	f.store.EXPECT().UserByEmail(gomock.Any(), "pat.lee@lakeside.edu").Return(nil, httpio.NewNotFoundMessage("none"))
	var renamed []string
	f.auth.SetUserRenamed(func(_ context.Context, id ccc.UUID, from, to string) error {
		if id != userID {
			t.Errorf("rename hook given user %s, want %s", id, userID)
		}
		renamed = append(renamed, from+" -> "+to)

		return nil
	})

	if rr := f.asUser(f.auth.Email().Add(), sessionID, map[string]string{"email": "pat.lee@lakeside.edu"}, nil); rr.Code != http.StatusOK {
		t.Fatalf("Add() = %d %s, want 200", rr.Code, rr.Body.String())
	}
	token := tokenIn(t, recorder.Messages()[0].Text, "verify")
	f.store.EXPECT().VerifyUserEmail(gomock.Any(), userID, "pat.lee@lakeside.edu").Return(nil)
	if rr := f.asUser(f.auth.Email().Verify(), sessionID, map[string]string{"token": token}, nil); rr.Code != http.StatusOK {
		t.Fatalf("Verify() = %d %s, want 200", rr.Code, rr.Body.String())
	}
	if len(renamed) != 1 || renamed[0] != "pat@lakeside.edu -> pat.lee@lakeside.edu" {
		t.Errorf("rename hook calls = %v, want the one rename", renamed)
	}
}

func authEmailCase4(t *testing.T) {
	t.Parallel()
	userID, _ := newIDs()
	f, _, _ := newMailFixture(t, gomock.NewController(t))
	f.store.EXPECT().SetUserEmail(gomock.Any(), userID, gomock.Any()).DoAndReturn(func(_ context.Context, _ ccc.UUID, email *string) error {
		if email == nil || *email != "pat@lakeside.edu" {
			t.Errorf("SetUserEmail() given %v, want the bare address", email)
		}

		return nil
	})
	if err := f.auth.API().SetSessionUserEmail(context.Background(), userID, strPtr("Pat Lee <pat@lakeside.edu>")); err != nil {
		t.Errorf("SetSessionUserEmail() error = %v", err)
	}
	if err := f.auth.API().SetSessionUserEmail(context.Background(), userID, strPtr("nope")); !httpio.HasBadRequest(err) {
		t.Errorf("SetSessionUserEmail() of a bad address error = %v, want BadRequest", err)
	}
	plain := newAuthFixture(t, gomock.NewController(t))
	if recovered := registrationPanic(func() { plain.auth.Email() }); recovered == nil || !strings.Contains(fmt.Sprint(recovered), "WithMail") {
		t.Errorf("Email() without mail panicked with %v, want the wiring named", recovered)
	}
}

func TestAuth_SignUp(t *testing.T) {
	t.Parallel()

	t.Run("a sign-up mails a link, the link opens, and completing it creates the account with the address verified and signs in", authSignUpCase1)
	t.Run("an address an account holds is pointed at it by mail, and the screen says nothing", authSignUpCase2)
	t.Run("sign-up is not offered without OpenSignUp, and OpenSignUp needs mail", authSignUpCase3)
}

func authSignUpCase1(t *testing.T) {
	t.Parallel()
	userID, sessionID := newIDs()
	f, recorder, links := newMailFixture(t, gomock.NewController(t), OpenSignUp())
	f.store.EXPECT().UserByEmail(gomock.Any(), "new@lakeside.edu").Return(nil, httpio.NewNotFoundMessage("none"))

	if rr := f.serve(f.auth.SignUp().Start(), http.MethodPost, "/sign-up", map[string]string{"email": "new@lakeside.edu"}, nil); rr.Code != http.StatusOK {
		t.Fatalf("Start() = %d %s, want 200", rr.Code, rr.Body.String())
	}
	msgs := recorder.Messages()
	if len(msgs) != 1 || msgs[0].Subject != "Finish creating your Harbor account" {
		t.Fatalf("messages = %+v, want the sign-up link", msgs)
	}
	token := tokenIn(t, msgs[0].Text, "signUp")
	if row := links.last(t); row.Kind != sessionstorage.MailLinkSignUp || row.Email != "new@lakeside.edu" {
		t.Errorf("stored link = %+v, want a sign-up for the address", row)
	}

	rr := f.serve(f.auth.SignUp().Open(), http.MethodPost, "/sign-up/open", map[string]string{"token": token}, nil)
	if body := decoded(t, rr); rr.Code != http.StatusOK || body["email"] != "new@lakeside.edu" || body["usernameIsEmail"] != false {
		t.Errorf("Open() = %d %s, want the address and a chosen username", rr.Code, rr.Body.String())
	}

	f.store.EXPECT().CreateUser(gomock.Any(), gomock.Any(), nil).DoAndReturn(func(_ context.Context, u *sessionstorage.InsertSessionUser, _ any) (*sessionstorage.SessionUser, error) {
		if u.Username != "newbie" || u.PasswordHash == nil || u.Email == nil || *u.Email != "new@lakeside.edu" || !u.EmailVerified {
			t.Errorf("CreateUser() given %+v, want the chosen username, a hash and the address verified", u)
		}

		return &sessionstorage.SessionUser{ID: userID, Username: "newbie"}, nil
	})
	f.expectSignIn(sessionID, func(req *sessioninfo.NewSessionRequest) {
		if req.UserID != userID || req.Identity.Method != sessioninfo.MethodPassword || req.Invitation != nil {
			t.Errorf("SignIn() given %+v, want the new user's password identity", req)
		}
	}, nil)
	rr = f.serve(f.auth.SignUp().Complete(), http.MethodPost, "/sign-up/complete", map[string]string{"token": token, "password": "correct horse", "username": "newbie"}, nil)
	if rr.Code != http.StatusOK || cookieNamed(rr, internalcookie.AuthCookieName) == nil {
		t.Errorf("Complete() = %d %s, want a session", rr.Code, rr.Body.String())
	}
	if links.last(t).ConsumedAt == nil {
		t.Error("the sign-up link stands after the completion, want it consumed")
	}
}

func authSignUpCase2(t *testing.T) {
	t.Parallel()
	userID, _ := newIDs()
	f, recorder, links := newMailFixture(t, gomock.NewController(t), OpenSignUp())
	f.store.EXPECT().UserByEmail(gomock.Any(), "pat@lakeside.edu").Return(&sessionstorage.SessionUser{ID: userID, Username: "pat"}, nil)

	if rr := f.serve(f.auth.SignUp().Start(), http.MethodPost, "/sign-up", map[string]string{"email": "pat@lakeside.edu"}, nil); rr.Code != http.StatusOK || rr.Body.String() != "{}\n" {
		t.Errorf("Start() = %d %s, want 200 and nothing said", rr.Code, rr.Body.String())
	}
	if msgs := recorder.Messages(); len(msgs) != 1 || msgs[0].Subject != "You already have a Harbor account" {
		t.Errorf("messages = %+v, want the notice", msgs)
	}
	if len(links.rows) != 0 {
		t.Error("a link was stored for a held address, want none")
	}
}

func authSignUpCase3(t *testing.T) {
	t.Parallel()
	f, _, _ := newMailFixture(t, gomock.NewController(t))
	if rr := f.serve(f.auth.SignUp().Start(), http.MethodPost, "/sign-up", map[string]string{"email": "new@lakeside.edu"}, nil); rr.Code != http.StatusNotFound {
		t.Errorf("Start() without OpenSignUp = %d, want 404", rr.Code)
	}
	if rr := f.serve(f.auth.SignUp().Complete(), http.MethodPost, "/sign-up/complete", map[string]string{"token": "x", "password": "correct horse"}, nil); rr.Code != http.StatusNotFound {
		t.Errorf("Complete() without OpenSignUp = %d, want 404", rr.Code)
	}
	a := newBareAuth(t, gomock.NewController(t))
	if recovered := registrationPanic(func() { PasswordSignIn(a, OpenSignUp()) }); recovered == nil || !strings.Contains(fmt.Sprint(recovered), "WithMail") {
		t.Errorf("PasswordSignIn(OpenSignUp()) without mail panicked with %v, want the wiring named", recovered)
	}
}

func TestNewAuth_Mail(t *testing.T) {
	t.Parallel()

	for _, tt := range []struct {
		name     string
		sender   mail.Sender
		settings MailSettings
		want     string
	}{
		{name: "no sender", settings: testMail, want: "sender is nil"},
		{name: "no application name", sender: &mail.Recorder{}, settings: MailSettings{LoginURL: "https://harbor.test/login"}, want: "application name is empty"},
		{name: "a relative login URL", sender: &mail.Recorder{}, settings: MailSettings{Application: "Harbor", LoginURL: "/login"}, want: "not an absolute"},
		{name: "a login URL with a fragment", sender: &mail.Recorder{}, settings: MailSettings{Application: "Harbor", LoginURL: "https://harbor.test/#/login"}, want: "not an absolute"},
	} {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			_, err := NewAuth[NoCustomData, NoCustomData](newAuthStoreMock(gomock.NewController(t)), cookieKey, WithMail(tt.sender, tt.settings))
			if err == nil || !strings.Contains(err.Error(), tt.want) {
				t.Errorf("NewAuth() error = %v, want %q", err, tt.want)
			}
		})
	}

	t.Run("the invitation cookie must differ from the session and pending cookies", func(t *testing.T) {
		t.Parallel()
		if _, err := NewAuth[NoCustomData, NoCustomData](newAuthStoreMock(gomock.NewController(t)), cookieKey, WithInvitationCookieName(defaultPendingCookieName)); err == nil {
			t.Error("NewAuth() with the pending cookie's name for the invitation cookie error = nil, want a refusal")
		}
	})
}

func TestAuth_ClaimVerifiedEmail(t *testing.T) {
	t.Parallel()

	userID := ccc.Must(ccc.NewUUID())
	for _, tt := range []struct {
		name     string
		identity *sessioninfo.Identity
		claims   int
	}{
		{name: "a method that verified the address writes it", identity: &sessioninfo.Identity{Method: sessioninfo.MethodGoogle, Email: "pat@lakeside.edu", EmailVerified: true}, claims: 1},
		{name: "an address the method did not verify is not written", identity: &sessioninfo.Identity{Method: sessioninfo.MethodAzure, Email: "pat@lakeside.edu"}},
		{name: "no address, nothing", identity: &sessioninfo.Identity{Method: sessioninfo.MethodPassword}},
	} {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			ctrl := gomock.NewController(t)
			store := mock_sessionstorage.NewMockAuthStore[mockTx](ctrl)
			store.EXPECT().CustomUserDataType().Return(nil).AnyTimes()
			store.EXPECT().UserDataLoginHookConfigured().Return(false).AnyTimes()
			store.EXPECT().OIDCUsersEnabled().Return(false).AnyTimes()
			store.EXPECT().ClaimVerifiedEmail(gomock.Any(), userID, "pat@lakeside.edu").Return(true, nil).Times(tt.claims)
			a, err := NewAuth[NoCustomData, NoCustomData](store, cookieKey)
			if err != nil {
				t.Fatal(err)
			}

			a.claimVerifiedEmail(context.Background(), userID, tt.identity)
		})
	}
}

func strPtr(s string) *string { return &s }

// newIDs gives a case its own user and session ids.
func newIDs() (userID, sessionID ccc.UUID) {
	return ccc.Must(ccc.NewUUID()), ccc.Must(ccc.NewUUID())
}

// pat is the signed-in user of the email cases.
func pat(userID ccc.UUID) *sessionstorage.SessionUser {
	return &sessionstorage.SessionUser{ID: userID, Username: "pat"}
}
