package e2e

import (
	"context"
	"encoding/json"
	"net/http"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/cccteam/ccc"
	"github.com/cccteam/session"
	"github.com/cccteam/session/sessioninfo"
	"github.com/cccteam/session/signin"
)

// The second factor the library runs, through the real handlers on both backends: the
// code mailed to the user's address, the browser remembered after it, the
// administrator's reset, the enrollment of an address at the step, and the limits.

// codePattern finds the spaced code in a code message's subject.
var codePattern = regexp.MustCompile(`\b(\d{3}) (\d{3})\b`)

// lastCode is the code of the last message the app sent, which must be a code message
// to address.
func (a *authApp[Tx]) lastCode(t *testing.T, to string) string {
	t.Helper()

	sent := a.mail.Messages()
	if len(sent) == 0 {
		t.Fatal("no mail was sent, want the code message")
	}
	last := sent[len(sent)-1]
	m := codePattern.FindStringSubmatch(last.Subject)
	if last.To != to || m == nil || !strings.Contains(last.Text, m[0]) {
		t.Fatalf("the last message = %+v, want a code message to %s with the code in its subject and text", last, to)
	}

	return m[1] + m[2]
}

// pendingStatus is the pending status as the page reads it.
type pendingStatus struct {
	Reason    string   `json:"reason"`
	Factors   []string `json:"factors"`
	EmailCode *struct {
		CodeEmail     string     `json:"codeEmail"`
		EnrollEmail   bool       `json:"enrollEmail"`
		CodeSent      bool       `json:"codeSent"`
		CodeExpiresAt *time.Time `json:"codeExpiresAt"`
	} `json:"emailCode"`
}

func (b *browser) pendingStatus(ctx context.Context) *pendingStatus {
	b.t.Helper()

	status := &pendingStatus{}
	if err := json.Unmarshal(b.expect(ctx, http.StatusOK, http.MethodGet, "/pending", nil), status); err != nil {
		b.t.Fatalf("json.Unmarshal() error = %v", err)
	}

	return status
}

// authenticatedEmail reads the session read's address and whether it is verified.
func (b *browser) authenticatedEmail(ctx context.Context) (email string, verified bool) {
	b.t.Helper()

	var body struct {
		Email         *string `json:"email"`
		EmailVerified bool    `json:"emailVerified"`
	}
	if err := json.Unmarshal(b.expect(ctx, http.StatusOK, http.MethodGet, "/authenticated", nil), &body); err != nil {
		b.t.Fatalf("json.Unmarshal() error = %v", err)
	}
	if body.Email == nil {
		return "", false
	}

	return *body.Email, body.EmailVerified
}

// seedWithEmail creates a user with seedPassword and email, unverified, as an operator
// enters it.
func (a *authApp[Tx]) seedWithEmail(ctx context.Context, t *testing.T, username, email string) ccc.UUID {
	t.Helper()

	pw := seedPassword
	id, err := a.api.CreateSessionUser(ctx, &session.CreateUserRequest{Username: username, Password: &pw, Email: &email})
	if err != nil {
		t.Fatalf("CreateSessionUser(%q) error = %v", username, err)
	}

	return id
}

// requireEmailCode is the policy of an application whose every session carries a
// second factor: the library's email code, which an attestation or a trusted device
// stands in for.
func requireEmailCode(*sessioninfo.NewSessionRequest) *signin.Decision {
	return signin.RequireMFA(sessioninfo.MethodEmailCode)
}

func seamEmailCode[Tx any](ctx context.Context, t *testing.T, a *authApp[Tx], _ *fakeWorkOS) {
	t.Helper()

	pat := a.seedWithEmail(ctx, t, "pat@lakeside.edu", "pat@lakeside.edu")
	a.hooks.set(func(h *hooks[Tx]) { h.policy = requireEmailCode })

	b := a.browser(t)
	b.prime(ctx)
	anonymous := b.sessionID(ctx)
	if status, mfa := b.passwordLogin(ctx, seedPassword); status != http.StatusOK || !mfa {
		t.Fatalf("password login = %d (mfaIsRequired %v), want 200 requiring MFA", status, mfa)
	}
	b.expect(ctx, http.StatusUnauthorized, http.MethodGet, "/whoami", nil)

	// The status says where the code goes, masked, and that none stands yet.
	status := b.pendingStatus(ctx)
	if status.Reason != "mfa" || len(status.Factors) != 1 || status.Factors[0] != "email-code" || status.EmailCode == nil ||
		status.EmailCode.CodeSent || status.EmailCode.EnrollEmail || status.EmailCode.CodeEmail != "p•••@lakeside.edu" {
		t.Fatalf("pending status = %+v (emailCode %+v), want an MFA wait taking the email code at p•••@lakeside.edu, none sent", status, status.EmailCode)
	}
	// A code entered before one was sent: none stands, so the page asks for one.
	if status, body := b.do(ctx, http.MethodPost, "/pending/code/verify", map[string]any{"code": "000000"}); status != http.StatusUnauthorized || !strings.Contains(string(body), `"code":"code_expired"`) {
		t.Errorf("verify before a code was sent = %d %s, want 401 code_expired", status, body)
	}

	b.expect(ctx, http.StatusOK, http.MethodPost, "/pending/code/send", nil)
	code := a.lastCode(t, "pat@lakeside.edu")
	status = b.pendingStatus(ctx)
	if status.EmailCode == nil || !status.EmailCode.CodeSent || status.EmailCode.CodeExpiresAt == nil || status.EmailCode.CodeEmail != "p•••@lakeside.edu" {
		t.Errorf("pending status after the send = %+v, want the code standing at p•••@lakeside.edu", status.EmailCode)
	}

	// A wrong code counts and leaves the code standing.
	wrong := "000000"
	if wrong == code {
		wrong = "111111"
	}
	if status, body := b.do(ctx, http.MethodPost, "/pending/code/verify", map[string]any{"code": wrong}); status != http.StatusUnauthorized || !strings.Contains(string(body), `"code":"invalid_code"`) {
		t.Errorf("a wrong code = %d %s, want 401 invalid_code", status, body)
	}
	replay := b.clone()

	// The right code, spaced as the mail shows it, completes the sign-in and
	// remembers the browser.
	spaced := code[:3] + " " + code[3:]
	if body := b.expect(ctx, http.StatusOK, http.MethodPost, "/pending/code/verify", map[string]any{"code": spaced, "rememberDevice": true}); !strings.Contains(string(body), `"mfaIsRequired":false`) {
		t.Fatalf("verify = %s, want mfaIsRequired false", body)
	}
	v := b.view(ctx)
	if v.UserID != pat.String() || v.SessionID == anonymous {
		t.Errorf("session = %+v, want user %s under a session ID other than %s", v, pat, anonymous)
	}
	assertEventsSeen(t, v, "password", "email-code")
	// The code proved the address an operator entered: it is verified now.
	if email, verified := b.authenticatedEmail(ctx); email != "pat@lakeside.edu" || !verified {
		t.Errorf("the session read = email %q verified %v, want pat@lakeside.edu verified by the code", email, verified)
	}

	// The pending identity and the code were consumed: a copy of the cookies
	// completes nothing.
	replay.expect(ctx, http.StatusUnauthorized, http.MethodGet, "/pending", nil)
	replay.expect(ctx, http.StatusUnauthorized, http.MethodPost, "/pending/code/verify", map[string]any{"code": code})
	replay.expect(ctx, http.StatusUnauthorized, http.MethodGet, "/whoami", nil)

	seamEmailCodeTrustedDevice(ctx, t, a, b, pat)
}

// seamEmailCodeTrustedDevice is the rest of seamEmailCode: b was remembered when pat
// entered the code.
func seamEmailCodeTrustedDevice[Tx any](ctx context.Context, t *testing.T, a *authApp[Tx], b *browser, pat ccc.UUID) {
	t.Helper()

	// The remembered browser signs in without the factor: the trusted device stands
	// in for it, and the session says so.
	b.expect(ctx, http.StatusOK, http.MethodPost, "/logout", nil)
	b.prime(ctx)
	if status, mfa := b.passwordLogin(ctx, seedPassword); status != http.StatusOK || mfa {
		t.Fatalf("password login from the remembered browser = %d (mfaIsRequired %v), want 200 with no MFA", status, mfa)
	}
	assertEventsSeen(t, b.view(ctx), "password", "trusted-device")

	// Another browser is not remembered.
	other := a.browser(t)
	other.prime(ctx)
	if status, mfa := other.passwordLogin(ctx, seedPassword); status != http.StatusOK || !mfa {
		t.Errorf("password login from another browser = %d (mfaIsRequired %v), want 200 requiring MFA", status, mfa)
	}

	// The administrator's reset forgets the remembered browser: its next sign-in
	// asks for the factor again.
	if err := a.api.ResetFactors(ctx, pat); err != nil {
		t.Fatalf("ResetFactors() error = %v", err)
	}
	b.expect(ctx, http.StatusOK, http.MethodPost, "/logout", nil)
	b.prime(ctx)
	if status, mfa := b.passwordLogin(ctx, seedPassword); status != http.StatusOK || !mfa {
		t.Errorf("password login after the reset = %d (mfaIsRequired %v), want 200 requiring MFA", status, mfa)
	}
	sent := len(a.mail.Messages())
	b.expect(ctx, http.StatusOK, http.MethodPost, "/pending/code/send", nil)
	if got := len(a.mail.Messages()); got != sent+1 {
		t.Errorf("messages sent after the second code = %d, want %d", got, sent+1)
	}
	b.expect(ctx, http.StatusOK, http.MethodPost, "/pending/code/verify", map[string]any{"code": a.lastCode(t, "pat@lakeside.edu")})
	assertEventsSeen(t, b.view(ctx), "password", "email-code")
}

func seamEmailCodeEnrollment[Tx any](ctx context.Context, t *testing.T, a *authApp[Tx], _ *fakeWorkOS) {
	t.Helper()

	// kim holds the address the enrolling person will try first: it is told by mail,
	// and the screen says nothing.
	a.seedWithEmail(ctx, t, "kim", "kim@lakeside.edu")
	pat := a.seed(ctx, t, "pat")
	a.hooks.set(func(h *hooks[Tx]) { h.policy = requireEmailCode })

	b := a.browser(t)
	b.prime(ctx)
	b.expect(ctx, http.StatusOK, http.MethodPost, "/login", map[string]string{"username": "pat", "password": seedPassword})
	status := b.pendingStatus(ctx)
	if status.EmailCode == nil || !status.EmailCode.EnrollEmail || status.EmailCode.CodeEmail != "" {
		t.Fatalf("pending status = %+v, want the step asking for an address", status.EmailCode)
	}
	if status, body := b.do(ctx, http.MethodPost, "/pending/code/send", nil); status != http.StatusConflict {
		t.Errorf("send for a user without an address = %d %s, want 409", status, body)
	}
	if status, body := b.do(ctx, http.MethodPost, "/pending/email", map[string]string{"email": "not an address"}); status != http.StatusBadRequest {
		t.Errorf("enroll with no address = %d %s, want 400", status, body)
	}

	// Someone else's address: answered as sent, the holder told, no code.
	b.expect(ctx, http.StatusOK, http.MethodPost, "/pending/email", map[string]string{"email": "KIM@lakeside.edu"})
	sent := a.mail.Messages()
	if last := sent[len(sent)-1]; last.To != "KIM@lakeside.edu" || !strings.Contains(last.Subject, "Your email address and") {
		t.Errorf("the last message = %+v, want the address-held notice to the holder", last)
	}
	if status, body := b.do(ctx, http.MethodPost, "/pending/code/verify", map[string]any{"code": "123456"}); status != http.StatusUnauthorized || !strings.Contains(string(body), `"code":"code_expired"`) {
		t.Errorf("verify after an enrollment of a held address = %d %s, want 401 code_expired: no code was sent", status, body)
	}

	// Their own: the code goes there, and the address is theirs once entered.
	b.expect(ctx, http.StatusOK, http.MethodPost, "/pending/email", map[string]string{"email": "pat@lakeside.edu"})
	code := a.lastCode(t, "pat@lakeside.edu")
	if status := b.pendingStatus(ctx); status.EmailCode == nil || !status.EmailCode.CodeSent || status.EmailCode.CodeEmail != "p•••@lakeside.edu" || status.EmailCode.EnrollEmail {
		t.Errorf("pending status after the enrollment = %+v, want the code standing at p•••@lakeside.edu", status.EmailCode)
	}
	b.expect(ctx, http.StatusOK, http.MethodPost, "/pending/code/verify", map[string]any{"code": code})
	v := b.view(ctx)
	if v.UserID != pat.String() {
		t.Errorf("session user = %s, want %s", v.UserID, pat)
	}
	assertEventsSeen(t, v, "password", "email-code")
	if email, verified := b.authenticatedEmail(ctx); email != "pat@lakeside.edu" || !verified {
		t.Errorf("the session read = email %q verified %v, want pat@lakeside.edu verified by the code", email, verified)
	}

	// The next sign-in finds the address on the user: no enrollment, the code goes
	// there.
	b.expect(ctx, http.StatusOK, http.MethodPost, "/logout", nil)
	b.prime(ctx)
	b.expect(ctx, http.StatusOK, http.MethodPost, "/login", map[string]string{"username": "pat", "password": seedPassword})
	if status := b.pendingStatus(ctx); status.EmailCode == nil || status.EmailCode.EnrollEmail || status.EmailCode.CodeEmail != "p•••@lakeside.edu" {
		t.Errorf("pending status at the next sign-in = %+v, want the code going to p•••@lakeside.edu", status.EmailCode)
	}
	if status, body := b.do(ctx, http.MethodPost, "/pending/email", map[string]string{"email": "other@lakeside.edu"}); status != http.StatusConflict {
		t.Errorf("enroll for a user holding an address = %d %s, want 409", status, body)
	}
}

func seamEmailCodeLimits[Tx any](ctx context.Context, t *testing.T, a *authApp[Tx], _ *fakeWorkOS) {
	t.Helper()

	a.seedWithEmail(ctx, t, "pat@lakeside.edu", "pat@lakeside.edu")
	a.hooks.set(func(h *hooks[Tx]) { h.policy = requireEmailCode })

	b := a.browser(t)
	b.prime(ctx)
	b.expect(ctx, http.StatusOK, http.MethodPost, "/login", map[string]string{"username": "pat@lakeside.edu", "password": seedPassword})
	b.expect(ctx, http.StatusOK, http.MethodPost, "/pending/code/send", nil)
	code := a.lastCode(t, "pat@lakeside.edu")
	wrong := "000000"
	if wrong == code {
		wrong = "111111"
	}
	for i := 1; i <= 4; i++ {
		if status, body := b.do(ctx, http.MethodPost, "/pending/code/verify", map[string]any{"code": wrong}); status != http.StatusUnauthorized || !strings.Contains(string(body), `"code":"invalid_code"`) {
			t.Fatalf("wrong code #%d = %d %s, want 401 invalid_code", i, status, body)
		}
	}
	// The fifth wrong code kills the code: the right one is dead too.
	if status, body := b.do(ctx, http.MethodPost, "/pending/code/verify", map[string]any{"code": wrong}); status != http.StatusUnauthorized || !strings.Contains(string(body), `"code":"code_expired"`) {
		t.Errorf("the fifth wrong code = %d %s, want 401 code_expired", status, body)
	}
	if status, body := b.do(ctx, http.MethodPost, "/pending/code/verify", map[string]any{"code": code}); status != http.StatusUnauthorized || !strings.Contains(string(body), `"code":"code_expired"`) {
		t.Errorf("the right code after five wrong ones = %d %s, want 401 code_expired", status, body)
	}
	if status := b.pendingStatus(ctx); status.EmailCode == nil || status.EmailCode.CodeSent {
		t.Errorf("pending status after the code died = %+v, want none standing", status.EmailCode)
	}

	// A new code replaces it, and the old one is dead with it.
	b.expect(ctx, http.StatusOK, http.MethodPost, "/pending/code/send", nil)
	fresh := a.lastCode(t, "pat@lakeside.edu")
	b.expect(ctx, http.StatusOK, http.MethodPost, "/pending/code/send", nil)
	freshest := a.lastCode(t, "pat@lakeside.edu")
	if fresh != freshest {
		if status, body := b.do(ctx, http.MethodPost, "/pending/code/verify", map[string]any{"code": fresh}); status != http.StatusUnauthorized {
			t.Errorf("the code a newer one replaced = %d %s, want 401", status, body)
		}
	}
	// The fourth send within the window is the address's limit.
	if status, body := b.do(ctx, http.MethodPost, "/pending/code/send", nil); status != http.StatusTooManyRequests || !strings.Contains(string(body), "too_many_attempts") {
		t.Errorf("the fourth code within fifteen minutes = %d %s, want 429 too_many_attempts", status, body)
	}
	b.expect(ctx, http.StatusOK, http.MethodPost, "/pending/code/verify", map[string]any{"code": freshest})
	assertEventsSeen(t, b.view(ctx), "password", "email-code")

	// A policy that accepts the application's own factor only offers no code: the
	// handlers refuse, and the status says nothing of it.
	a.hooks.set(func(h *hooks[Tx]) {
		h.policy = func(*sessioninfo.NewSessionRequest) *signin.Decision { return signin.RequireMFA("totp") }
	})
	other := a.browser(t)
	other.prime(ctx)
	other.expect(ctx, http.StatusOK, http.MethodPost, "/login", map[string]string{"username": "pat@lakeside.edu", "password": seedPassword})
	if status := other.pendingStatus(ctx); status.EmailCode != nil || len(status.Factors) != 1 || status.Factors[0] != "totp" {
		t.Errorf("pending status under a totp-only policy = %+v, want the factor and no email code", status)
	}
	if status, body := other.do(ctx, http.MethodPost, "/pending/code/send", nil); status != http.StatusConflict {
		t.Errorf("send under a totp-only policy = %d %s, want 409", status, body)
	}
}
