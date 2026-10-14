package e2e

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"slices"
	"strings"
	"sync"
	"testing"

	"github.com/cccteam/ccc"
	"github.com/cccteam/ccc/accesstypes"
	"github.com/cccteam/httpio"
	"github.com/cccteam/session"
	"github.com/cccteam/session/azure"
	"github.com/cccteam/session/google"
	"github.com/cccteam/session/sessioninfo"
	"github.com/cccteam/session/sessionstorage"
	"github.com/cccteam/session/signin"
	"github.com/cccteam/session/workos"
	"github.com/go-chi/chi/v5"
)

// The password every seeded user has.
const seedPassword = "correct horse battery staple"

// The WorkOS client the fake accepts, and the connection its sign-ins come through.
const (
	workosClientID     = "client_test"
	lakesideConnection = "conn_lakeside"
)

// hooks are an Auth app's user resolvers, sign-in policy, IdentityLinked hook and
// PendingHook, set per scenario. The resolvers and the policy run inside the sign-in's
// transactions, typed to the backend's transaction; resolveTx and policyTx, when set,
// receive it to write and read the application's own rows.
type hooks[Tx any] struct {
	mu sync.Mutex
	// rows reaches the application's own tables in a sign-in's transaction.
	rows appRows[Tx]
	// resolve decides a WorkOS identity that is not linked yet; resolveTx the same,
	// with the sign-in's transaction. Unset, every unlinked identity is rejected.
	resolve   func(identity *workos.Identity) *signin.Resolution
	resolveTx func(ctx context.Context, tx Tx, identity *workos.Identity) (*signin.Resolution, error)
	// resolveAzure and resolveGoogle decide those methods' unlinked identities.
	resolveAzure  func(identity *azure.Identity) *signin.Resolution
	resolveGoogle func(identity *google.Identity) *signin.Resolution
	// policy decides every sign-in; policyTx the same, with the sign-in's transaction.
	// Unset, every sign-in is allowed.
	policy   func(req *sessioninfo.NewSessionRequest) *signin.Decision
	policyTx func(ctx context.Context, tx Tx, req *sessioninfo.NewSessionRequest) (*signin.Decision, error)
	// pendingURL is where the PendingHook sends a pending sign-in; "" keeps the default.
	pendingURL string
	resolved   int
	linked     []ccc.UUID
	pendings   []*sessioninfo.PendingIdentity
}

func (h *hooks[Tx]) workOSResolver(ctx context.Context, tx Tx, identity *workos.Identity) (*signin.Resolution, error) {
	h.mu.Lock()
	defer h.mu.Unlock()

	h.resolved++
	switch {
	case h.resolveTx != nil:
		return h.resolveTx(ctx, tx, identity)
	case h.resolve == nil:
		return signin.Reject(""), nil
	}

	return h.resolve(identity), nil
}

func (h *hooks[Tx]) azureResolver(_ context.Context, _ Tx, identity *azure.Identity) (*signin.Resolution, error) {
	h.mu.Lock()
	defer h.mu.Unlock()

	h.resolved++
	if h.resolveAzure == nil {
		return signin.Reject(""), nil
	}

	return h.resolveAzure(identity), nil
}

func (h *hooks[Tx]) googleResolver(_ context.Context, _ Tx, identity *google.Identity) (*signin.Resolution, error) {
	h.mu.Lock()
	defer h.mu.Unlock()

	h.resolved++
	if h.resolveGoogle == nil {
		return signin.Reject(""), nil
	}

	return h.resolveGoogle(identity), nil
}

func (h *hooks[Tx]) signInPolicy(ctx context.Context, tx Tx, req *sessioninfo.NewSessionRequest) (*signin.Decision, error) {
	h.mu.Lock()
	defer h.mu.Unlock()

	switch {
	case h.policyTx != nil:
		return h.policyTx(ctx, tx, req)
	case h.policy == nil:
		return signin.Allow(), nil
	}

	return h.policy(req), nil
}

// sessionData resolves a new session's custom data in the transaction that inserts the
// session: the partner its user is a member of, "" when none.
func (h *hooks[Tx]) sessionData(ctx context.Context, tx Tx, req *sessioninfo.NewSessionRequest) (*appSessionData, error) {
	partner, _, err := h.rows.partnerOf(ctx, tx, req.UserID)
	if err != nil {
		return nil, err
	}

	return &appSessionData{Partner: partner}, nil
}

func (h *hooks[Tx]) pendingHook(_ context.Context, _ http.ResponseWriter, _ *http.Request, pending *sessioninfo.PendingIdentity) (string, error) {
	h.mu.Lock()
	defer h.mu.Unlock()

	h.pendings = append(h.pendings, pending)

	return h.pendingURL, nil
}

func (h *hooks[Tx]) identityLinked(_ context.Context, userID ccc.UUID, _ *sessioninfo.Identity) error {
	h.mu.Lock()
	defer h.mu.Unlock()

	h.linked = append(h.linked, userID)

	return nil
}

func (h *hooks[Tx]) set(fn func(h *hooks[Tx])) {
	h.mu.Lock()
	defer h.mu.Unlock()

	fn(h)
}

func (h *hooks[Tx]) counts() (resolved int, linked []ccc.UUID) {
	h.mu.Lock()
	defer h.mu.Unlock()

	return h.resolved, append([]ccc.UUID(nil), h.linked...)
}

// appSessionData is the application's custom session data: the partner the session's
// user is a member of, resolved in the sign-in's transaction. One struct serves both
// backends through its tags.
type appSessionData struct {
	Partner string `db:"Partner" spanner:"Partner"`
}

// appUserData is the application's custom user data, written with the user.
type appUserData struct {
	Locale string `db:"Locale" spanner:"Locale"`
}

// authApp is an application on one Auth session over a backend with the users, auth
// events, impersonation and custom data schema.
type authApp[Tx any] struct {
	db     appDB
	rows   appRows[Tx]
	server *httptest.Server
	api    *session.AuthAPI[appSessionData, appUserData, Tx]
	hooks  *hooks[Tx]
}

// withCustomData attaches the application's custom session and user data to store
// through the store's one configuration of each, typed to its transaction, the way an
// application does.
func withCustomData[Tx any](t *testing.T, store *sessionstorage.Auth[Tx], h *hooks[Tx]) *sessionstorage.Auth[Tx] {
	t.Helper()

	sessionData, err := sessionstorage.NewCustomSessionData("SessionCustomData", h.sessionData)
	if err != nil {
		t.Fatalf("sessionstorage.NewCustomSessionData() error = %v", err)
	}
	userData, err := sessionstorage.NewCustomUserData[appUserData]("UserCustomData")
	if err != nil {
		t.Fatalf("sessionstorage.NewCustomUserData() error = %v", err)
	}

	return store.WithCustomSessionData(sessionData).WithCustomUserData(userData)
}

// mountAuth mounts auth's shared routes, the way the README prescribes, plus the
// application's own MFA step, a /whoami that reports the validated session and a
// /session-data that reports its custom data.
func mountAuth[Tx any](r chi.Router, auth *session.Auth[appSessionData, appUserData, Tx], routes func(r chi.Router)) {
	api := auth.API()

	r.Use(auth.StartSession, auth.SetXSRFToken)
	r.Get("/authenticated", auth.Authenticated())
	r.Get("/sid", func(w http.ResponseWriter, r *http.Request) {
		_ = httpio.NewEncoder(w).Ok(map[string]string{"sessionId": sessioninfo.IDFromRequest(r).String()})
	})
	r.Get("/pending", auth.Pending().Status())
	routes(r)

	r.Group(func(r chi.Router) {
		r.Use(auth.ValidateXSRFToken)
		r.Post("/pending/confirm", auth.Pending().ConfirmWithPassword())
		r.Post("/pending/cancel", auth.Pending().Cancel())
		// The application's MFA step: here it accepts anything, which is what the
		// scenarios need; a real one checks a code first.
		r.Post("/mfa", func(w http.ResponseWriter, r *http.Request) {
			if _, err := api.CompletePending(r.Context(), w, sessioninfo.AuthEvent{Method: "email-otp"}); err != nil {
				_ = httpio.NewEncoder(w).ClientMessage(r.Context(), err)

				return
			}
			w.WriteHeader(http.StatusNoContent)
		})

		r.Group(func(r chi.Router) {
			r.Use(auth.ValidateSession)
			r.Get("/whoami", whoami)
			r.Get("/session-data", func(w http.ResponseWriter, r *http.Request) {
				data, err := api.CustomData(r.Context())
				if err != nil {
					_ = httpio.NewEncoder(w).ClientMessage(r.Context(), err)

					return
				}
				_ = httpio.NewEncoder(w).Ok(data)
			})
			r.Post("/logout", auth.Logout())
			r.Post("/impersonate", func(w http.ResponseWriter, r *http.Request) {
				var body struct {
					User string `json:"user"`
				}
				if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
					http.Error(w, err.Error(), http.StatusBadRequest)

					return
				}
				_, err := api.StartImpersonatedSession(r.Context(), w, &session.ImpersonationRequest{
					Actor:           sessioninfo.FromCtx(r.Context()).Username,
					SourceSessionID: ccc.NullUUIDFromUUID(sessioninfo.IDFromRequest(r)),
					Principal:       accesstypes.UserPrincipal(accesstypes.User(body.User)),
				})
				if err != nil {
					_ = httpio.NewEncoder(w).ClientMessage(r.Context(), err)

					return
				}
				w.WriteHeader(http.StatusNoContent)
			})
		})
	})
}

// sessionView is GET /whoami's answer: the validated session as the application sees
// it.
type sessionView struct {
	SessionID string   `json:"sessionId"`
	UserID    string   `json:"userId"`
	Username  string   `json:"username"`
	User      string   `json:"user"`
	Events    []string `json:"events"`
}

func whoami(w http.ResponseWriter, r *http.Request) {
	data, _ := r.Context().Value(sessioninfo.CtxSessionInfo).(*sessioninfo.SessionData)
	view := sessionView{
		SessionID: data.ID.String(),
		Username:  data.Username,
		User:      sessioninfo.UserFromRequest(r).ID.String(),
	}
	if data.UserID.Valid {
		view.UserID = data.UserID.String()
	}
	for _, e := range data.AuthEvents {
		view.Events = append(view.Events, strings.TrimSuffix(string(e.Method)+":"+e.Connection, ":"))
	}
	_ = httpio.NewEncoder(w).Ok(view)
}

// newPasswordWorkOSApp is an application with password and WorkOS sign-in on one Auth
// over be.
func newPasswordWorkOSApp[Tx any](ctx context.Context, t *testing.T, be backend[Tx], fake *fakeWorkOS) *authApp[Tx] {
	t.Helper()

	h := &hooks[Tx]{rows: be.rows}
	db, store := be.newStore(ctx, t)
	auth, err := session.NewAuth[appSessionData, appUserData](withCustomData(t, store, h), cookieKey, h.signInPolicy,
		session.WithIdentityLinked(h.identityLinked), session.WithPendingHook(h.pendingHook))
	if err != nil {
		t.Fatalf("session.NewAuth() error = %v", err)
	}
	password := session.PasswordSignIn(auth)
	sso := workos.SignIn(auth, "workos", h.workOSResolver, &workos.Config{APIKey: "sk_test", ClientID: workosClientID, RedirectURL: "https://app.example/sso/callback", BaseURL: fake.server.URL})

	r := chi.NewRouter()
	mountAuth(r, auth, func(r chi.Router) {
		r.Get("/sso/login", sso.Login())
		r.Get("/sso/callback", sso.Callback())
		r.With(auth.ValidateXSRFToken).Post("/login", password.Login())
	})

	server := httptest.NewTLSServer(r)
	t.Cleanup(server.Close)

	return &authApp[Tx]{db: db, rows: be.rows, server: server, api: auth.API(), hooks: h}
}

// browser is a user agent of an Auth app.
func (a *authApp[Tx]) browser(t *testing.T) *browser {
	t.Helper()

	return newBrowser(t, a.server)
}

// seed creates a user with seedPassword.
func (a *authApp[Tx]) seed(ctx context.Context, t *testing.T, username string) ccc.UUID {
	t.Helper()

	pw := seedPassword
	id, err := a.api.CreateSessionUser(ctx, &session.CreateUserRequest{Username: username, Password: &pw})
	if err != nil {
		t.Fatalf("CreateSessionUser(%q) error = %v", username, err)
	}

	return id
}

// provisionMember is a user resolver that provisions every unlinked identity under its
// email for the lakeside partner, and records the membership in the application's own
// table in OnProvisioned, in the sign-in's transaction.
func (a *authApp[Tx]) provisionMember(_ context.Context, tx Tx, identity *workos.Identity) (*signin.Resolution, error) {
	return signin.Provision(&signin.NewUser{Username: identity.Email}, func(ctx context.Context, userID ccc.UUID) error {
		return a.rows.addMember(ctx, tx, userID, "lakeside")
	}, signin.Tenant("lakeside")), nil
}

// fakeWorkOS is the WorkOS code exchange: POST /sso/token answers the profile issued for
// the code, once, to the configured client.
type fakeWorkOS struct {
	server   *httptest.Server
	mu       sync.Mutex
	profiles map[string]map[string]any
}

func newFakeWorkOS(t *testing.T) *fakeWorkOS {
	t.Helper()

	f := &fakeWorkOS{profiles: map[string]map[string]any{}}
	f.server = httptest.NewServer(http.HandlerFunc(f.token))
	t.Cleanup(f.server.Close)

	return f
}

func (f *fakeWorkOS) token(w http.ResponseWriter, r *http.Request) {
	var body struct {
		ClientID     string `json:"client_id"`
		ClientSecret string `json:"client_secret"`
		GrantType    string `json:"grant_type"`
		Code         string `json:"code"`
	}
	if r.Method != http.MethodPost || r.URL.Path != "/sso/token" || r.Header.Get("Content-Type") != "application/json" {
		http.Error(w, "not found", http.StatusNotFound)

		return
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil || body.ClientID != workosClientID || body.ClientSecret != "sk_test" || body.GrantType != "authorization_code" {
		http.Error(w, `{"error":"invalid_client"}`, http.StatusUnauthorized)

		return
	}

	f.mu.Lock()
	profile, ok := f.profiles[body.Code]
	delete(f.profiles, body.Code)
	f.mu.Unlock()
	if !ok {
		http.Error(w, `{"error":"invalid_grant"}`, http.StatusBadRequest)

		return
	}
	_ = json.NewEncoder(w).Encode(map[string]any{"access_token": "at", "profile": profile})
}

// issue registers a profile of the Lakeside connection for a new code and returns the
// code.
func (f *fakeWorkOS) issue(idpID, email string) string {
	return f.issueFrom(lakesideConnection, idpID, email)
}

// issueFrom registers a profile of connection for a new code and returns the code: what
// another organisation's identity provider would assert, email included.
func (f *fakeWorkOS) issueFrom(connection, idpID, email string) string {
	f.mu.Lock()
	defer f.mu.Unlock()

	code := "code_" + ccc.Must(ccc.NewUUID()).String()
	f.profiles[code] = map[string]any{
		"id": "prof_" + idpID, "idp_id": idpID, "connection_id": connection, "connection_type": "GenericSAML",
		"organization_id": "org_lakeside", "email": email, "first_name": "Pat", "last_name": "Lee",
		"raw_attributes": map[string]any{"eduPersonPrincipalName": email},
	}

	return code
}

// prime gets the browser its anonymous session and XSRF token, as a page load would.
func (b *browser) prime(ctx context.Context) {
	b.t.Helper()
	b.expect(ctx, http.StatusOK, http.MethodGet, "/authenticated", nil)
}

// location sends GET path and returns the redirect target, failing unless it is a 302.
func (b *browser) location(ctx context.Context, path string) *url.URL {
	b.t.Helper()

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, b.base.String()+path, http.NoBody)
	if err != nil {
		b.t.Fatalf("http.NewRequestWithContext() error = %v", err)
	}
	resp, err := b.client.Do(req)
	if err != nil {
		b.t.Fatalf("GET %s error = %v", path, err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusFound {
		b.t.Fatalf("GET %s = %d, want 302", path, resp.StatusCode)
	}
	loc, err := resp.Location()
	if err != nil {
		b.t.Fatalf("resp.Location() error = %v", err)
	}

	return loc
}

// workOSSignIn runs a WorkOS round trip for the upstream identity idpID of the Lakeside
// connection and returns where the callback sent the browser.
func (b *browser) workOSSignIn(ctx context.Context, idp *fakeWorkOS, returnURL, idpID, email string) *url.URL {
	b.t.Helper()

	return b.workOSSignInFrom(ctx, idp, returnURL, lakesideConnection, idpID, email)
}

// workOSSignInFrom runs a WorkOS round trip for the upstream identity idpID that
// connection asserts, and returns where the callback sent the browser.
func (b *browser) workOSSignInFrom(ctx context.Context, idp *fakeWorkOS, returnURL, connection, idpID, email string) *url.URL {
	b.t.Helper()

	authorize := b.location(ctx, "/sso/login?organization=org_lakeside&returnUrl="+url.QueryEscape(returnURL))
	q := authorize.Query()
	if authorize.Path != "/sso/authorize" || q.Get("organization") != "org_lakeside" || q.Get("client_id") != workosClientID || q.Get("state") == "" {
		b.t.Fatalf("authorization URL = %s, want /sso/authorize for org_lakeside with a state", authorize)
	}

	code := idp.issueFrom(connection, idpID, email)

	return b.location(ctx, "/sso/callback?code="+url.QueryEscape(code)+"&state="+url.QueryEscape(q.Get("state")))
}

func (b *browser) view(ctx context.Context) *sessionView {
	b.t.Helper()

	v := &sessionView{}
	if err := json.Unmarshal(b.expect(ctx, http.StatusOK, http.MethodGet, "/whoami", nil), v); err != nil {
		b.t.Fatalf("json.Unmarshal() error = %v", err)
	}

	return v
}

// sessionData reads the validated session's custom data.
func (b *browser) sessionData(ctx context.Context) *appSessionData {
	b.t.Helper()

	data := &appSessionData{}
	if err := json.Unmarshal(b.expect(ctx, http.StatusOK, http.MethodGet, "/session-data", nil), data); err != nil {
		b.t.Fatalf("json.Unmarshal() error = %v", err)
	}

	return data
}

func (b *browser) sessionID(ctx context.Context) string {
	b.t.Helper()

	var body struct {
		SessionID string `json:"sessionId"`
	}
	if err := json.Unmarshal(b.expect(ctx, http.StatusOK, http.MethodGet, "/sid", nil), &body); err != nil {
		b.t.Fatalf("json.Unmarshal() error = %v", err)
	}

	return body.SessionID
}

// passwordLogin signs pat@lakeside.edu in with password.
func (b *browser) passwordLogin(ctx context.Context, password string) (status int, mfaIsRequired bool) {
	b.t.Helper()

	status, body := b.do(ctx, http.MethodPost, "/login", map[string]string{"username": "pat@lakeside.edu", "password": password})
	var answer struct {
		MFAIsRequired bool `json:"mfaIsRequired"`
	}
	_ = json.Unmarshal(body, &answer)

	return status, answer.MFAIsRequired
}

func assertEventsSeen(t *testing.T, v *sessionView, want ...string) {
	t.Helper()

	if strings.Join(v.Events, ",") != strings.Join(want, ",") {
		t.Errorf("session auth events = %v, want %v", v.Events, want)
	}
}

func assertRedirect(t *testing.T, got *url.URL, wantPath string, wantQuery url.Values) {
	t.Helper()

	if got.Path != wantPath || got.Query().Encode() != wantQuery.Encode() {
		t.Errorf("redirect = %s, want %s?%s", got, wantPath, wantQuery.Encode())
	}
}

// TestAuthSeams_PasswordAndWorkOS runs the password and WorkOS scenarios on each
// backend: the hooks an application gives the Auth are typed to that backend's
// transaction, and run inside the sign-in's.
func TestAuthSeams_PasswordAndWorkOS(t *testing.T) {
	t.Parallel()

	t.Run(postgresBackend.name, func(t *testing.T) {
		t.Parallel()
		runPasswordWorkOSSeams(t, postgresBackend)
	})
	t.Run(spannerBackend.name, func(t *testing.T) {
		t.Parallel()
		runPasswordWorkOSSeams(t, spannerBackend)
	})
}

func runPasswordWorkOSSeams[Tx any](t *testing.T, be backend[Tx]) {
	tests := []struct {
		name string
		run  func(ctx context.Context, t *testing.T, a *authApp[Tx], idp *fakeWorkOS)
	}{
		{
			name: "a password sign-in establishes a session under a new ID that belongs to the user and records the password method",
			run:  seamPasswordSignIn[Tx],
		},
		{
			name: "a first WorkOS sign-in provisions the user the resolver names; the next signs in through the link without the resolver",
			run:  seamWorkOSProvisionThenLink[Tx],
		},
		{
			name: "a first WorkOS sign-in provisions the user, and a policy that reads the rows OnProvisioned wrote in the same transaction signs it in",
			run:  seamWorkOSProvisionPolicyReadsRows[Tx],
		},
		{
			name: "a WorkOS sign-in the resolver rejects keeps the resolver's record of the attempt",
			run:  seamWorkOSRejectedKeepsAttempt[Tx],
		},
		{
			name: "a provisioning sign-in held for MFA names the new user to the pending hook, which sends the browser to the application's MFA page",
			run:  seamWorkOSProvisionHeldForMFA[Tx],
		},
		{
			name: "a WorkOS identity for a user with a password waits for that password, then links, reports the link and signs in",
			run:  seamWorkOSConfirmWithPassword[Tx],
		},
		{
			name: "an untrusted link of another connection's identity to a password-less user is refused with identity_rejected, and a trusted one links",
			run:  seamWorkOSCrossConnectionLink[Tx],
		},
		{
			name: "a policy that requires MFA holds the password sign-in, and the application's MFA step completes it under a new session ID",
			run:  seamPasswordMFA[Tx],
		},
		{
			name: "a confirmed link the policy still holds for MFA stays pending, now for MFA",
			run:  seamConfirmThenMFA[Tx],
		},
		{
			name: "a refused WorkOS sign-in returns to the login page with its code only and leaves no session or pending identity",
			run:  seamWorkOSRefused[Tx],
		},
		{
			name: "the WorkOS login refuses a returnUrl that leaves the application, and a login without an organization",
			run:  seamWorkOSLoginGuards[Tx],
		},
		{
			name: "a WorkOS callback that does not match the login this browser started is refused",
			run:  seamWorkOSCallbackBinding[Tx],
		},
		{
			name: "a disabled user's session is refused on its next request, and a user-principal impersonation belongs to the impersonated user",
			run:  seamDisabledAndImpersonation[Tx],
		},
		{
			name: "the store's one custom session data configuration resolves each session's row in the sign-in's transaction, and custom user data is written with the user and read on demand",
			run:  seamCustomData[Tx],
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			ctx := t.Context()

			idp := newFakeWorkOS(t)
			tt.run(ctx, t, newPasswordWorkOSApp(ctx, t, be, idp), idp)
		})
	}
}

func seamPasswordSignIn[Tx any](ctx context.Context, t *testing.T, a *authApp[Tx], _ *fakeWorkOS) {
	t.Helper()

	pat := a.seed(ctx, t, "pat@lakeside.edu")
	b := a.browser(t)
	b.prime(ctx)
	anonymous := b.sessionID(ctx)

	if status, mfa := b.passwordLogin(ctx, seedPassword); status != http.StatusOK || mfa {
		t.Fatalf("password login = %d (mfaIsRequired %v), want 200 without MFA", status, mfa)
	}
	v := b.view(ctx)
	if v.UserID != pat.String() || v.User != pat.String() || v.SessionID == anonymous {
		t.Errorf("session = %+v, want user %s under a session ID other than %s", v, pat, anonymous)
	}
	assertEventsSeen(t, v, "password")

	if status, _ := b.passwordLogin(ctx, "wrong"); status != http.StatusUnauthorized {
		t.Errorf("password login with a wrong password = %d, want 401", status)
	}
}

func seamWorkOSProvisionThenLink[Tx any](ctx context.Context, t *testing.T, a *authApp[Tx], idp *fakeWorkOS) {
	t.Helper()

	a.hooks.set(func(h *hooks[Tx]) {
		h.resolve = func(identity *workos.Identity) *signin.Resolution {
			return signin.Provision(&signin.NewUser{Username: identity.Email}, nil, signin.Tenant("lakeside"))
		}
	})

	b := a.browser(t)
	b.prime(ctx)
	assertRedirect(t, b.workOSSignIn(ctx, idp, "/dashboard", "idp_sam", "sam@lakeside.edu"), "/dashboard", url.Values{})
	first := b.view(ctx)
	if first.Username != "sam@lakeside.edu" || first.UserID == "" {
		t.Fatalf("session = %+v, want the provisioned user sam@lakeside.edu", first)
	}
	assertEventsSeen(t, first, "workos:"+lakesideConnection)

	other := a.browser(t)
	other.prime(ctx)
	assertRedirect(t, other.workOSSignIn(ctx, idp, "", "idp_sam", "sam@lakeside.edu"), "/", url.Values{})
	if second := other.view(ctx); second.UserID != first.UserID {
		t.Errorf("second sign-in user = %s, want %s", second.UserID, first.UserID)
	}

	resolved, linked := a.hooks.counts()
	if resolved != 1 {
		t.Errorf("user resolver ran %d times, want once: a linked identity never reaches it", resolved)
	}
	if len(linked) != 1 || linked[0].String() != first.UserID {
		t.Errorf("IdentityLinked reports = %v, want one for %s", linked, first.UserID)
	}
}

func seamWorkOSProvisionPolicyReadsRows[Tx any](ctx context.Context, t *testing.T, a *authApp[Tx], idp *fakeWorkOS) {
	t.Helper()

	var sources []sessioninfo.UserSource
	a.hooks.set(func(h *hooks[Tx]) {
		h.resolveTx = a.provisionMember
		// The policy reads the membership the resolver wrote, as an application's
		// "members of a partner may sign in" rule does, and refuses what it cannot see.
		h.policyTx = func(ctx context.Context, tx Tx, req *sessioninfo.NewSessionRequest) (*signin.Decision, error) {
			sources = append(sources, req.User.Source)
			partner, found, err := a.rows.partnerOf(ctx, tx, req.UserID)
			switch {
			case err != nil:
				return nil, err
			case !found:
				return signin.Deny("not_a_member"), nil
			case partner != req.User.Tenant:
				return signin.Deny("wrong_partner"), nil
			}

			return signin.Allow(), nil
		}
	})

	b := a.browser(t)
	b.prime(ctx)
	assertRedirect(t, b.workOSSignIn(ctx, idp, "/dashboard", "idp_sam", "sam@lakeside.edu"), "/dashboard", url.Values{})
	first := b.view(ctx)
	if first.Username != "sam@lakeside.edu" || first.UserID == "" {
		t.Fatalf("session = %+v, want the provisioned user sam@lakeside.edu", first)
	}

	other := a.browser(t)
	other.prime(ctx)
	assertRedirect(t, other.workOSSignIn(ctx, idp, "/dashboard", "idp_sam", "sam@lakeside.edu"), "/dashboard", url.Values{})
	if second := other.view(ctx); second.UserID != first.UserID {
		t.Errorf("second sign-in user = %s, want %s", second.UserID, first.UserID)
	}

	var seen []sessioninfo.UserSource
	a.hooks.set(func(*hooks[Tx]) { seen = append(seen, sources...) })
	if want := []sessioninfo.UserSource{sessioninfo.UserProvisioned, sessioninfo.UserExistingLink}; !slices.Equal(seen, want) {
		t.Errorf("the policy saw users %v, want %v", seen, want)
	}
	if _, linked := a.hooks.counts(); len(linked) != 1 || linked[0].String() != first.UserID {
		t.Errorf("IdentityLinked reports = %v, want one for %s", linked, first.UserID)
	}
}

func seamWorkOSRejectedKeepsAttempt[Tx any](ctx context.Context, t *testing.T, a *authApp[Tx], idp *fakeWorkOS) {
	t.Helper()

	a.hooks.set(func(h *hooks[Tx]) {
		h.resolveTx = func(ctx context.Context, tx Tx, identity *workos.Identity) (*signin.Resolution, error) {
			if err := a.rows.recordAttempt(ctx, tx, identity.IDPID, "refused: no invite"); err != nil {
				return nil, err
			}

			return signin.Reject("not_invited"), nil
		}
	})

	b := a.browser(t)
	b.prime(ctx)
	assertRedirect(t, b.workOSSignIn(ctx, idp, "/dashboard", "idp_x", "x@lakeside.edu"), "/login", url.Values{"code": {"not_invited"}})
	b.expect(ctx, http.StatusUnauthorized, http.MethodGet, "/whoami", nil)

	if got := a.db.attemptOutcome(ctx, t, "idp_x"); got != "refused: no invite" {
		t.Errorf("the resolver's record of the refused attempt = %q, want it committed", got)
	}
}

func seamWorkOSProvisionHeldForMFA[Tx any](ctx context.Context, t *testing.T, a *authApp[Tx], idp *fakeWorkOS) {
	t.Helper()

	a.hooks.set(func(h *hooks[Tx]) {
		h.resolveTx = a.provisionMember
		h.policy = func(*sessioninfo.NewSessionRequest) *signin.Decision {
			return signin.RequireMFA()
		}
		h.pendingURL = "/app/mfa"
	})

	b := a.browser(t)
	b.prime(ctx)
	anonymous := b.sessionID(ctx)
	assertRedirect(t, b.workOSSignIn(ctx, idp, "/dashboard", "idp_sam", "sam@lakeside.edu"), "/app/mfa", url.Values{})
	b.expect(ctx, http.StatusUnauthorized, http.MethodGet, "/whoami", nil)

	var pending *sessioninfo.PendingIdentity
	a.hooks.set(func(h *hooks[Tx]) {
		if len(h.pendings) == 1 {
			pending = h.pendings[0]
		}
	})
	if pending == nil || pending.Reason != sessioninfo.PendingMFA || !pending.UserID.Valid || pending.Identity.Email != "sam@lakeside.edu" || pending.ReturnURL != "/dashboard" {
		t.Fatalf("pending hook received %+v, want one MFA wait naming the provisioned user, its email and the return path", pending)
	}
	if got := a.db.username(ctx, t, pending.UserID.UUID); got != "sam@lakeside.edu" {
		t.Errorf("the pending user = %q, want sam@lakeside.edu committed, so the application can send its code", got)
	}

	b.expect(ctx, http.StatusNoContent, http.MethodPost, "/mfa", nil)
	v := b.view(ctx)
	if v.UserID != pending.UserID.String() || v.SessionID == anonymous {
		t.Errorf("session = %+v, want user %s under a session ID other than %s", v, pending.UserID.UUID, anonymous)
	}
	assertEventsSeen(t, v, "workos:"+lakesideConnection, "email-otp")
	if _, linked := a.hooks.counts(); len(linked) != 1 || linked[0] != pending.UserID.UUID {
		t.Errorf("IdentityLinked reports = %v, want one for %s", linked, pending.UserID.UUID)
	}
}

func seamWorkOSConfirmWithPassword[Tx any](ctx context.Context, t *testing.T, a *authApp[Tx], idp *fakeWorkOS) {
	t.Helper()

	pat := a.seed(ctx, t, "pat@lakeside.edu")
	a.hooks.set(func(h *hooks[Tx]) {
		h.resolve = func(*workos.Identity) *signin.Resolution {
			return signin.Confirm(pat, signin.Tenant("lakeside"))
		}
	})

	b := a.browser(t)
	b.prime(ctx)
	assertRedirect(t, b.workOSSignIn(ctx, idp, "/dashboard", "idp_pat", "pat@lakeside.edu"), "/login",
		url.Values{"pending": {"confirmation"}, "returnUrl": {"/dashboard"}})
	b.expect(ctx, http.StatusUnauthorized, http.MethodGet, "/whoami", nil)

	var status struct {
		Reason    string `json:"reason"`
		Email     string `json:"email"`
		ReturnURL string `json:"returnUrl"`
	}
	if err := json.Unmarshal(b.expect(ctx, http.StatusOK, http.MethodGet, "/pending", nil), &status); err != nil {
		t.Fatalf("json.Unmarshal() error = %v", err)
	}
	if status.Reason != "confirmation" || status.Email != "pat@lakeside.edu" || status.ReturnURL != "/dashboard" {
		t.Errorf("pending status = %+v, want confirmation for pat@lakeside.edu returning to /dashboard", status)
	}

	b.expect(ctx, http.StatusUnauthorized, http.MethodPost, "/pending/confirm", map[string]string{"password": "wrong"})
	if _, linked := a.hooks.counts(); len(linked) != 0 {
		t.Fatalf("IdentityLinked reports after a wrong password = %v, want none", linked)
	}
	replay := b.clone()

	if body := b.expect(ctx, http.StatusOK, http.MethodPost, "/pending/confirm", map[string]string{"password": seedPassword}); !strings.Contains(string(body), `"mfaIsRequired":false`) {
		t.Fatalf("confirm = %s, want mfaIsRequired false", body)
	}
	v := b.view(ctx)
	if v.UserID != pat.String() {
		t.Errorf("session user = %s, want %s", v.UserID, pat)
	}
	assertEventsSeen(t, v, "workos:"+lakesideConnection, "link-confirmation")
	if _, linked := a.hooks.counts(); len(linked) != 1 || linked[0] != pat {
		t.Errorf("IdentityLinked reports = %v, want one for %s", linked, pat)
	}

	// The pending identity was consumed: a copy of its cookie confirms nothing.
	replay.expect(ctx, http.StatusUnauthorized, http.MethodGet, "/pending", nil)
	replay.expect(ctx, http.StatusUnauthorized, http.MethodPost, "/pending/confirm", map[string]string{"password": seedPassword})

	// The identity is linked now: the next sign-in goes straight in.
	next := a.browser(t)
	next.prime(ctx)
	assertRedirect(t, next.workOSSignIn(ctx, idp, "/dashboard", "idp_pat", "pat@lakeside.edu"), "/dashboard", url.Values{})
	if got := next.view(ctx).UserID; got != pat.String() {
		t.Errorf("linked sign-in user = %s, want %s", got, pat)
	}
}

func seamPasswordMFA[Tx any](ctx context.Context, t *testing.T, a *authApp[Tx], _ *fakeWorkOS) {
	t.Helper()

	pat := a.seed(ctx, t, "pat@lakeside.edu")
	a.hooks.set(func(h *hooks[Tx]) {
		h.policy = func(*sessioninfo.NewSessionRequest) *signin.Decision {
			return signin.RequireMFA("email-otp")
		}
	})

	b := a.browser(t)
	b.prime(ctx)
	anonymous := b.sessionID(ctx)
	if status, mfa := b.passwordLogin(ctx, seedPassword); status != http.StatusOK || !mfa {
		t.Fatalf("password login = %d (mfaIsRequired %v), want 200 requiring MFA", status, mfa)
	}
	b.expect(ctx, http.StatusUnauthorized, http.MethodGet, "/whoami", nil)
	if body := b.expect(ctx, http.StatusOK, http.MethodGet, "/pending", nil); !strings.Contains(string(body), `"reason":"mfa"`) || !strings.Contains(string(body), `"factors":["email-otp"]`) {
		t.Errorf("pending status = %s, want reason mfa accepting email-otp", body)
	}
	replay := b.clone()

	b.expect(ctx, http.StatusNoContent, http.MethodPost, "/mfa", nil)
	v := b.view(ctx)
	if v.UserID != pat.String() || v.SessionID == anonymous {
		t.Errorf("session = %+v, want user %s under a session ID other than %s", v, pat, anonymous)
	}
	assertEventsSeen(t, v, "password", "email-otp")

	replay.expect(ctx, http.StatusUnauthorized, http.MethodPost, "/mfa", nil)
	replay.expect(ctx, http.StatusUnauthorized, http.MethodGet, "/whoami", nil)
}

func seamConfirmThenMFA[Tx any](ctx context.Context, t *testing.T, a *authApp[Tx], idp *fakeWorkOS) {
	t.Helper()

	pat := a.seed(ctx, t, "pat@lakeside.edu")
	a.hooks.set(func(h *hooks[Tx]) {
		h.resolve = func(*workos.Identity) *signin.Resolution {
			return signin.Confirm(pat)
		}
		h.policy = func(req *sessioninfo.NewSessionRequest) *signin.Decision {
			if req.Reason == sessioninfo.ReasonIdentityLinked {
				return signin.RequireMFA()
			}

			return signin.Allow()
		}
	})

	b := a.browser(t)
	b.prime(ctx)
	b.workOSSignIn(ctx, idp, "/", "idp_pat", "pat@lakeside.edu")
	if body := b.expect(ctx, http.StatusOK, http.MethodPost, "/pending/confirm", map[string]string{"password": seedPassword}); !strings.Contains(string(body), `"mfaIsRequired":true`) {
		t.Fatalf("confirm = %s, want mfaIsRequired true", body)
	}
	b.expect(ctx, http.StatusUnauthorized, http.MethodGet, "/whoami", nil)

	b.expect(ctx, http.StatusNoContent, http.MethodPost, "/mfa", nil)
	assertEventsSeen(t, b.view(ctx), "workos:"+lakesideConnection, "link-confirmation", "email-otp")
}

func seamWorkOSRefused[Tx any](ctx context.Context, t *testing.T, a *authApp[Tx], idp *fakeWorkOS) {
	t.Helper()

	a.hooks.set(func(h *hooks[Tx]) {
		h.resolve = func(*workos.Identity) *signin.Resolution {
			return signin.Reject("not_invited")
		}
	})

	b := a.browser(t)
	b.prime(ctx)
	assertRedirect(t, b.workOSSignIn(ctx, idp, "/dashboard", "idp_x", "x@lakeside.edu"), "/login", url.Values{"code": {"not_invited"}})
	b.expect(ctx, http.StatusUnauthorized, http.MethodGet, "/whoami", nil)
	b.expect(ctx, http.StatusNotFound, http.MethodGet, "/pending", nil)
}

func seamWorkOSLoginGuards[Tx any](ctx context.Context, t *testing.T, a *authApp[Tx], _ *fakeWorkOS) {
	t.Helper()

	b := a.browser(t)
	for _, path := range []string{
		"/sso/login?organization=org_lakeside&returnUrl=" + url.QueryEscape("https://evil.example/"),
		"/sso/login?organization=org_lakeside&returnUrl=" + url.QueryEscape("//evil.example/"),
		"/sso/login?organization=org_lakeside&returnUrl=" + url.QueryEscape(`/\evil.example/`),
		"/sso/login?organization=org_lakeside&returnUrl=" + url.QueryEscape(`/./\evil.example/`),
		"/sso/login?organization=org_lakeside&returnUrl=" + url.QueryEscape(`/a/../\evil.example/`),
		"/sso/login?organization=org_lakeside&returnUrl=" + url.QueryEscape("/%2e/%5cevil.example/"),
		"/sso/login",
	} {
		b.expect(ctx, http.StatusBadRequest, http.MethodGet, path, nil)
	}
}

func seamWorkOSCallbackBinding[Tx any](ctx context.Context, t *testing.T, a *authApp[Tx], idp *fakeWorkOS) {
	t.Helper()

	b := a.browser(t)
	state := b.location(ctx, "/sso/login?organization=org_lakeside").Query().Get("state")

	code := idp.issue("idp_x", "x@lakeside.edu")
	assertRedirect(t, b.location(ctx, "/sso/callback?code="+code+"&state=forged"), "/login", url.Values{"code": {"invalid_state"}})

	stranger := a.browser(t)
	assertRedirect(t, stranger.location(ctx, "/sso/callback?code="+code+"&state="+url.QueryEscape(state)), "/login", url.Values{"code": {"no_oidc_cookie"}})
}

func seamDisabledAndImpersonation[Tx any](ctx context.Context, t *testing.T, a *authApp[Tx], _ *fakeWorkOS) {
	t.Helper()

	pat := a.seed(ctx, t, "pat@lakeside.edu")
	bob := a.seed(ctx, t, "bob@lakeside.edu")

	b := a.browser(t)
	b.prime(ctx)
	b.passwordLogin(ctx, seedPassword)
	tab := b.clone()
	b.expect(ctx, http.StatusNoContent, http.MethodPost, "/impersonate", map[string]string{"user": "bob@lakeside.edu"})
	v := b.view(ctx)
	if v.UserID != bob.String() || v.User != bob.String() {
		t.Errorf("impersonated session = %+v, want user %s", v, bob)
	}
	assertEventsSeen(t, v, "impersonation:pat@lakeside.edu")

	a.db.disableUser(ctx, t, pat)
	tab.expect(ctx, http.StatusUnauthorized, http.MethodGet, "/whoami", nil)
}

// seamWorkOSCrossConnectionLink: sam signs in through Lakeside and is provisioned
// without a password. A resolver that matches by email then links the identity another
// connection asserts for sam's email: refused, since sam has no password to confirm
// with, unless the resolver vouches with trusted.
func seamWorkOSCrossConnectionLink[Tx any](ctx context.Context, t *testing.T, a *authApp[Tx], idp *fakeWorkOS) {
	t.Helper()

	a.hooks.set(func(h *hooks[Tx]) { h.resolveTx = a.provisionMember })
	first := a.browser(t)
	first.prime(ctx)
	assertRedirect(t, first.workOSSignIn(ctx, idp, "/home", "idp_sam", "sam@lakeside.edu"), "/home", url.Values{})
	sam, err := ccc.UUIDFromString(first.view(ctx).UserID)
	if err != nil {
		t.Fatalf("ccc.UUIDFromString() error = %v", err)
	}

	trusted := false
	a.hooks.set(func(h *hooks[Tx]) {
		h.resolveTx = func(context.Context, Tx, *workos.Identity) (*signin.Resolution, error) {
			return signin.Link(sam, trusted), nil
		}
	})
	other := a.browser(t)
	other.prime(ctx)
	assertRedirect(t, other.workOSSignInFrom(ctx, idp, "/home", "conn_riverside", "idp_mallory", "sam@lakeside.edu"), "/login", url.Values{"code": {"identity_rejected"}})
	other.expect(ctx, http.StatusUnauthorized, http.MethodGet, "/whoami", nil)
	if links, err := a.api.Identities(ctx, sam); err != nil || len(links) != 1 {
		t.Fatalf("Identities() = %d links, %v; want the Lakeside one only", len(links), err)
	}

	trusted = true
	assertRedirect(t, other.workOSSignInFrom(ctx, idp, "/home", "conn_riverside", "idp_mallory", "sam@lakeside.edu"), "/home", url.Values{})
	if v := other.view(ctx); v.UserID != sam.String() {
		t.Errorf("trusted cross-connection session = %+v, want user %s", v, sam)
	}
	if links, err := a.api.Identities(ctx, sam); err != nil || len(links) != 2 {
		t.Errorf("Identities() = %d links, %v; want the trusted link added", len(links), err)
	}
}

func seamCustomData[Tx any](ctx context.Context, t *testing.T, a *authApp[Tx], idp *fakeWorkOS) {
	t.Helper()

	a.hooks.set(func(h *hooks[Tx]) { h.resolveTx = a.provisionMember })

	// A provisioning sign-in: the resolver reads the membership OnProvisioned wrote,
	// in the same transaction, for the user the sign-in just provisioned.
	b := a.browser(t)
	b.prime(ctx)
	assertRedirect(t, b.workOSSignIn(ctx, idp, "/dashboard", "idp_sam", "sam@lakeside.edu"), "/dashboard", url.Values{})
	if got := b.sessionData(ctx); got.Partner != "lakeside" {
		t.Errorf("custom session data after the provisioning sign-in = %+v, want the lakeside membership OnProvisioned wrote", got)
	}

	// A password sign-in of a user with no membership resolves an empty row, under the
	// same configuration.
	a.seed(ctx, t, "pat@lakeside.edu")
	other := a.browser(t)
	other.prime(ctx)
	if status, mfa := other.passwordLogin(ctx, seedPassword); status != http.StatusOK || mfa {
		t.Fatalf("password login = %d (mfaIsRequired %v), want 200 without MFA", status, mfa)
	}
	if got := other.sessionData(ctx); got.Partner != "" {
		t.Errorf("custom session data of a user without a membership = %+v, want an empty partner", got)
	}

	// Custom user data is written with the user, read on demand, and updated in place.
	pw := seedPassword
	kim, err := a.api.CreateSessionUser(ctx, &session.CreateUserRequest{Username: "kim@lakeside.edu", Password: &pw}, &appUserData{Locale: "en-AU"})
	if err != nil {
		t.Fatalf("CreateSessionUser() error = %v", err)
	}
	if got, err := a.api.CustomUserData(ctx, kim); err != nil || got.Locale != "en-AU" {
		t.Errorf("CustomUserData() = %+v, %v; want the locale written with the user", got, err)
	}
	if err := a.api.UpdateCustomUserData(ctx, kim, func(d *appUserData) error {
		d.Locale = "fr-CA"

		return nil
	}); err != nil {
		t.Fatalf("UpdateCustomUserData() error = %v", err)
	}
	if got, err := a.api.CustomUserData(ctx, kim); err != nil || got.Locale != "fr-CA" {
		t.Errorf("CustomUserData() after the update = %+v, %v; want fr-CA", got, err)
	}
}
