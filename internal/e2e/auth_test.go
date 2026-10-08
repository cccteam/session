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
	dbinitiator "github.com/cccteam/db-initiator"
	"github.com/cccteam/httpio"
	"github.com/cccteam/session"
	"github.com/cccteam/session/sessioninfo"
	"github.com/cccteam/session/sessionstorage"
	"github.com/go-chi/chi/v5"
	"github.com/go-playground/errors/v5"
	"github.com/jackc/pgx/v5"
)

const accountsMigrations = "file://../../schema/postgresql/accounts/migrations"

// The password every seeded account has.
const seedPassword = "correct horse battery staple"

// The WorkOS client the fake accepts, and the connection its sign-ins come through.
const (
	workosClientID     = "client_test"
	lakesideConnection = "conn_lakeside"
)

// hooks are an Auth app's account resolver, sign-in policy, IdentityLinked hook and
// PendingHook, set per scenario. The resolver and the policy run inside the sign-in's
// transactions; resolveTx and policyTx, when set, receive them to write and read the
// application's own rows.
type hooks struct {
	mu        sync.Mutex
	resolve   func(req *sessioninfo.NewSessionRequest) *sessionstorage.Resolution
	policy    func(req *sessioninfo.NewSessionRequest) *sessionstorage.SignInDecision
	resolveTx func(ctx context.Context, tx pgx.Tx, req *sessioninfo.NewSessionRequest) (*sessionstorage.Resolution, error)
	policyTx  func(ctx context.Context, tx pgx.Tx, req *sessioninfo.NewSessionRequest) (*sessionstorage.SignInDecision, error)
	// pendingURL is where the PendingHook sends a pending sign-in; "" keeps the default.
	pendingURL string
	resolved   int
	linked     []ccc.UUID
	pendings   []*sessioninfo.PendingIdentity
}

func (h *hooks) resolver(ctx context.Context, tx pgx.Tx, req *sessioninfo.NewSessionRequest) (*sessionstorage.Resolution, error) {
	h.mu.Lock()
	defer h.mu.Unlock()

	h.resolved++
	switch {
	case h.resolveTx != nil:
		return h.resolveTx(ctx, tx, req)
	case h.resolve == nil:
		return &sessionstorage.Resolution{}, nil
	}

	return h.resolve(req), nil
}

func (h *hooks) signInPolicy(ctx context.Context, tx pgx.Tx, req *sessioninfo.NewSessionRequest) (*sessionstorage.SignInDecision, error) {
	h.mu.Lock()
	defer h.mu.Unlock()

	switch {
	case h.policyTx != nil:
		return h.policyTx(ctx, tx, req)
	case h.policy == nil:
		return &sessionstorage.SignInDecision{Outcome: sessionstorage.AllowSignIn}, nil
	}

	return h.policy(req), nil
}

func (h *hooks) pendingHook(_ context.Context, _ http.ResponseWriter, _ *http.Request, pending *sessioninfo.PendingIdentity) (string, error) {
	h.mu.Lock()
	defer h.mu.Unlock()

	h.pendings = append(h.pendings, pending)

	return h.pendingURL, nil
}

func (h *hooks) identityLinked(_ context.Context, userID ccc.UUID, _ *sessioninfo.Identity) error {
	h.mu.Lock()
	defer h.mu.Unlock()

	h.linked = append(h.linked, userID)

	return nil
}

func (h *hooks) set(fn func(h *hooks)) {
	h.mu.Lock()
	defer h.mu.Unlock()

	fn(h)
}

func (h *hooks) counts() (resolved int, linked []ccc.UUID) {
	h.mu.Lock()
	defer h.mu.Unlock()

	return h.resolved, append([]ccc.UUID(nil), h.linked...)
}

// authApp is an application on one Auth session over PostgreSQL with the accounts,
// auth events and impersonation schema.
type authApp struct {
	db     *dbinitiator.PostgresDatabase
	server *httptest.Server
	api    *session.AuthAPI[session.NoCustomData, session.NoCustomData]
	hooks  *hooks
}

// newAuthStore prepares a database with the shipped sessions, impersonation and accounts
// migrations and returns account storage over it with h's hooks.
func newAuthStore(ctx context.Context, t *testing.T, h *hooks) (*dbinitiator.PostgresDatabase, *sessionstorage.Accounts) {
	t.Helper()

	db := prepareDatabase(ctx, t)
	if err := db.MigrateUp(accountsMigrations); err != nil {
		t.Fatalf("PostgresDatabase.MigrateUp(accounts) error = %v", err)
	}
	// The application's own tables, which its hooks write in the sign-in transactions.
	if _, err := db.Exec(ctx, `
		CREATE TABLE "PartnerMembers" ("UserId" UUID PRIMARY KEY REFERENCES "SessionUsers" ("Id"), "Partner" character varying NOT NULL);
		CREATE TABLE "SignInAttempts" ("Subject" character varying NOT NULL, "Outcome" character varying NOT NULL)`); err != nil {
		t.Fatalf("create the application's tables: %v", err)
	}

	identities, err := sessionstorage.NewPostgresIdentities("SessionIdentities", h.resolver, h.signInPolicy)
	if err != nil {
		t.Fatalf("sessionstorage.NewPostgresIdentities() error = %v", err)
	}
	events, err := sessionstorage.NewAuthEventsTable("SessionAuthEvents")
	if err != nil {
		t.Fatalf("sessionstorage.NewAuthEventsTable() error = %v", err)
	}
	impersonation, err := sessionstorage.NewImpersonationTable("SessionImpersonations")
	if err != nil {
		t.Fatalf("sessionstorage.NewImpersonationTable() error = %v", err)
	}

	return db, sessionstorage.NewPostgresAccounts(db.Pool,
		sessionstorage.WithPostgresIdentities(identities), sessionstorage.WithAuthEvents(events), sessionstorage.WithImpersonation(impersonation))
}

// mountAuth mounts auth's shared routes, the way the README prescribes, plus the
// application's own MFA step and a /whoami that reports the validated session.
func mountAuth(r chi.Router, auth *session.Auth[session.NoCustomData, session.NoCustomData], routes func(r chi.Router)) {
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
	Account   string   `json:"account"`
	Events    []string `json:"events"`
}

func whoami(w http.ResponseWriter, r *http.Request) {
	data, _ := r.Context().Value(sessioninfo.CtxSessionInfo).(*sessioninfo.SessionData)
	view := sessionView{
		SessionID: data.ID.String(),
		Username:  data.Username,
		Account:   sessioninfo.UserFromRequest(r).ID.String(),
	}
	if data.UserID.Valid {
		view.UserID = data.UserID.String()
	}
	for _, e := range data.AuthEvents {
		view.Events = append(view.Events, strings.TrimSuffix(string(e.Method)+":"+e.Connection, ":"))
	}
	_ = httpio.NewEncoder(w).Ok(view)
}

// newPasswordWorkOSApp is an application with password and WorkOS sign-in on one Auth.
func newPasswordWorkOSApp(ctx context.Context, t *testing.T, workos *fakeWorkOS) *authApp {
	t.Helper()

	h := &hooks{}
	db, store := newAuthStore(ctx, t, h)
	auth, err := session.NewAuth[session.NoCustomData, session.NoCustomData](store, cookieKey,
		session.WithIdentityLinked(h.identityLinked), session.WithPendingHook(h.pendingHook))
	if err != nil {
		t.Fatalf("session.NewAuth() error = %v", err)
	}
	password := session.PasswordSignIn(auth)
	sso := session.WorkOSSignIn(auth, "sk_test", workosClientID, "https://app.example/sso/callback", session.WithWorkOSBaseURL(workos.server.URL))

	r := chi.NewRouter()
	mountAuth(r, auth, func(r chi.Router) {
		r.Get("/sso/login", sso.Login())
		r.Get("/sso/callback", sso.Callback())
		r.With(auth.ValidateXSRFToken).Post("/login", password.Login())
	})

	server := httptest.NewTLSServer(r)
	t.Cleanup(server.Close)

	return &authApp{db: db, server: server, api: auth.API(), hooks: h}
}

// browser is a user agent of an Auth app.
func (a *authApp) browser(t *testing.T) *browser {
	t.Helper()

	return (&app{db: a.db, server: a.server}).browser(t)
}

// seed creates an account with seedPassword.
func (a *authApp) seed(ctx context.Context, t *testing.T, username string) ccc.UUID {
	t.Helper()

	pw := seedPassword
	id, err := a.api.CreateSessionUser(ctx, &session.CreateUserRequest{Username: username, Password: &pw})
	if err != nil {
		t.Fatalf("CreateSessionUser(%q) error = %v", username, err)
	}

	return id
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
	f.mu.Lock()
	defer f.mu.Unlock()

	code := "code_" + ccc.Must(ccc.NewUUID()).String()
	f.profiles[code] = map[string]any{
		"id": "prof_" + idpID, "idp_id": idpID, "connection_id": lakesideConnection, "connection_type": "GenericSAML",
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
func (b *browser) workOSSignIn(ctx context.Context, workos *fakeWorkOS, returnURL, idpID, email string) *url.URL {
	b.t.Helper()

	authorize := b.location(ctx, "/sso/login?organization=org_lakeside&returnUrl="+url.QueryEscape(returnURL))
	q := authorize.Query()
	if authorize.Path != "/sso/authorize" || q.Get("organization") != "org_lakeside" || q.Get("client_id") != workosClientID || q.Get("state") == "" {
		b.t.Fatalf("authorization URL = %s, want /sso/authorize for org_lakeside with a state", authorize)
	}

	code := workos.issue(idpID, email)

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

func TestAuthSeams_PasswordAndWorkOS(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		run  func(ctx context.Context, t *testing.T, a *authApp, workos *fakeWorkOS)
	}{
		{
			name: "a password sign-in establishes a session under a new ID that belongs to the account and records the password method",
			run:  seamPasswordSignIn,
		},
		{
			name: "a first WorkOS sign-in provisions the account the resolver names; the next signs in through the link without the resolver",
			run:  seamWorkOSProvisionThenLink,
		},
		{
			name: "a first WorkOS sign-in provisions the account, and a policy that reads the account and the application's rows OnProvisioned wrote signs it in",
			run:  seamWorkOSProvisionPolicyReadsAccount,
		},
		{
			name: "a WorkOS sign-in the resolver rejects keeps the resolver's record of the attempt",
			run:  seamWorkOSRejectedKeepsAttempt,
		},
		{
			name: "a provisioning sign-in held for MFA names the new account to the pending hook, which sends the browser to the application's MFA page",
			run:  seamWorkOSProvisionHeldForMFA,
		},
		{
			name: "a WorkOS identity for an account with a password waits for that password, then links, reports the link and signs in",
			run:  seamWorkOSConfirmWithPassword,
		},
		{
			name: "a policy that requires MFA holds the password sign-in, and the application's MFA step completes it under a new session ID",
			run:  seamPasswordMFA,
		},
		{
			name: "a confirmed link the policy still holds for MFA stays pending, now for MFA",
			run:  seamConfirmThenMFA,
		},
		{
			name: "a refused WorkOS sign-in returns to the login page with its code only and leaves no session or pending identity",
			run:  seamWorkOSRefused,
		},
		{
			name: "the WorkOS login refuses a returnUrl that leaves the application, and a login without an organization",
			run:  seamWorkOSLoginGuards,
		},
		{
			name: "a WorkOS callback that does not match the login this browser started is refused",
			run:  seamWorkOSCallbackBinding,
		},
		{
			name: "a disabled account's session is refused on its next request, and a user-principal impersonation belongs to the impersonated account",
			run:  seamDisabledAndImpersonation,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			ctx := t.Context()

			workos := newFakeWorkOS(t)
			tt.run(ctx, t, newPasswordWorkOSApp(ctx, t, workos), workos)
		})
	}
}

func seamPasswordSignIn(ctx context.Context, t *testing.T, a *authApp, _ *fakeWorkOS) {
	t.Helper()

	pat := a.seed(ctx, t, "pat@lakeside.edu")
	b := a.browser(t)
	b.prime(ctx)
	anonymous := b.sessionID(ctx)

	if status, mfa := b.passwordLogin(ctx, seedPassword); status != http.StatusOK || mfa {
		t.Fatalf("password login = %d (mfaIsRequired %v), want 200 without MFA", status, mfa)
	}
	v := b.view(ctx)
	if v.UserID != pat.String() || v.Account != pat.String() || v.SessionID == anonymous {
		t.Errorf("session = %+v, want account %s under a session ID other than %s", v, pat, anonymous)
	}
	assertEventsSeen(t, v, "password")

	if status, _ := b.passwordLogin(ctx, "wrong"); status != http.StatusUnauthorized {
		t.Errorf("password login with a wrong password = %d, want 401", status)
	}
}

func seamWorkOSProvisionThenLink(ctx context.Context, t *testing.T, a *authApp, workos *fakeWorkOS) {
	t.Helper()

	a.hooks.set(func(h *hooks) {
		h.resolve = func(req *sessioninfo.NewSessionRequest) *sessionstorage.Resolution {
			return &sessionstorage.Resolution{Outcome: sessionstorage.ProvisionAccount, NewUser: &sessionstorage.InsertSessionUser{Username: req.Identity.Email}, Tenant: "lakeside"}
		}
	})

	b := a.browser(t)
	b.prime(ctx)
	assertRedirect(t, b.workOSSignIn(ctx, workos, "/dashboard", "idp_sam", "sam@lakeside.edu"), "/dashboard", url.Values{})
	first := b.view(ctx)
	if first.Username != "sam@lakeside.edu" || first.UserID == "" {
		t.Fatalf("session = %+v, want the provisioned account sam@lakeside.edu", first)
	}
	assertEventsSeen(t, first, "workos:"+lakesideConnection)

	other := a.browser(t)
	other.prime(ctx)
	assertRedirect(t, other.workOSSignIn(ctx, workos, "", "idp_sam", "sam@lakeside.edu"), "/", url.Values{})
	if second := other.view(ctx); second.UserID != first.UserID {
		t.Errorf("second sign-in account = %s, want %s", second.UserID, first.UserID)
	}

	resolved, linked := a.hooks.counts()
	if resolved != 1 {
		t.Errorf("account resolver ran %d times, want once: a linked identity never reaches it", resolved)
	}
	if len(linked) != 1 || linked[0].String() != first.UserID {
		t.Errorf("IdentityLinked reports = %v, want one for %s", linked, first.UserID)
	}
}

// provisionMember is an account resolver that provisions every unlinked identity under
// its email for the lakeside partner, and records the membership in the application's
// own table in OnProvisioned, in the resolver's transaction.
func provisionMember(_ context.Context, tx pgx.Tx, req *sessioninfo.NewSessionRequest) (*sessionstorage.Resolution, error) {
	return &sessionstorage.Resolution{
		Outcome: sessionstorage.ProvisionAccount, NewUser: &sessionstorage.InsertSessionUser{Username: req.Identity.Email}, Tenant: "lakeside",
		OnProvisioned: func(ctx context.Context, userID ccc.UUID) error {
			_, err := tx.Exec(ctx, `INSERT INTO "PartnerMembers" ("UserId", "Partner") VALUES ($1, 'lakeside')`, userID)

			return err //nolint:wrapcheck // the driver wraps it
		},
	}, nil
}

func seamWorkOSProvisionPolicyReadsAccount(ctx context.Context, t *testing.T, a *authApp, workos *fakeWorkOS) {
	t.Helper()

	var sources []sessioninfo.AccountSource
	a.hooks.set(func(h *hooks) {
		h.resolveTx = provisionMember
		// The policy reads the account and its membership, as an application's "members
		// of a partner may sign in" rule does, and refuses what it cannot see.
		h.policyTx = func(ctx context.Context, tx pgx.Tx, req *sessioninfo.NewSessionRequest) (*sessionstorage.SignInDecision, error) {
			sources = append(sources, req.Account.Source)
			var partner string
			err := tx.QueryRow(ctx, `SELECT m."Partner" FROM "PartnerMembers" m JOIN "SessionUsers" u ON u."Id" = m."UserId" WHERE u."Id" = $1`, req.UserID).Scan(&partner)
			switch {
			case errors.Is(err, pgx.ErrNoRows):
				return &sessionstorage.SignInDecision{Outcome: sessionstorage.DenySignIn, Refusal: "not_a_member"}, nil
			case err != nil:
				return nil, err //nolint:wrapcheck // the driver wraps it
			case partner != req.Account.Tenant:
				return &sessionstorage.SignInDecision{Outcome: sessionstorage.DenySignIn, Refusal: "wrong_partner"}, nil
			}

			return &sessionstorage.SignInDecision{Outcome: sessionstorage.AllowSignIn}, nil
		}
	})

	b := a.browser(t)
	b.prime(ctx)
	assertRedirect(t, b.workOSSignIn(ctx, workos, "/dashboard", "idp_sam", "sam@lakeside.edu"), "/dashboard", url.Values{})
	first := b.view(ctx)
	if first.Username != "sam@lakeside.edu" || first.UserID == "" {
		t.Fatalf("session = %+v, want the provisioned account sam@lakeside.edu", first)
	}

	other := a.browser(t)
	other.prime(ctx)
	assertRedirect(t, other.workOSSignIn(ctx, workos, "/dashboard", "idp_sam", "sam@lakeside.edu"), "/dashboard", url.Values{})
	if second := other.view(ctx); second.UserID != first.UserID {
		t.Errorf("second sign-in account = %s, want %s", second.UserID, first.UserID)
	}

	var seen []sessioninfo.AccountSource
	a.hooks.set(func(*hooks) { seen = append(seen, sources...) })
	if want := []sessioninfo.AccountSource{sessioninfo.AccountProvisioned, sessioninfo.AccountExistingLink}; !slices.Equal(seen, want) {
		t.Errorf("the policy saw accounts %v, want %v", seen, want)
	}
	if _, linked := a.hooks.counts(); len(linked) != 1 || linked[0].String() != first.UserID {
		t.Errorf("IdentityLinked reports = %v, want one for %s", linked, first.UserID)
	}
}

func seamWorkOSRejectedKeepsAttempt(ctx context.Context, t *testing.T, a *authApp, workos *fakeWorkOS) {
	t.Helper()

	a.hooks.set(func(h *hooks) {
		h.resolveTx = func(ctx context.Context, tx pgx.Tx, req *sessioninfo.NewSessionRequest) (*sessionstorage.Resolution, error) {
			if _, err := tx.Exec(ctx, `INSERT INTO "SignInAttempts" ("Subject", "Outcome") VALUES ($1, 'refused: no invite')`, req.Identity.Subject); err != nil {
				return nil, err //nolint:wrapcheck // the driver wraps it
			}

			return &sessionstorage.Resolution{Outcome: sessionstorage.RejectIdentity, Refusal: "not_invited"}, nil
		}
	})

	b := a.browser(t)
	b.prime(ctx)
	assertRedirect(t, b.workOSSignIn(ctx, workos, "/dashboard", "idp_x", "x@lakeside.edu"), "/login", url.Values{"code": {"not_invited"}})
	b.expect(ctx, http.StatusUnauthorized, http.MethodGet, "/whoami", nil)

	var outcome string
	if err := a.db.QueryRow(ctx, `SELECT "Outcome" FROM "SignInAttempts" WHERE "Subject" = 'idp_x'`).Scan(&outcome); err != nil || outcome != "refused: no invite" {
		t.Errorf("the resolver's record of the refused attempt = %q, %v; want it committed", outcome, err)
	}
}

func seamWorkOSProvisionHeldForMFA(ctx context.Context, t *testing.T, a *authApp, workos *fakeWorkOS) {
	t.Helper()

	a.hooks.set(func(h *hooks) {
		h.resolveTx = provisionMember
		h.policy = func(*sessioninfo.NewSessionRequest) *sessionstorage.SignInDecision {
			return &sessionstorage.SignInDecision{Outcome: sessionstorage.RequireMFA}
		}
		h.pendingURL = "/app/mfa"
	})

	b := a.browser(t)
	b.prime(ctx)
	anonymous := b.sessionID(ctx)
	assertRedirect(t, b.workOSSignIn(ctx, workos, "/dashboard", "idp_sam", "sam@lakeside.edu"), "/app/mfa", url.Values{})
	b.expect(ctx, http.StatusUnauthorized, http.MethodGet, "/whoami", nil)

	var pending *sessioninfo.PendingIdentity
	a.hooks.set(func(h *hooks) {
		if len(h.pendings) == 1 {
			pending = h.pendings[0]
		}
	})
	if pending == nil || pending.Reason != sessioninfo.PendingMFA || !pending.UserID.Valid || pending.Identity.Email != "sam@lakeside.edu" || pending.ReturnURL != "/dashboard" {
		t.Fatalf("pending hook received %+v, want one MFA wait naming the provisioned account, its email and the return path", pending)
	}
	var username string
	if err := a.db.QueryRow(ctx, `SELECT "Username" FROM "SessionUsers" WHERE "Id" = $1`, pending.UserID.UUID).Scan(&username); err != nil || username != "sam@lakeside.edu" {
		t.Errorf("the pending account = %q, %v; want sam@lakeside.edu committed, so the application can send its code", username, err)
	}

	b.expect(ctx, http.StatusNoContent, http.MethodPost, "/mfa", nil)
	v := b.view(ctx)
	if v.UserID != pending.UserID.String() || v.SessionID == anonymous {
		t.Errorf("session = %+v, want account %s under a session ID other than %s", v, pending.UserID.UUID, anonymous)
	}
	assertEventsSeen(t, v, "workos:"+lakesideConnection, "email-otp")
	if _, linked := a.hooks.counts(); len(linked) != 1 || linked[0] != pending.UserID.UUID {
		t.Errorf("IdentityLinked reports = %v, want one for %s", linked, pending.UserID.UUID)
	}
}

func seamWorkOSConfirmWithPassword(ctx context.Context, t *testing.T, a *authApp, workos *fakeWorkOS) {
	t.Helper()

	pat := a.seed(ctx, t, "pat@lakeside.edu")
	a.hooks.set(func(h *hooks) {
		h.resolve = func(*sessioninfo.NewSessionRequest) *sessionstorage.Resolution {
			return &sessionstorage.Resolution{Outcome: sessionstorage.RequireConfirmation, UserID: pat, Tenant: "lakeside"}
		}
	})

	b := a.browser(t)
	b.prime(ctx)
	assertRedirect(t, b.workOSSignIn(ctx, workos, "/dashboard", "idp_pat", "pat@lakeside.edu"), "/login",
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
		t.Errorf("session account = %s, want %s", v.UserID, pat)
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
	assertRedirect(t, next.workOSSignIn(ctx, workos, "/dashboard", "idp_pat", "pat@lakeside.edu"), "/dashboard", url.Values{})
	if got := next.view(ctx).UserID; got != pat.String() {
		t.Errorf("linked sign-in account = %s, want %s", got, pat)
	}
}

func seamPasswordMFA(ctx context.Context, t *testing.T, a *authApp, _ *fakeWorkOS) {
	t.Helper()

	pat := a.seed(ctx, t, "pat@lakeside.edu")
	a.hooks.set(func(h *hooks) {
		h.policy = func(*sessioninfo.NewSessionRequest) *sessionstorage.SignInDecision {
			return &sessionstorage.SignInDecision{Outcome: sessionstorage.RequireMFA}
		}
	})

	b := a.browser(t)
	b.prime(ctx)
	anonymous := b.sessionID(ctx)
	if status, mfa := b.passwordLogin(ctx, seedPassword); status != http.StatusOK || !mfa {
		t.Fatalf("password login = %d (mfaIsRequired %v), want 200 requiring MFA", status, mfa)
	}
	b.expect(ctx, http.StatusUnauthorized, http.MethodGet, "/whoami", nil)
	if body := b.expect(ctx, http.StatusOK, http.MethodGet, "/pending", nil); !strings.Contains(string(body), `"reason":"mfa"`) {
		t.Errorf("pending status = %s, want reason mfa", body)
	}
	replay := b.clone()

	b.expect(ctx, http.StatusNoContent, http.MethodPost, "/mfa", nil)
	v := b.view(ctx)
	if v.UserID != pat.String() || v.SessionID == anonymous {
		t.Errorf("session = %+v, want account %s under a session ID other than %s", v, pat, anonymous)
	}
	assertEventsSeen(t, v, "password", "email-otp")

	replay.expect(ctx, http.StatusUnauthorized, http.MethodPost, "/mfa", nil)
	replay.expect(ctx, http.StatusUnauthorized, http.MethodGet, "/whoami", nil)
}

func seamConfirmThenMFA(ctx context.Context, t *testing.T, a *authApp, workos *fakeWorkOS) {
	t.Helper()

	pat := a.seed(ctx, t, "pat@lakeside.edu")
	a.hooks.set(func(h *hooks) {
		h.resolve = func(*sessioninfo.NewSessionRequest) *sessionstorage.Resolution {
			return &sessionstorage.Resolution{Outcome: sessionstorage.RequireConfirmation, UserID: pat}
		}
		h.policy = func(req *sessioninfo.NewSessionRequest) *sessionstorage.SignInDecision {
			if req.Reason == sessioninfo.ReasonIdentityLinked {
				return &sessionstorage.SignInDecision{Outcome: sessionstorage.RequireMFA}
			}

			return &sessionstorage.SignInDecision{Outcome: sessionstorage.AllowSignIn}
		}
	})

	b := a.browser(t)
	b.prime(ctx)
	b.workOSSignIn(ctx, workos, "/", "idp_pat", "pat@lakeside.edu")
	if body := b.expect(ctx, http.StatusOK, http.MethodPost, "/pending/confirm", map[string]string{"password": seedPassword}); !strings.Contains(string(body), `"mfaIsRequired":true`) {
		t.Fatalf("confirm = %s, want mfaIsRequired true", body)
	}
	b.expect(ctx, http.StatusUnauthorized, http.MethodGet, "/whoami", nil)

	b.expect(ctx, http.StatusNoContent, http.MethodPost, "/mfa", nil)
	assertEventsSeen(t, b.view(ctx), "workos:"+lakesideConnection, "link-confirmation", "email-otp")
}

func seamWorkOSRefused(ctx context.Context, t *testing.T, a *authApp, workos *fakeWorkOS) {
	t.Helper()

	a.hooks.set(func(h *hooks) {
		h.resolve = func(*sessioninfo.NewSessionRequest) *sessionstorage.Resolution {
			return &sessionstorage.Resolution{Outcome: sessionstorage.RejectIdentity, Refusal: "not_invited"}
		}
	})

	b := a.browser(t)
	b.prime(ctx)
	assertRedirect(t, b.workOSSignIn(ctx, workos, "/dashboard", "idp_x", "x@lakeside.edu"), "/login", url.Values{"code": {"not_invited"}})
	b.expect(ctx, http.StatusUnauthorized, http.MethodGet, "/whoami", nil)
	b.expect(ctx, http.StatusNotFound, http.MethodGet, "/pending", nil)
}

func seamWorkOSLoginGuards(ctx context.Context, t *testing.T, a *authApp, _ *fakeWorkOS) {
	t.Helper()

	b := a.browser(t)
	for _, path := range []string{
		"/sso/login?organization=org_lakeside&returnUrl=" + url.QueryEscape("https://evil.example/"),
		"/sso/login?organization=org_lakeside&returnUrl=" + url.QueryEscape("//evil.example/"),
		"/sso/login?organization=org_lakeside&returnUrl=" + url.QueryEscape(`/\evil.example/`),
		"/sso/login",
	} {
		b.expect(ctx, http.StatusBadRequest, http.MethodGet, path, nil)
	}
}

func seamWorkOSCallbackBinding(ctx context.Context, t *testing.T, a *authApp, workos *fakeWorkOS) {
	t.Helper()

	b := a.browser(t)
	state := b.location(ctx, "/sso/login?organization=org_lakeside").Query().Get("state")

	code := workos.issue("idp_x", "x@lakeside.edu")
	assertRedirect(t, b.location(ctx, "/sso/callback?code="+code+"&state=forged"), "/login", url.Values{"code": {"invalid_state"}})

	stranger := a.browser(t)
	assertRedirect(t, stranger.location(ctx, "/sso/callback?code="+code+"&state="+url.QueryEscape(state)), "/login", url.Values{"code": {"no_oidc_cookie"}})
}

func seamDisabledAndImpersonation(ctx context.Context, t *testing.T, a *authApp, _ *fakeWorkOS) {
	t.Helper()

	pat := a.seed(ctx, t, "pat@lakeside.edu")
	bob := a.seed(ctx, t, "bob@lakeside.edu")

	b := a.browser(t)
	b.prime(ctx)
	b.passwordLogin(ctx, seedPassword)
	tab := b.clone()
	b.expect(ctx, http.StatusNoContent, http.MethodPost, "/impersonate", map[string]string{"user": "bob@lakeside.edu"})
	v := b.view(ctx)
	if v.UserID != bob.String() || v.Account != bob.String() {
		t.Errorf("impersonated session = %+v, want account %s", v, bob)
	}
	assertEventsSeen(t, v, "impersonation:pat@lakeside.edu")

	if _, err := a.db.Exec(ctx, `UPDATE "SessionUsers" SET "Disabled" = TRUE WHERE "Id" = $1`, pat); err != nil {
		t.Fatalf("disable pat: %v", err)
	}
	tab.expect(ctx, http.StatusUnauthorized, http.MethodGet, "/whoami", nil)
}
