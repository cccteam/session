package e2e

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"net/url"
	"testing"
	"time"

	"github.com/cccteam/ccc"
	"github.com/cccteam/ccc/accesstypes"
	dbinitiator "github.com/cccteam/db-initiator"
	"github.com/cccteam/httpio"
	"github.com/cccteam/session"
	"github.com/cccteam/session/sessioninfo"
	"github.com/cccteam/session/sessionstorage"
	"github.com/go-chi/chi/v5"
)

const cookieKey = "Rsgb6WsDvBsMQ5IJr2WJjVLCPO+o9WW6SdVktdaaq9O0WFA0Hc/EmJeOwCGV6LIqG8ue3iSZ/lycpv8ZNKvWjWU42hZnlO15vYANZG89R1ncjmu4KStldFuP/r0RFhZa"

// The XSRF cookie and header names the cookie client uses by default.
const (
	xsrfCookieName = "XSRF-TOKEN"
	xsrfHeaderName = "X-XSRF-TOKEN"
)

// app is the application under test: Preauth over PostgreSQL with impersonation, on the
// routes the README prescribes. Preauth is the thinnest type, so what these scenarios
// prove is the shared machinery, not one type's identity rules.
type app struct {
	db     *dbinitiator.PostgresDatabase
	server *httptest.Server
}

// impersonateRequest is the body of POST /impersonate.
type impersonateRequest struct {
	User          string `json:"user"`
	ReadOnly      bool   `json:"readOnly"`
	MaxDurationMS int    `json:"maxDurationMs"`
}

func newApp(ctx context.Context, t *testing.T) *app {
	t.Helper()

	db := prepareDatabase(ctx, t)

	table, err := sessionstorage.NewImpersonationTable("SessionImpersonations")
	if err != nil {
		t.Fatalf("sessionstorage.NewImpersonationTable() error = %v", err)
	}
	store := sessionstorage.NewPostgresPreauth(db.Pool, sessionstorage.WithImpersonation(table))
	auth, err := session.NewPreauth[session.NoCustomData](store, cookieKey)
	if err != nil {
		t.Fatalf("session.NewPreauth() error = %v", err)
	}
	api := auth.API()

	ok := func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusNoContent) }

	r := chi.NewRouter()
	r.Use(auth.StartSession)
	r.Post("/login", func(w http.ResponseWriter, r *http.Request) {
		var body struct {
			Username string `json:"username"`
		}
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)

			return
		}
		if _, err := api.Login(r.Context(), w, body.Username); err != nil {
			_ = httpio.NewEncoder(w).ClientMessage(r.Context(), err)

			return
		}
		w.WriteHeader(http.StatusNoContent)
	})
	r.Get("/authenticated", auth.Authenticated())

	r.Group(func(r chi.Router) {
		r.Use(auth.ValidateSession, auth.ValidateXSRFToken)

		r.Post("/impersonation/end", auth.EndImpersonation())
		r.Post("/logout", auth.Logout())
		r.Post("/impersonate", func(w http.ResponseWriter, r *http.Request) {
			var body impersonateRequest
			if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
				http.Error(w, err.Error(), http.StatusBadRequest)

				return
			}
			req := &session.ImpersonationRequest{
				// The actor is whoever holds the validated session; the source session
				// defaults to it.
				Actor:       sessioninfo.FromCtx(r.Context()).Username,
				Principal:   accesstypes.UserPrincipal(accesstypes.User(body.User)),
				MaxDuration: time.Duration(body.MaxDurationMS) * time.Millisecond,
			}
			if body.ReadOnly {
				req.Mask = accesstypes.MaskPermissions(accesstypes.DenyAll(), accesstypes.List, accesstypes.Read)
			}
			id, err := api.StartImpersonatedSession(r.Context(), w, req)
			if err != nil {
				_ = httpio.NewEncoder(w).ClientMessage(r.Context(), err)

				return
			}
			_ = httpio.NewEncoder(w).Ok(map[string]string{"sessionId": id.String()})
		})

		// The operator's surface. Who may call these is the application's guard; here
		// anyone validated may, which is what the scenarios need.
		r.Get("/admin/impersonations", func(w http.ResponseWriter, r *http.Request) {
			imps, err := api.ActiveImpersonations(r.Context(), nil)
			if err != nil {
				_ = httpio.NewEncoder(w).ClientMessage(r.Context(), err)

				return
			}
			ids := make([]string, 0, len(imps))
			for _, imp := range imps {
				ids = append(ids, imp.SessionID.String())
			}
			_ = httpio.NewEncoder(w).Ok(ids)
		})
		r.Post("/admin/revoke", func(w http.ResponseWriter, r *http.Request) {
			var body struct {
				SessionID string `json:"sessionId"`
			}
			if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
				http.Error(w, err.Error(), http.StatusBadRequest)

				return
			}
			id, err := ccc.UUIDFromString(body.SessionID)
			if err != nil {
				http.Error(w, err.Error(), http.StatusBadRequest)

				return
			}
			if err := api.DestroyImpersonatedSession(r.Context(), id); err != nil {
				_ = httpio.NewEncoder(w).ClientMessage(r.Context(), err)

				return
			}
			w.WriteHeader(http.StatusNoContent)
		})
		r.Post("/admin/destroy-all", func(w http.ResponseWriter, r *http.Request) {
			var body struct {
				Username string `json:"username"`
			}
			if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
				http.Error(w, err.Error(), http.StatusBadRequest)

				return
			}
			if err := api.DestroyAllUserSessions(r.Context(), body.Username); err != nil {
				_ = httpio.NewEncoder(w).ClientMessage(r.Context(), err)

				return
			}
			w.WriteHeader(http.StatusNoContent)
		})

		// Application resources sit behind the read-only backstop as well.
		r.Group(func(r chi.Router) {
			r.Use(auth.EnforceReadOnlyMask)
			r.Get("/resource", ok)
			r.Post("/resource", ok)
		})
	})

	// TLS, because the auth cookies are Secure and a jar only sends them over https.
	server := httptest.NewTLSServer(r)
	t.Cleanup(server.Close)

	return &app{db: db, server: server}
}

// browser is one user agent: a cookie jar, and the XSRF header a frontend derives from
// the XSRF cookie on every non-safe request.
type browser struct {
	t      *testing.T
	client *http.Client
	base   *url.URL
}

func (a *app) browser(t *testing.T) *browser {
	t.Helper()

	jar, err := cookiejar.New(nil)
	if err != nil {
		t.Fatalf("cookiejar.New() error = %v", err)
	}
	// The server hands out one shared *http.Client; each browser needs its own jar, so
	// copy the client and share only its transport.
	client := *a.server.Client()
	client.Jar = jar
	client.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	base, err := url.Parse(a.server.URL)
	if err != nil {
		t.Fatalf("url.Parse() error = %v", err)
	}

	return &browser{t: t, client: &client, base: base}
}

// clone is a second user agent holding copies of this one's cookies: the same login in
// another tab, whose cookies then diverge.
func (b *browser) clone() *browser {
	b.t.Helper()

	jar, err := cookiejar.New(nil)
	if err != nil {
		b.t.Fatalf("cookiejar.New() error = %v", err)
	}
	jar.SetCookies(b.base, b.client.Jar.Cookies(b.base))
	client := *b.client
	client.Jar = jar

	return &browser{t: b.t, client: &client, base: b.base}
}

// xsrfToken is the current XSRF cookie value, or "" when none is held.
func (b *browser) xsrfToken() string {
	for _, c := range b.client.Jar.Cookies(b.base) {
		if c.Name == xsrfCookieName {
			return c.Value
		}
	}

	return ""
}

// do sends a request with the jar's cookies and, for a non-safe method, the XSRF header
// taken from the jar unless the caller pins one. It returns the status and the body.
func (b *browser) do(ctx context.Context, method, path string, body any, xsrfHeader ...string) (status int, response []byte) {
	b.t.Helper()

	var payload io.Reader = http.NoBody
	if body != nil {
		buf, err := json.Marshal(body)
		if err != nil {
			b.t.Fatalf("json.Marshal() error = %v", err)
		}
		payload = bytes.NewReader(buf)
	}
	req, err := http.NewRequestWithContext(ctx, method, b.base.String()+path, payload)
	if err != nil {
		b.t.Fatalf("http.NewRequestWithContext() error = %v", err)
	}
	req.Header.Set("Content-Type", "application/json")
	if method != http.MethodGet && method != http.MethodHead {
		token := b.xsrfToken()
		if len(xsrfHeader) == 1 {
			token = xsrfHeader[0]
		}
		req.Header.Set(xsrfHeaderName, token)
	}

	resp, err := b.client.Do(req)
	if err != nil {
		b.t.Fatalf("http.Client.Do(%s %s) error = %v", method, path, err)
	}
	defer resp.Body.Close()
	got, err := io.ReadAll(resp.Body)
	if err != nil {
		b.t.Fatalf("io.ReadAll() error = %v", err)
	}

	return resp.StatusCode, got
}

// expect sends the request and fails the test unless the status matches.
func (b *browser) expect(ctx context.Context, want int, method, path string, body any, xsrfHeader ...string) []byte {
	b.t.Helper()

	status, got := b.do(ctx, method, path, body, xsrfHeader...)
	if status != want {
		b.t.Fatalf("%s %s = %d, want %d: %s", method, path, status, want, got)
	}

	return got
}

func (b *browser) login(ctx context.Context, username string) {
	b.t.Helper()
	b.expect(ctx, http.StatusNoContent, http.MethodPost, "/login", map[string]string{"username": username})
}

// impersonate establishes an impersonated session and returns its ID.
func (b *browser) impersonate(ctx context.Context, req impersonateRequest) ccc.UUID {
	b.t.Helper()

	var body struct {
		SessionID string `json:"sessionId"`
	}
	if err := json.Unmarshal(b.expect(ctx, http.StatusOK, http.MethodPost, "/impersonate", req), &body); err != nil {
		b.t.Fatalf("json.Unmarshal() error = %v", err)
	}

	return ccc.Must(ccc.UUIDFromString(body.SessionID))
}

// whoami decodes GET /authenticated.
func (b *browser) whoami(ctx context.Context) (authenticated bool, username string, impersonated bool) {
	b.t.Helper()

	var body struct {
		Authenticated bool            `json:"authenticated"`
		Username      string          `json:"username"`
		Impersonation json.RawMessage `json:"impersonation"`
	}
	if err := json.Unmarshal(b.expect(ctx, http.StatusOK, http.MethodGet, "/authenticated", nil), &body); err != nil {
		b.t.Fatalf("json.Unmarshal() error = %v", err)
	}

	return body.Authenticated, body.Username, len(body.Impersonation) > 0 && string(body.Impersonation) != "null"
}

// activeImpersonations decodes GET /admin/impersonations.
func (b *browser) activeImpersonations(ctx context.Context) []string {
	b.t.Helper()

	var ids []string
	if err := json.Unmarshal(b.expect(ctx, http.StatusOK, http.MethodGet, "/admin/impersonations", nil), &ids); err != nil {
		b.t.Fatalf("json.Unmarshal() error = %v", err)
	}

	return ids
}

// endReason reads the record's end reason straight from the table; "" while it is live.
func (a *app) endReason(ctx context.Context, t *testing.T, sessionID ccc.UUID) string {
	t.Helper()

	var reason *string
	if err := a.db.QueryRow(ctx, `SELECT "EndReason" FROM "SessionImpersonations" WHERE "SessionId" = $1`, sessionID).Scan(&reason); err != nil {
		t.Fatalf("QueryRow().Scan() error = %v", err)
	}
	if reason == nil {
		return ""
	}

	return *reason
}

func assertIdentity(ctx context.Context, t *testing.T, b *browser, wantUser string, wantImpersonated bool) {
	t.Helper()

	authenticated, username, impersonated := b.whoami(ctx)
	if !authenticated || username != wantUser || impersonated != wantImpersonated {
		t.Errorf("authenticated = (%v, %q, impersonated %v), want (true, %q, %v)", authenticated, username, impersonated, wantUser, wantImpersonated)
	}
}

func TestSeams(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		run  func(ctx context.Context, t *testing.T, a *app)
	}{
		{
			name: "a read-only impersonation cannot write, ends Released back to the actor, and its cookie is dead afterwards",
			run: func(ctx context.Context, t *testing.T, a *app) {
				alice := a.browser(t)
				alice.login(ctx, "alice")
				alice.expect(ctx, http.StatusNoContent, http.MethodPost, "/resource", nil)

				id := alice.impersonate(ctx, impersonateRequest{User: "bob", ReadOnly: true})
				assertIdentity(ctx, t, alice, "bob", true)
				alice.expect(ctx, http.StatusNoContent, http.MethodGet, "/resource", nil)
				alice.expect(ctx, http.StatusForbidden, http.MethodPost, "/resource", nil)

				replay := alice.clone()
				alice.expect(ctx, http.StatusOK, http.MethodPost, "/impersonation/end", nil)
				assertIdentity(ctx, t, alice, "alice", false)
				if got := a.endReason(ctx, t, id); got != "Released" {
					t.Errorf("EndReason = %q, want Released", got)
				}

				// The impersonated cookie, replayed after the end, opens nothing.
				replay.expect(ctx, http.StatusUnauthorized, http.MethodGet, "/resource", nil)
			},
		},
		{
			name: "an operator revokes an impersonation: its next request is refused and the listing no longer shows it",
			run: func(ctx context.Context, t *testing.T, a *app) {
				alice := a.browser(t)
				alice.login(ctx, "alice")
				id := alice.impersonate(ctx, impersonateRequest{User: "bob"})
				alice.expect(ctx, http.StatusNoContent, http.MethodPost, "/resource", nil)

				operator := a.browser(t)
				operator.login(ctx, "root")
				if ids := operator.activeImpersonations(ctx); len(ids) != 1 || ids[0] != id.String() {
					t.Fatalf("active impersonations = %v, want [%s]", ids, id)
				}
				operator.expect(ctx, http.StatusNoContent, http.MethodPost, "/admin/revoke", map[string]string{"sessionId": id.String()})
				alice.expect(ctx, http.StatusUnauthorized, http.MethodGet, "/resource", nil)
				if ids := operator.activeImpersonations(ctx); len(ids) != 0 {
					t.Errorf("active impersonations after revoke = %v, want none", ids)
				}
				if got := a.endReason(ctx, t, id); got != "Revoked" {
					t.Errorf("EndReason = %q, want Revoked", got)
				}
			},
		},
		{
			name: "destroying the actor's sessions ends their own session and every impersonation they hold as Revoked",
			run: func(ctx context.Context, t *testing.T, a *app) {
				alice := a.browser(t)
				alice.login(ctx, "alice")
				tab := alice.clone()
				id := tab.impersonate(ctx, impersonateRequest{User: "carol"})
				tab.expect(ctx, http.StatusNoContent, http.MethodGet, "/resource", nil)

				operator := a.browser(t)
				operator.login(ctx, "root")
				operator.expect(ctx, http.StatusNoContent, http.MethodPost, "/admin/destroy-all", map[string]string{"username": "alice"})

				alice.expect(ctx, http.StatusUnauthorized, http.MethodGet, "/resource", nil)
				tab.expect(ctx, http.StatusUnauthorized, http.MethodGet, "/resource", nil)
				if got := a.endReason(ctx, t, id); got != "Revoked" {
					t.Errorf("EndReason = %q, want Revoked", got)
				}
			},
		},
		{
			name: "the hard cap refuses the session's next request and ends the record Expired",
			run: func(ctx context.Context, t *testing.T, a *app) {
				alice := a.browser(t)
				alice.login(ctx, "alice")
				id := alice.impersonate(ctx, impersonateRequest{User: "bob", MaxDurationMS: 1})
				time.Sleep(20 * time.Millisecond)

				alice.expect(ctx, http.StatusUnauthorized, http.MethodGet, "/resource", nil)
				if got := a.endReason(ctx, t, id); got != "Expired" {
					t.Errorf("EndReason = %q, want Expired", got)
				}
			},
		},
		{
			name: "an impersonated session cannot impersonate",
			run: func(ctx context.Context, t *testing.T, a *app) {
				alice := a.browser(t)
				alice.login(ctx, "alice")
				alice.impersonate(ctx, impersonateRequest{User: "bob"})

				alice.expect(ctx, http.StatusForbidden, http.MethodPost, "/impersonate", impersonateRequest{User: "carol"})
			},
		},
		{
			name: "the actor's XSRF token is refused on the impersonated session, whose own token is accepted",
			run: func(ctx context.Context, t *testing.T, a *app) {
				alice := a.browser(t)
				alice.login(ctx, "alice")
				actorToken := alice.xsrfToken()
				alice.impersonate(ctx, impersonateRequest{User: "bob"})

				alice.expect(ctx, http.StatusForbidden, http.MethodPost, "/resource", nil, actorToken)
				alice.expect(ctx, http.StatusNoContent, http.MethodPost, "/resource", nil)
			},
		},
		{
			name: "logout ends an impersonated session with reason Logout and its cookie is dead afterwards",
			run: func(ctx context.Context, t *testing.T, a *app) {
				alice := a.browser(t)
				alice.login(ctx, "alice")
				id := alice.impersonate(ctx, impersonateRequest{User: "bob"})
				replay := alice.clone()

				alice.expect(ctx, http.StatusOK, http.MethodPost, "/logout", nil)
				replay.expect(ctx, http.StatusUnauthorized, http.MethodGet, "/resource", nil)
				if got := a.endReason(ctx, t, id); got != "Logout" {
					t.Errorf("EndReason = %q, want Logout", got)
				}
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			ctx := t.Context()

			tt.run(ctx, t, newApp(ctx, t))
		})
	}
}
