package session

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"slices"
	"testing"
	"time"

	"github.com/cccteam/ccc"
	"github.com/cccteam/ccc/accesstypes"
	"github.com/cccteam/httpio"
	"github.com/cccteam/session/internal/basesession"
	internalcookie "github.com/cccteam/session/internal/cookie"
	"github.com/cccteam/session/internal/dbtype"
	"github.com/cccteam/session/sessioninfo"
	"github.com/google/go-cmp/cmp"
	gomock "go.uber.org/mock/gomock"
)

// The public session types satisfy basesession.Handlers by delegating to their
// BaseSession. The compile-time assertions check signatures, not targets: several
// handlers share a signature (EnforceReadOnlyMask and ValidateXSRFToken; EndImpersonation,
// Logout and Authenticated), so a delegate forwarded to the wrong base method compiles
// and passes every unit test of the base. This file drives every handler, middleware and
// impersonation API on every public type, through real cookies and a mocked store, and
// asserts the effect a caller would observe.

// storeRecorder is the slice of the generated store mock recorders these scenarios
// set expectations on. Every store mock's recorder satisfies it.
type storeRecorder interface {
	ImpersonationEnabled() *gomock.Call
	Session(ctx, sessionID any) *gomock.Call
	DestroySession(ctx, sessionID any) *gomock.Call
	DestroyImpersonatedSession(ctx, sessionID, reason any) *gomock.Call
}

// sessionAPI is the impersonation surface of the four API types that this file
// exercises directly.
type sessionAPI interface {
	EndImpersonation(ctx context.Context, w http.ResponseWriter) (restored bool, err error)
}

// surface is one public session type under test.
type surface struct {
	handlers basesession.Handlers
	api      sessionAPI
	base     *basesession.BaseSession
	store    storeRecorder
	// validating adds the store expectations the type makes, beyond Session(), when it
	// validates a session for username.
	validating func(username string)
	// startImpersonated calls the type's StartImpersonatedSession without custom data.
	startImpersonated func(ctx context.Context, w http.ResponseWriter, req *ImpersonationRequest) error
}

type surfaceBuilder func(t *testing.T, ctrl *gomock.Controller, hook ImpersonationAuditHook) *surface

func surfaceBuilders() []struct {
	name  string
	build surfaceBuilder
} {
	userID := ccc.Must(ccc.NewUUID())

	return []struct {
		name  string
		build surfaceBuilder
	}{
		{
			name: "PasswordAuth",
			build: func(t *testing.T, ctrl *gomock.Controller, hook ImpersonationAuditHook) *surface {
				storage := newPasswordStoreMock(ctrl)
				p, err := NewPasswordAuth[NoCustomData, NoCustomData](storage, cookieKey, WithImpersonationAudit(hook))
				if err != nil {
					t.Fatalf("NewPasswordAuth() error = %v", err)
				}

				return &surface{
					handlers: p,
					api:      p.API(),
					base:     p.baseSession,
					store:    storage.EXPECT(),
					validating: func(username string) {
						storage.EXPECT().UserByUserName(gomock.Any(), username).Return(&dbtype.SessionUser{ID: userID, Username: username}, nil).AnyTimes()
					},
					startImpersonated: func(ctx context.Context, w http.ResponseWriter, req *ImpersonationRequest) error {
						_, err := p.API().StartImpersonatedSession(ctx, w, req)

						return err
					},
				}
			},
		},
		{
			name: "Preauth",
			build: func(t *testing.T, ctrl *gomock.Controller, hook ImpersonationAuditHook) *surface {
				storage := newPreauthStoreMock(ctrl)
				p, err := NewPreauth[NoCustomData](storage, cookieKey, WithImpersonationAudit(hook))
				if err != nil {
					t.Fatalf("NewPreauth() error = %v", err)
				}

				return &surface{
					handlers:   p,
					api:        p.API(),
					base:       p.baseSession,
					store:      storage.EXPECT(),
					validating: func(string) {},
					startImpersonated: func(ctx context.Context, w http.ResponseWriter, req *ImpersonationRequest) error {
						_, err := p.API().StartImpersonatedSession(ctx, w, req)

						return err
					},
				}
			},
		},
		{
			name: "OIDCAzure",
			build: func(t *testing.T, ctrl *gomock.Controller, hook ImpersonationAuditHook) *surface {
				storage := newOIDCStoreMock(ctrl)
				a, err := NewOIDCAzure[NoCustomData, NoCustomData](storage, DisableRoleSync(), cookieKey, "issuerURL", "clientID", "clientSecret", "redirectURL", WithImpersonationAudit(hook))
				if err != nil {
					t.Fatalf("NewOIDCAzure() error = %v", err)
				}

				return &surface{
					handlers:   a,
					api:        a.API(),
					base:       a.baseSession,
					store:      storage.EXPECT(),
					validating: func(string) {},
					startImpersonated: func(ctx context.Context, w http.ResponseWriter, req *ImpersonationRequest) error {
						_, err := a.API().StartImpersonatedSession(ctx, w, req)

						return err
					},
				}
			},
		},
		{
			name: "OIDCGoogle",
			build: func(t *testing.T, ctrl *gomock.Controller, hook ImpersonationAuditHook) *surface {
				storage := newGoogleOIDCStoreMock(ctrl)
				g, err := NewOIDCGoogle[NoCustomData, NoCustomData](storage, DisableRoleSync(), cookieKey, "clientID", "clientSecret", "redirectURL", "example.com", WithImpersonationAudit(hook))
				if err != nil {
					t.Fatalf("NewOIDCGoogle() error = %v", err)
				}

				return &surface{
					handlers:   g,
					api:        g.API(),
					base:       g.baseSession,
					store:      storage.EXPECT(),
					validating: func(string) {},
					startImpersonated: func(ctx context.Context, w http.ResponseWriter, req *ImpersonationRequest) error {
						_, err := g.API().StartImpersonatedSession(ctx, w, req)

						return err
					},
				}
			},
		},
	}
}

// surfaceScenario drives one handler on a built surface and asserts its effect. events
// collects the impersonation events the type announced.
type surfaceScenario struct {
	name string
	run  func(t *testing.T, s *surface, events *[]sessioninfo.ImpersonationEventKind)
}

// Fixtures shared by the scenarios below.
var (
	surfaceSessionID = ccc.Must(ccc.NewUUID())
	surfaceSourceID  = ccc.Must(ccc.NewUUID())
	surfaceReadOnly  = accesstypes.MaskPermissions(accesstypes.DenyAll(), accesstypes.List, accesstypes.Read)
)

// requestWithSession is a request whose context carries a started session ID.
func requestWithSession(method string) *http.Request {
	ctx := context.WithValue(context.Background(), sessioninfo.CTXSessionID, surfaceSessionID)

	return httptest.NewRequestWithContext(ctx, method, "/resource", http.NoBody)
}

// requestAs is a request whose context carries a validated session, impersonated when imp is not nil.
func requestAs(method, username string, imp *sessioninfo.Impersonation) *http.Request {
	return httptest.NewRequestWithContext(impersonatedCtx(surfaceSessionID, username, imp), method, "/resource", http.NoBody)
}

// liveImpersonation is a read-only user-principal impersonation held by a foreign actor.
func liveImpersonation() *sessioninfo.Impersonation {
	return &sessioninfo.Impersonation{SessionID: surfaceSessionID, Actor: "alice", ActorRealm: "admin-portal", Principal: accesstypes.UserPrincipal("bob"), Mask: surfaceReadOnly, ExpiresAt: time.Now().Add(time.Hour)}
}

// localActorImpersonation is a role-principal impersonation by a local actor with a source session.
func localActorImpersonation() *sessioninfo.Impersonation {
	return &sessioninfo.Impersonation{SessionID: surfaceSessionID, Actor: "alice", SourceSessionID: ccc.NullUUID{UUID: surfaceSourceID, Valid: true}, Principal: accesstypes.RolePrincipal("Editor"), ExpiresAt: time.Now().Add(time.Hour)}
}

// nextRecorder is a terminal handler that records whether it ran and the context it saw.
type nextRecorder struct {
	called bool
	ctx    context.Context
}

func (rec *nextRecorder) handler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		rec.called = true
		rec.ctx = r.Context()
		w.WriteHeader(http.StatusNoContent)
	})
}

func hasCookie(rr *httptest.ResponseRecorder, name string) bool {
	for _, c := range rr.Result().Cookies() {
		if c.Name == name {
			return true
		}
	}

	return false
}

func assertEvents(t *testing.T, want, got []sessioninfo.ImpersonationEventKind) {
	t.Helper()

	if diff := cmp.Diff(want, got); diff != "" {
		t.Errorf("events mismatch (-want +got):\n%s", diff)
	}
}

// sessionScenarios cover the session lifecycle middleware and handlers.
func sessionScenarios() []surfaceScenario {
	sessionID := surfaceSessionID

	return []surfaceScenario{
		{
			name: "StartSession without a cookie starts a new session and sets the auth cookie",
			run: func(t *testing.T, s *surface, _ *[]sessioninfo.ImpersonationEventKind) {
				rec := &nextRecorder{}
				rr := httptest.NewRecorder()
				s.handlers.StartSession(rec.handler()).ServeHTTP(rr, httptest.NewRequestWithContext(context.Background(), http.MethodGet, "/resource", http.NoBody))

				if !rec.called {
					t.Fatalf("next not called: status %d %s", rr.Code, rr.Body.String())
				}
				if id := sessioninfo.IDFromCtx(rec.ctx); id == ccc.NilUUID {
					t.Error("no session ID in the context")
				}
				if !hasCookie(rr, internalcookie.AuthCookieName) {
					t.Error("auth cookie not set")
				}
			},
		},
		{
			name: "ValidateSession admits a live session and exposes it to the handler",
			run: func(t *testing.T, s *surface, _ *[]sessioninfo.ImpersonationEventKind) {
				s.store.Session(gomock.Any(), sessionID).Return(liveSession(sessionID, "alice"), nil)
				s.validating("alice")

				rec := &nextRecorder{}
				rr := httptest.NewRecorder()
				s.handlers.ValidateSession(rec.handler()).ServeHTTP(rr, requestWithSession(http.MethodGet))

				if !rec.called {
					t.Fatalf("next not called: status %d %s", rr.Code, rr.Body.String())
				}
				if got := sessioninfo.FromCtx(rec.ctx).Username; got != "alice" {
					t.Errorf("session username in context = %q, want alice", got)
				}
			},
		},
		{
			name: "ValidateSession refuses an impersonated session whose record has ended",
			run: func(t *testing.T, s *surface, _ *[]sessioninfo.ImpersonationEventKind) {
				imp := liveImpersonation()
				ended := time.Now()
				imp.EndedAt = &ended
				imp.EndReason = sessioninfo.ImpersonationEndedByRelease
				s.store.Session(gomock.Any(), sessionID).Return(&sessioninfo.SessionData{SessionInfo: &sessioninfo.SessionInfo{ID: sessionID, Username: "bob", UpdatedAt: time.Now()}, Impersonation: imp}, nil)

				rec := &nextRecorder{}
				rr := httptest.NewRecorder()
				s.handlers.ValidateSession(rec.handler()).ServeHTTP(rr, requestWithSession(http.MethodGet))

				if rec.called || rr.Code != http.StatusUnauthorized {
					t.Errorf("next called = %v, status = %d; want not called, 401", rec.called, rr.Code)
				}
			},
		},
		{
			name: "Authenticated reports the validated session",
			run: func(t *testing.T, s *surface, _ *[]sessioninfo.ImpersonationEventKind) {
				s.store.Session(gomock.Any(), sessionID).Return(liveSession(sessionID, "alice"), nil)
				s.validating("alice")

				rr := httptest.NewRecorder()
				s.handlers.Authenticated().ServeHTTP(rr, requestWithSession(http.MethodGet))

				var body struct {
					Authenticated bool   `json:"authenticated"`
					Username      string `json:"username"`
				}
				if err := json.Unmarshal(rr.Body.Bytes(), &body); err != nil {
					t.Fatalf("json.Unmarshal() error = %v: %s", err, rr.Body.String())
				}
				if !body.Authenticated || body.Username != "alice" {
					t.Errorf("body = %+v, want authenticated as alice", body)
				}
			},
		},
	}
}

// impersonationScenarios cover the read-only mask, the two ends of an impersonated
// session, and the establishing guard.
func impersonationScenarios() []surfaceScenario {
	sessionID := surfaceSessionID

	return []surfaceScenario{
		{
			name: "EnforceReadOnlyMask refuses a write from a read-only session",
			run: func(t *testing.T, s *surface, events *[]sessioninfo.ImpersonationEventKind) {
				rec := &nextRecorder{}
				rr := httptest.NewRecorder()
				s.handlers.EnforceReadOnlyMask(rec.handler()).ServeHTTP(rr, requestAs(http.MethodPost, "bob", liveImpersonation()))

				if rec.called || rr.Code != http.StatusForbidden {
					t.Errorf("next called = %v, status = %d; want not called, 403", rec.called, rr.Code)
				}
				assertEvents(t, []sessioninfo.ImpersonationEventKind{sessioninfo.ImpersonationWriteBlocked}, *events)
			},
		},
		{
			name: "EnforceReadOnlyMask passes a read from a read-only session",
			run: func(t *testing.T, s *surface, events *[]sessioninfo.ImpersonationEventKind) {
				rec := &nextRecorder{}
				rr := httptest.NewRecorder()
				s.handlers.EnforceReadOnlyMask(rec.handler()).ServeHTTP(rr, requestAs(http.MethodGet, "bob", liveImpersonation()))

				if !rec.called {
					t.Errorf("next not called: status %d %s", rr.Code, rr.Body.String())
				}
				if len(*events) != 0 {
					t.Errorf("events = %v, want none", *events)
				}
			},
		},
		{
			name: "EndImpersonation ends the session Released and returns a local actor to their source session",
			run: func(t *testing.T, s *surface, events *[]sessioninfo.ImpersonationEventKind) {
				s.store.DestroyImpersonatedSession(gomock.Any(), sessionID, sessioninfo.ImpersonationEndedByRelease).Return(nil)
				s.store.Session(gomock.Any(), surfaceSourceID).Return(liveSession(surfaceSourceID, "alice"), nil)

				rr := httptest.NewRecorder()
				s.handlers.EndImpersonation().ServeHTTP(rr, requestAs(http.MethodPost, "alice", localActorImpersonation()))

				if rr.Code != http.StatusOK {
					t.Fatalf("status = %d, want 200: %s", rr.Code, rr.Body.String())
				}
				var body basesession.EndImpersonationResponse
				if err := json.Unmarshal(rr.Body.Bytes(), &body); err != nil {
					t.Fatalf("json.Unmarshal() error = %v", err)
				}
				if !body.Restored {
					t.Error("Restored = false, want true")
				}
				if !hasCookie(rr, internalcookie.AuthCookieName) || !hasCookie(rr, internalcookie.XSRFCookieName) {
					t.Error("the source session's auth and XSRF cookies were not set")
				}
				assertEvents(t, []sessioninfo.ImpersonationEventKind{sessioninfo.ImpersonationEnded}, *events)
			},
		},
		{
			name: "Logout destroys the session and announces an impersonation's end",
			run: func(t *testing.T, s *surface, events *[]sessioninfo.ImpersonationEventKind) {
				s.store.DestroySession(gomock.Any(), sessionID).Return(nil)

				rr := httptest.NewRecorder()
				s.handlers.Logout().ServeHTTP(rr, requestAs(http.MethodPost, "bob", liveImpersonation()))

				if rr.Code != http.StatusOK {
					t.Errorf("status = %d, want 200: %s", rr.Code, rr.Body.String())
				}
				assertEvents(t, []sessioninfo.ImpersonationEventKind{sessioninfo.ImpersonationEnded}, *events)
			},
		},
		{
			name: "the API's EndImpersonation ends the session Released and reports no restore for a foreign actor",
			run: func(t *testing.T, s *surface, events *[]sessioninfo.ImpersonationEventKind) {
				s.store.DestroyImpersonatedSession(gomock.Any(), sessionID, sessioninfo.ImpersonationEndedByRelease).Return(nil)

				restored, err := s.api.EndImpersonation(impersonatedCtx(sessionID, "bob", liveImpersonation()), httptest.NewRecorder())
				if err != nil {
					t.Fatalf("EndImpersonation() error = %v", err)
				}
				if restored {
					t.Error("restored = true, want false for a foreign actor")
				}
				assertEvents(t, []sessioninfo.ImpersonationEventKind{sessioninfo.ImpersonationEnded}, *events)
			},
		},
		{
			name: "StartImpersonatedSession refuses an impersonated session as the caller",
			run: func(t *testing.T, s *surface, _ *[]sessioninfo.ImpersonationEventKind) {
				s.store.ImpersonationEnabled().Return(true)

				req := &ImpersonationRequest{Actor: "bob", Principal: accesstypes.RolePrincipal("Editor")}
				err := s.startImpersonated(impersonatedCtx(sessionID, "bob", liveImpersonation()), httptest.NewRecorder(), req)
				if !httpio.HasForbidden(err) {
					t.Errorf("StartImpersonatedSession() error = %v, want Forbidden", err)
				}
			},
		},
	}
}

func TestSessionTypes_PublicSurface(t *testing.T) {
	t.Parallel()

	scenarios := slices.Concat(sessionScenarios(), impersonationScenarios(), xsrfScenarios())

	for _, tb := range surfaceBuilders() {
		for _, sc := range scenarios {
			t.Run(tb.name+"/"+sc.name, func(t *testing.T) {
				t.Parallel()
				ctrl := gomock.NewController(t)

				var events []sessioninfo.ImpersonationEventKind
				s := tb.build(t, ctrl, hookOrRecorder(nil, &events))
				sc.run(t, s, &events)
			})
		}
	}
}

// xsrfScenarios cover the XSRF middleware pair with real tokens.
func xsrfScenarios() []surfaceScenario {
	sessionID := surfaceSessionID

	return []surfaceScenario{
		{
			name: "ValidateXSRFToken refuses a write without a token",
			run: func(t *testing.T, s *surface, _ *[]sessioninfo.ImpersonationEventKind) {
				rec := &nextRecorder{}
				rr := httptest.NewRecorder()
				s.handlers.ValidateXSRFToken(rec.handler()).ServeHTTP(rr, requestWithSession(http.MethodPost))

				if rec.called || rr.Code != http.StatusForbidden {
					t.Errorf("next called = %v, status = %d; want not called, 403", rec.called, rr.Code)
				}
			},
		},
		{
			name: "ValidateXSRFToken admits a write carrying the session's token in cookie and header",
			run: func(t *testing.T, s *surface, _ *[]sessioninfo.ImpersonationEventKind) {
				issued := httptest.NewRecorder()
				s.base.CookieHandler.CreateXSRFTokenCookie(issued, sessionID)
				r := requestWithSession(http.MethodPost)
				for _, c := range issued.Result().Cookies() {
					r.AddCookie(c)
					if c.Name == internalcookie.XSRFCookieName {
						r.Header.Set(internalcookie.XSRFHeaderName, c.Value)
					}
				}

				rec := &nextRecorder{}
				rr := httptest.NewRecorder()
				s.handlers.ValidateXSRFToken(rec.handler()).ServeHTTP(rr, r)

				if !rec.called {
					t.Errorf("next not called: status %d %s", rr.Code, rr.Body.String())
				}
			},
		},
		{
			name: "SetXSRFToken issues the token cookie on a read that lacks it",
			run: func(t *testing.T, s *surface, _ *[]sessioninfo.ImpersonationEventKind) {
				rec := &nextRecorder{}
				rr := httptest.NewRecorder()
				s.handlers.SetXSRFToken(rec.handler()).ServeHTTP(rr, requestWithSession(http.MethodGet))

				if !rec.called {
					t.Errorf("next not called: status %d %s", rr.Code, rr.Body.String())
				}
				if !hasCookie(rr, internalcookie.XSRFCookieName) {
					t.Error("XSRF cookie not set")
				}
			},
		},
		{
			name: "SetXSRFToken redirects a write that lacks the token so it retries with the cookie",
			run: func(t *testing.T, s *surface, _ *[]sessioninfo.ImpersonationEventKind) {
				rec := &nextRecorder{}
				rr := httptest.NewRecorder()
				s.handlers.SetXSRFToken(rec.handler()).ServeHTTP(rr, requestWithSession(http.MethodPost))

				if rec.called || rr.Code != http.StatusTemporaryRedirect {
					t.Errorf("next called = %v, status = %d; want not called, 307", rec.called, rr.Code)
				}
			},
		},
	}
}
