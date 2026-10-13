package session

import (
	"context"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/cccteam/ccc"
	"github.com/cccteam/ccc/accesstypes"
	"github.com/cccteam/httpio"
	"github.com/cccteam/session/cookie"
	"github.com/cccteam/session/internal/basesession"
	"github.com/cccteam/session/mock/mock_cookie"
	"github.com/cccteam/session/sessioninfo"
	"github.com/cccteam/session/sessionstorage/mock/mock_sessionstorage"
	"github.com/go-playground/errors/v5"
	"github.com/google/go-cmp/cmp"
	gomock "go.uber.org/mock/gomock"
)

func impersonatedCtx(sessionID ccc.UUID, username string, imp *sessioninfo.Impersonation) context.Context {
	ctx := context.WithValue(context.Background(), sessioninfo.CTXSessionID, sessionID)

	return context.WithValue(ctx, sessioninfo.CtxSessionInfo, &sessioninfo.SessionData{
		SessionInfo:   &sessioninfo.SessionInfo{ID: sessionID, Username: username, UpdatedAt: time.Now()},
		Impersonation: imp,
	})
}

// liveSession is an ordinary, just-active session row for username.
func liveSession(id ccc.UUID, username string) *sessioninfo.SessionData {
	return &sessioninfo.SessionData{SessionInfo: &sessioninfo.SessionInfo{ID: id, Username: username, UpdatedAt: time.Now()}}
}

// hookOrRecorder returns hook when set, otherwise a hook recording event kinds into seen.
func hookOrRecorder(hook ImpersonationAuditHook, seen *[]sessioninfo.ImpersonationEventKind) ImpersonationAuditHook {
	if hook != nil {
		return hook
	}

	return func(_ context.Context, event sessioninfo.ImpersonationEvent) error {
		*seen = append(*seen, event.Kind)

		return nil
	}
}

// assertErrorShape checks which httpio message class err carries.
func assertErrorShape(t *testing.T, err error, wantBadRequest, wantForbidden, wantUnauthorized bool) {
	t.Helper()

	if httpio.HasBadRequest(err) != wantBadRequest || httpio.HasForbidden(err) != wantForbidden || httpio.HasUnauthorized(err) != wantUnauthorized {
		t.Errorf("error = %v; want badRequest=%v forbidden=%v unauthorized=%v", err, wantBadRequest, wantForbidden, wantUnauthorized)
	}
}

func TestPreauthAPI_StartImpersonatedSession(t *testing.T) {
	t.Parallel()

	sessionID := ccc.Must(ccc.NewUUID())
	customData := &NoCustomData{}

	tests := []struct {
		name           string
		ctx            context.Context
		options        []PreauthOption
		hook           ImpersonationAuditHook
		req            *ImpersonationRequest
		customData     []*NoCustomData
		prepare        func(storage *mock_sessionstorage.MockPreauthStore, cookieHandler *mock_cookie.MockHandler)
		wantErr        bool
		wantBadRequest bool
		wantForbidden  bool
	}{
		{
			name: "refused when impersonation is not configured on the storage",
			req:  &ImpersonationRequest{Actor: "alice", Principal: accesstypes.UserPrincipal("bob")},
			prepare: func(storage *mock_sessionstorage.MockPreauthStore, _ *mock_cookie.MockHandler) {
				storage.EXPECT().ImpersonationEnabled().Return(false)
			},
			wantErr: true,
		},
		{
			name: "requires an actor",
			req:  &ImpersonationRequest{Principal: accesstypes.UserPrincipal("bob")},
			prepare: func(storage *mock_sessionstorage.MockPreauthStore, _ *mock_cookie.MockHandler) {
				storage.EXPECT().ImpersonationEnabled().Return(true)
			},
			wantErr:        true,
			wantBadRequest: true,
		},
		{
			name: "requires a named principal",
			req:  &ImpersonationRequest{Actor: "alice", Principal: accesstypes.RolePrincipal("")},
			prepare: func(storage *mock_sessionstorage.MockPreauthStore, _ *mock_cookie.MockHandler) {
				storage.EXPECT().ImpersonationEnabled().Return(true)
			},
			wantErr:        true,
			wantBadRequest: true,
		},
		{
			name: "an impersonated session cannot impersonate",
			ctx:  impersonatedCtx(sessionID, "bob", &sessioninfo.Impersonation{Actor: "alice", Principal: accesstypes.UserPrincipal("bob")}),
			req:  &ImpersonationRequest{Actor: "bob", Principal: accesstypes.RolePrincipal("Editor")},
			prepare: func(storage *mock_sessionstorage.MockPreauthStore, _ *mock_cookie.MockHandler) {
				storage.EXPECT().ImpersonationEnabled().Return(true)
			},
			wantErr:       true,
			wantForbidden: true,
		},
		{
			name: "a user principal is taken as given: no record lookup, zero user ID, masked, with custom data",
			req: &ImpersonationRequest{
				Actor:       "alice",
				ActorRealm:  "admin-portal",
				Principal:   accesstypes.UserPrincipal("bob@partner.org"),
				Mask:        accesstypes.MaskPermissions(accesstypes.DenyAll(), accesstypes.List, accesstypes.Read),
				Reason:      "ticket JRN-1",
				MaxDuration: 30 * time.Minute,
			},
			customData: []*NoCustomData{customData},
			prepare: func(storage *mock_sessionstorage.MockPreauthStore, cookieHandler *mock_cookie.MockHandler) {
				storage.EXPECT().ImpersonationEnabled().Return(true)
				storage.EXPECT().CreateImpersonatedSession(gomock.Any(), gomock.Any(), gomock.Any()).
					DoAndReturn(func(_ context.Context, req *sessioninfo.NewSessionRequest, imp *sessioninfo.Impersonation) (ccc.UUID, error) {
						if req.Reason != sessioninfo.ReasonImpersonation || req.Username != "bob@partner.org" || req.UserID != ccc.NilUUID || req.CustomData != customData {
							return ccc.NilUUID, errors.Newf("unexpected NewSessionRequest %+v", req)
						}
						if imp.Actor != "alice" || imp.ActorRealm != "admin-portal" || imp.Principal != accesstypes.UserPrincipal("bob@partner.org") || imp.Mask.String() != "List,Read" || imp.Reason != "ticket JRN-1" {
							return ccc.NilUUID, errors.Newf("unexpected impersonation %+v", imp)
						}
						if lifetime := imp.ExpiresAt.Sub(imp.StartedAt); lifetime != 30*time.Minute {
							return ccc.NilUUID, errors.Newf("lifetime = %v, want 30m", lifetime)
						}

						return sessionID, nil
					})
				cookieHandler.EXPECT().NewAuthCookie(gomock.Any(), true, sessionID).Return(cookie.NewValues())
				cookieHandler.EXPECT().CreateXSRFTokenCookie(gomock.Any(), sessionID)
			},
		},
		{
			name:    "a role principal establishes the session as the actor under the configured cap",
			options: []PreauthOption{WithImpersonationTimeout(15 * time.Minute)},
			req:     &ImpersonationRequest{Actor: "alice", ActorRealm: "admin-portal", Principal: accesstypes.RolePrincipal("PartnerViewer")},
			prepare: func(storage *mock_sessionstorage.MockPreauthStore, cookieHandler *mock_cookie.MockHandler) {
				storage.EXPECT().ImpersonationEnabled().Return(true)
				storage.EXPECT().CreateImpersonatedSession(gomock.Any(), gomock.Any(), gomock.Any()).
					DoAndReturn(func(_ context.Context, req *sessioninfo.NewSessionRequest, imp *sessioninfo.Impersonation) (ccc.UUID, error) {
						want := sessioninfo.NewSessionRequest{Reason: sessioninfo.ReasonImpersonation, Username: "alice"}
						if diff := cmp.Diff(want, *req); diff != "" {
							return ccc.NilUUID, errors.New("unexpected NewSessionRequest: " + diff)
						}
						if imp.Principal != accesstypes.RolePrincipal("PartnerViewer") || !imp.Mask.IsZero() {
							return ccc.NilUUID, errors.Newf("unexpected impersonation %+v", imp)
						}
						if lifetime := imp.ExpiresAt.Sub(imp.StartedAt); lifetime != 15*time.Minute {
							return ccc.NilUUID, errors.Newf("lifetime = %v, want 15m", lifetime)
						}

						return sessionID, nil
					})
				cookieHandler.EXPECT().NewAuthCookie(gomock.Any(), true, sessionID).Return(cookie.NewValues())
				cookieHandler.EXPECT().CreateXSRFTokenCookie(gomock.Any(), sessionID)
			},
		},
		{
			name: "a failed audit destroys the session and fails the establishment",
			hook: func(context.Context, sessioninfo.ImpersonationEvent) error { return errors.New("audit store down") },
			req:  &ImpersonationRequest{Actor: "alice", ActorRealm: "admin-portal", Principal: accesstypes.UserPrincipal("bob")},
			prepare: func(storage *mock_sessionstorage.MockPreauthStore, _ *mock_cookie.MockHandler) {
				storage.EXPECT().ImpersonationEnabled().Return(true)
				storage.EXPECT().CreateImpersonatedSession(gomock.Any(), gomock.Any(), gomock.Any()).Return(sessionID, nil)
				storage.EXPECT().DestroySession(gomock.Any(), sessionID).Return(nil)
			},
			wantErr: true,
		},
		{
			name:       "more than one custom data value is refused before any insert",
			req:        &ImpersonationRequest{Actor: "alice", Principal: accesstypes.UserPrincipal("bob")},
			customData: []*NoCustomData{customData, customData},
			wantErr:    true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			ctrl := gomock.NewController(t)
			storage := newPreauthStoreMock(ctrl)
			cookieHandler := mock_cookie.NewMockHandler(ctrl)

			var started []sessioninfo.ImpersonationEventKind
			options := append([]PreauthOption{WithImpersonationAudit(hookOrRecorder(tt.hook, &started))}, tt.options...)

			p, err := NewPreauth[NoCustomData](storage, cookieKey, options...)
			if err != nil {
				t.Fatalf("NewPreauth() error = %v", err)
			}
			p.baseSession.CookieHandler = cookieHandler
			if tt.prepare != nil {
				tt.prepare(storage, cookieHandler)
			}

			ctx := tt.ctx
			if ctx == nil {
				ctx = context.Background()
			}

			got, err := p.API().StartImpersonatedSession(ctx, httptest.NewRecorder(), tt.req, tt.customData...)
			if (err != nil) != tt.wantErr {
				t.Fatalf("StartImpersonatedSession() error = %v, wantErr %v", err, tt.wantErr)
			}
			assertErrorShape(t, err, tt.wantBadRequest, tt.wantForbidden, false)
			if tt.wantErr {
				return
			}
			if got != sessionID {
				t.Errorf("StartImpersonatedSession() = %v, want %v", got, sessionID)
			}
			if diff := cmp.Diff([]sessioninfo.ImpersonationEventKind{sessioninfo.ImpersonationStarted}, started); diff != "" {
				t.Errorf("audit events mismatch (-want +got):\n%s", diff)
			}
		})
	}
}

func TestSessionAPIs_DestroyImpersonatedSessions(t *testing.T) {
	t.Parallel()

	t.Run("Preauth refuses when not configured and delegates by actor", func(t *testing.T) {
		t.Parallel()
		ctrl := gomock.NewController(t)
		storage := newPreauthStoreMock(ctrl)
		storage.EXPECT().ImpersonationEnabled().Return(false)
		storage.EXPECT().ImpersonationEnabled().Return(true)
		storage.EXPECT().DestroyImpersonatedSessions(gomock.Any(), "alice").Return(nil)

		p, err := NewPreauth[NoCustomData](storage, cookieKey)
		if err != nil {
			t.Fatalf("NewPreauth() error = %v", err)
		}
		if err := p.API().DestroyImpersonatedSessions(context.Background(), "alice"); err == nil {
			t.Error("DestroyImpersonatedSessions() error = nil, want not configured")
		}
		if err := p.API().DestroyImpersonatedSessions(context.Background(), "alice"); err != nil {
			t.Errorf("DestroyImpersonatedSessions() error = %v", err)
		}
	})

	t.Run("single revocation refuses when not configured and delegates by session", func(t *testing.T) {
		t.Parallel()
		ctrl := gomock.NewController(t)
		sessionID := ccc.Must(ccc.NewUUID())

		refused := newPreauthStoreMock(ctrl)
		refused.EXPECT().ImpersonationEnabled().Return(false)
		p, err := NewPreauth[NoCustomData](refused, cookieKey)
		if err != nil {
			t.Fatalf("NewPreauth() error = %v", err)
		}
		if err := p.API().DestroyImpersonatedSession(context.Background(), sessionID); err == nil {
			t.Error("Preauth DestroyImpersonatedSession() error = nil, want not configured")
		}

		preauth := newPreauthStoreMock(ctrl)
		preauth.EXPECT().ImpersonationEnabled().Return(true)
		preauth.EXPECT().DestroyImpersonatedSession(gomock.Any(), sessionID, sessioninfo.ImpersonationEndedByRevocation).Return(nil)
		pa, err := NewPreauth[NoCustomData](preauth, cookieKey)
		if err != nil {
			t.Fatalf("NewPreauth() error = %v", err)
		}
		if err := pa.API().DestroyImpersonatedSession(context.Background(), sessionID); err != nil {
			t.Errorf("Preauth DestroyImpersonatedSession() error = %v", err)
		}
	})
}

func TestWithPrincipalResolver_AppliesToEverySessionType(t *testing.T) {
	t.Parallel()
	ctrl := gomock.NewController(t)

	resolver := func(context.Context) (accesstypes.Principal, error) { return accesstypes.RolePrincipal("Editor"), nil }
	opt := WithPrincipalResolver(resolver)

	preauth, err := NewPreauth[NoCustomData](newPreauthStoreMock(ctrl), cookieKey, opt)
	if err != nil {
		t.Fatalf("NewPreauth() error = %v", err)
	}
	auth, err := NewAuth[NoCustomData, NoCustomData](newAuthStoreMock(ctrl, false), cookieKey, opt)
	if err != nil {
		t.Fatalf("NewAuth() error = %v", err)
	}
	for name, base := range map[string]*basesession.BaseSession{"Preauth": preauth.baseSession, "Auth": auth.baseSession} {
		if base.PrincipalResolver == nil {
			t.Errorf("%s: PrincipalResolver not installed", name)
		}
	}

	var _ PasswordOption = opt
}

func TestSessionAPIs_ActiveImpersonations(t *testing.T) {
	t.Parallel()

	sessionID := ccc.Must(ccc.NewUUID())
	listed := []*sessioninfo.Impersonation{{SessionID: sessionID, Actor: "alice", Principal: accesstypes.RolePrincipal("Editor")}}

	// expectListing arms the storage: the cutoff is now minus the idle session timeout,
	// and the query (nil normalized to the zero query) passes through.
	expectListing := func(enabled, active *gomock.Call, timeout time.Duration, wantQuery *ImpersonationQuery) {
		enabled.Return(true)
		active.DoAndReturn(func(_ context.Context, activeSince time.Time, gotQuery *sessioninfo.ImpersonationQuery) ([]*sessioninfo.Impersonation, error) {
			if drift := time.Since(activeSince.Add(timeout)); drift < 0 || drift > time.Minute {
				return nil, errors.Newf("activeSince = %v, want about now - %v", activeSince, timeout)
			}
			if gotQuery == nil || *gotQuery != *wantQuery {
				return nil, errors.Newf("query = %+v, want %+v", gotQuery, wantQuery)
			}

			return listed, nil
		})
	}

	t.Run("Preauth refuses when not configured, normalizes a nil query and lists", func(t *testing.T) {
		t.Parallel()
		ctrl := gomock.NewController(t)
		storage := newPreauthStoreMock(ctrl)
		storage.EXPECT().ImpersonationEnabled().Return(false)
		expectListing(storage.EXPECT().ImpersonationEnabled(), storage.EXPECT().ActiveImpersonations(gomock.Any(), gomock.Any(), gomock.Any()), 15*time.Minute, &ImpersonationQuery{})

		p, err := NewPreauth[NoCustomData](storage, cookieKey, WithSessionTimeout(15*time.Minute))
		if err != nil {
			t.Fatalf("NewPreauth() error = %v", err)
		}
		if _, err := p.API().ActiveImpersonations(context.Background(), nil); err == nil {
			t.Error("ActiveImpersonations() error = nil, want not configured")
		}
		got, err := p.API().ActiveImpersonations(context.Background(), nil)
		if err != nil {
			t.Fatalf("ActiveImpersonations() error = %v", err)
		}
		principals := cmp.Comparer(func(a, b accesstypes.Principal) bool { return a == b })
		masks := cmp.Comparer(func(a, b accesstypes.PermissionMask) bool { return a.String() == b.String() })
		if diff := cmp.Diff(listed, got, principals, masks); diff != "" {
			t.Errorf("ActiveImpersonations() mismatch (-want +got):\n%s", diff)
		}
	})
}

// Logout on the session APIs announces an impersonated session's end as an Ended
// event on every type that offers it; a type that destroys the row directly would
// end the record without evidence.
func TestSessionAPIs_Logout_AnnouncesImpersonationEnd(t *testing.T) {
	t.Parallel()

	type logoutAPI interface {
		Logout(ctx context.Context) error
	}
	tests := []struct {
		name  string
		build func(t *testing.T, ctrl *gomock.Controller, sessionID ccc.UUID, hook ImpersonationAuditHook) logoutAPI
	}{
		{
			name: "Preauth",
			build: func(t *testing.T, ctrl *gomock.Controller, sessionID ccc.UUID, hook ImpersonationAuditHook) logoutAPI {
				storage := newPreauthStoreMock(ctrl)
				storage.EXPECT().DestroySession(gomock.Any(), sessionID).Return(nil)
				p, err := NewPreauth[NoCustomData](storage, cookieKey, WithImpersonationAudit(hook))
				if err != nil {
					t.Fatalf("NewPreauth() error = %v", err)
				}

				return p.API()
			},
		},
		{
			name: "Auth",
			build: func(t *testing.T, ctrl *gomock.Controller, sessionID ccc.UUID, hook ImpersonationAuditHook) logoutAPI {
				storage := newAuthStoreMock(ctrl, false)
				storage.EXPECT().DestroySession(gomock.Any(), sessionID).Return(nil)
				a, err := NewAuth[NoCustomData, NoCustomData](storage, cookieKey, WithImpersonationAudit(hook))
				if err != nil {
					t.Fatalf("NewAuth() error = %v", err)
				}

				return a.API()
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			ctrl := gomock.NewController(t)
			sessionID := ccc.Must(ccc.NewUUID())

			var seen []sessioninfo.ImpersonationEventKind
			api := tt.build(t, ctrl, sessionID, hookOrRecorder(nil, &seen))

			imp := &sessioninfo.Impersonation{SessionID: sessionID, Actor: "alice", Principal: accesstypes.UserPrincipal("bob"), ExpiresAt: time.Now().Add(time.Hour)}
			if err := api.Logout(impersonatedCtx(sessionID, "bob", imp)); err != nil {
				t.Fatalf("Logout() error = %v", err)
			}
			if diff := cmp.Diff([]sessioninfo.ImpersonationEventKind{sessioninfo.ImpersonationEnded}, seen); diff != "" {
				t.Errorf("audit events mismatch (-want +got):\n%s", diff)
			}
			if imp.EndReason != sessioninfo.ImpersonationEndedByLogout {
				t.Errorf("EndReason = %q, want %q", imp.EndReason, sessioninfo.ImpersonationEndedByLogout)
			}
		})
	}
}
