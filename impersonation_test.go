package session

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/cccteam/ccc"
	"github.com/cccteam/ccc/accesstypes"
	"github.com/cccteam/httpio"
	"github.com/cccteam/session/cookie"
	"github.com/cccteam/session/internal/basesession"
	"github.com/cccteam/session/internal/dbtype"
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

func TestPasswordAuthAPI_StartImpersonatedSession(t *testing.T) {
	t.Parallel()

	sessionID := ccc.Must(ccc.NewUUID())
	userID := ccc.Must(ccc.NewUUID())
	sourceID := ccc.Must(ccc.NewUUID())
	customData := &NoCustomData{}

	type test struct {
		name             string
		ctx              context.Context
		options          []PasswordOption
		hook             ImpersonationAuditHook
		req              *ImpersonationRequest
		customData       []*NoCustomData
		prepare          func(storage *mock_sessionstorage.MockPasswordAuthStore, cookieHandler *mock_cookie.MockHandler)
		wantErr          bool
		wantBadRequest   bool
		wantForbidden    bool
		wantUnauthorized bool
	}
	tests := []test{
		{
			name: "refused when impersonation is not configured on the storage",
			req:  &ImpersonationRequest{Actor: "alice", Principal: accesstypes.RolePrincipal("Editor")},
			prepare: func(storage *mock_sessionstorage.MockPasswordAuthStore, _ *mock_cookie.MockHandler) {
				storage.EXPECT().ImpersonationEnabled().Return(false)
			},
			wantErr: true,
		},
		{
			name: "requires an actor",
			req:  &ImpersonationRequest{Principal: accesstypes.RolePrincipal("Editor")},
			prepare: func(storage *mock_sessionstorage.MockPasswordAuthStore, _ *mock_cookie.MockHandler) {
				storage.EXPECT().ImpersonationEnabled().Return(true)
			},
			wantErr:        true,
			wantBadRequest: true,
		},
		{
			name: "requires a named principal",
			req:  &ImpersonationRequest{Actor: "alice"},
			prepare: func(storage *mock_sessionstorage.MockPasswordAuthStore, _ *mock_cookie.MockHandler) {
				storage.EXPECT().ImpersonationEnabled().Return(true)
			},
			wantErr:        true,
			wantBadRequest: true,
		},
		{
			name: "an impersonated session cannot impersonate",
			ctx:  impersonatedCtx(sessionID, "bob", &sessioninfo.Impersonation{Actor: "alice", Principal: accesstypes.UserPrincipal("bob")}),
			req:  &ImpersonationRequest{Actor: "bob", Principal: accesstypes.RolePrincipal("Editor")},
			prepare: func(storage *mock_sessionstorage.MockPasswordAuthStore, _ *mock_cookie.MockHandler) {
				storage.EXPECT().ImpersonationEnabled().Return(true)
			},
			wantErr:       true,
			wantForbidden: true,
		},
		{
			name: "an impersonated user must exist",
			req:  &ImpersonationRequest{Actor: "alice", Principal: accesstypes.UserPrincipal("ghost")},
			prepare: func(storage *mock_sessionstorage.MockPasswordAuthStore, _ *mock_cookie.MockHandler) {
				storage.EXPECT().ImpersonationEnabled().Return(true)
				storage.EXPECT().UserByUserName(gomock.Any(), "ghost").Return(nil, errors.New("not found"))
			},
			wantErr: true,
		},
		{
			name: "a disabled user cannot be impersonated",
			req:  &ImpersonationRequest{Actor: "alice", Principal: accesstypes.UserPrincipal("bob")},
			prepare: func(storage *mock_sessionstorage.MockPasswordAuthStore, _ *mock_cookie.MockHandler) {
				storage.EXPECT().ImpersonationEnabled().Return(true)
				storage.EXPECT().UserByUserName(gomock.Any(), "bob").Return(&dbtype.SessionUser{ID: userID, Username: "bob", Disabled: true}, nil)
			},
			wantErr:          true,
			wantUnauthorized: true,
		},
		{
			name: "a foreign actor's role principal is refused when the actor's name is a user of this application",
			req:  &ImpersonationRequest{Actor: "alice", ActorRealm: "admin-portal", Principal: accesstypes.RolePrincipal("PartnerViewer")},
			prepare: func(storage *mock_sessionstorage.MockPasswordAuthStore, _ *mock_cookie.MockHandler) {
				storage.EXPECT().ImpersonationEnabled().Return(true)
				storage.EXPECT().UserByUserName(gomock.Any(), "alice").Return(&dbtype.SessionUser{ID: userID, Username: "alice"}, nil)
			},
			wantErr:       true,
			wantForbidden: true,
		},
		{
			name: "a failed actor lookup fails the establishment",
			req:  &ImpersonationRequest{Actor: "alice", ActorRealm: "admin-portal", Principal: accesstypes.RolePrincipal("PartnerViewer")},
			prepare: func(storage *mock_sessionstorage.MockPasswordAuthStore, _ *mock_cookie.MockHandler) {
				storage.EXPECT().ImpersonationEnabled().Return(true)
				storage.EXPECT().UserByUserName(gomock.Any(), "alice").Return(nil, errors.New("db down"))
			},
			wantErr: true,
		},
		{
			name: "a foreign actor's role principal establishes the session as the actor with the default cap",
			req:  &ImpersonationRequest{Actor: "alice", ActorRealm: "admin-portal", Principal: accesstypes.RolePrincipal("PartnerViewer")},
			prepare: func(storage *mock_sessionstorage.MockPasswordAuthStore, cookieHandler *mock_cookie.MockHandler) {
				storage.EXPECT().ImpersonationEnabled().Return(true)
				storage.EXPECT().UserByUserName(gomock.Any(), "alice").Return(nil, httpio.NewNotFoundMessage("no such user"))
				storage.EXPECT().CreateImpersonatedSession(gomock.Any(), gomock.Any(), gomock.Any()).
					DoAndReturn(func(_ context.Context, req *sessioninfo.NewSessionRequest, imp *sessioninfo.Impersonation) (ccc.UUID, error) {
						want := sessioninfo.NewSessionRequest{Reason: sessioninfo.ReasonImpersonation, Username: "alice"}
						if diff := cmp.Diff(want, *req); diff != "" {
							return ccc.NilUUID, errors.New("unexpected NewSessionRequest: " + diff)
						}
						if imp.Actor != "alice" || imp.ActorRealm != "admin-portal" || imp.Principal != accesstypes.RolePrincipal("PartnerViewer") || !imp.Mask.IsZero() {
							return ccc.NilUUID, errors.Newf("unexpected impersonation %+v", imp)
						}
						if lifetime := imp.ExpiresAt.Sub(imp.StartedAt); lifetime != basesession.DefaultImpersonationTimeout {
							return ccc.NilUUID, errors.Newf("lifetime = %v, want %v", lifetime, basesession.DefaultImpersonationTimeout)
						}

						return sessionID, nil
					})
				cookieHandler.EXPECT().NewAuthCookie(gomock.Any(), true, sessionID).Return(cookie.NewValues())
				cookieHandler.EXPECT().CreateXSRFTokenCookie(gomock.Any(), sessionID)
			},
		},
		{
			name: "a local actor's role principal is verified against their own live session, not against SessionUsers",
			req:  &ImpersonationRequest{Actor: "alice", SourceSessionID: ccc.NullUUID{UUID: sourceID, Valid: true}, Principal: accesstypes.RolePrincipal("Editor")},
			prepare: func(storage *mock_sessionstorage.MockPasswordAuthStore, cookieHandler *mock_cookie.MockHandler) {
				storage.EXPECT().ImpersonationEnabled().Return(true)
				storage.EXPECT().Session(gomock.Any(), sourceID).Return(liveSession(sourceID, "alice"), nil)
				storage.EXPECT().CreateImpersonatedSession(gomock.Any(), gomock.Any(), gomock.Any()).DoAndReturn(createdAsLocalActor("alice", sourceID, sessionID))
				cookieHandler.EXPECT().NewAuthCookie(gomock.Any(), true, sessionID).Return(cookie.NewValues())
				cookieHandler.EXPECT().CreateXSRFTokenCookie(gomock.Any(), sessionID)
			},
		},
		{
			name: "a local actor must name their own session",
			req:  &ImpersonationRequest{Actor: "alice", Principal: accesstypes.RolePrincipal("Editor")},
			prepare: func(storage *mock_sessionstorage.MockPasswordAuthStore, _ *mock_cookie.MockHandler) {
				storage.EXPECT().ImpersonationEnabled().Return(true)
			},
			wantErr:        true,
			wantBadRequest: true,
		},
		{
			name: "a local actor's source session must be theirs",
			req:  &ImpersonationRequest{Actor: "alice", SourceSessionID: ccc.NullUUID{UUID: sourceID, Valid: true}, Principal: accesstypes.RolePrincipal("Editor")},
			prepare: func(storage *mock_sessionstorage.MockPasswordAuthStore, _ *mock_cookie.MockHandler) {
				storage.EXPECT().ImpersonationEnabled().Return(true)
				storage.EXPECT().Session(gomock.Any(), sourceID).Return(liveSession(sourceID, "carol"), nil)
			},
			wantErr:       true,
			wantForbidden: true,
		},
		{
			name: "a local actor's source session must be live",
			req:  &ImpersonationRequest{Actor: "alice", SourceSessionID: ccc.NullUUID{UUID: sourceID, Valid: true}, Principal: accesstypes.UserPrincipal("bob")},
			prepare: func(storage *mock_sessionstorage.MockPasswordAuthStore, _ *mock_cookie.MockHandler) {
				storage.EXPECT().ImpersonationEnabled().Return(true)
				storage.EXPECT().UserByUserName(gomock.Any(), "bob").Return(&dbtype.SessionUser{ID: userID, Username: "bob"}, nil)
				src := liveSession(sourceID, "alice")
				src.Expired = true
				storage.EXPECT().Session(gomock.Any(), sourceID).Return(src, nil)
			},
			wantErr:       true,
			wantForbidden: true,
		},
		{
			name: "a local actor's source session must exist here",
			req:  &ImpersonationRequest{Actor: "alice", SourceSessionID: ccc.NullUUID{UUID: sourceID, Valid: true}, Principal: accesstypes.RolePrincipal("Editor")},
			prepare: func(storage *mock_sessionstorage.MockPasswordAuthStore, _ *mock_cookie.MockHandler) {
				storage.EXPECT().ImpersonationEnabled().Return(true)
				storage.EXPECT().Session(gomock.Any(), sourceID).Return(nil, httpio.NewNotFoundMessage("no such session"))
			},
			wantErr:       true,
			wantForbidden: true,
		},
		{
			name: "a user principal establishes the session as the user, masked, with custom data and a shortened cap",
			req: &ImpersonationRequest{
				Actor:           "alice",
				SourceSessionID: ccc.NullUUID{UUID: sourceID, Valid: true},
				Principal:       accesstypes.UserPrincipal("Bob"),
				Mask:            accesstypes.MaskPermissions(accesstypes.DenyAll(), accesstypes.List, accesstypes.Read),
				Reason:          "ticket JRN-1",
				MaxDuration:     30 * time.Minute,
			},
			customData: []*NoCustomData{customData},
			prepare: func(storage *mock_sessionstorage.MockPasswordAuthStore, cookieHandler *mock_cookie.MockHandler) {
				storage.EXPECT().ImpersonationEnabled().Return(true)
				storage.EXPECT().UserByUserName(gomock.Any(), "Bob").Return(&dbtype.SessionUser{ID: userID, Username: "bob"}, nil)
				storage.EXPECT().Session(gomock.Any(), sourceID).Return(liveSession(sourceID, "alice"), nil)
				storage.EXPECT().CreateImpersonatedSession(gomock.Any(), gomock.Any(), gomock.Any()).
					DoAndReturn(func(_ context.Context, req *sessioninfo.NewSessionRequest, imp *sessioninfo.Impersonation) (ccc.UUID, error) {
						if req.Reason != sessioninfo.ReasonImpersonation || req.Username != "bob" || req.UserID != userID || req.CustomData != customData {
							return ccc.NilUUID, errors.Newf("unexpected NewSessionRequest %+v", req)
						}
						if imp.Principal != accesstypes.UserPrincipal("Bob") || imp.Mask.String() != "List,Read" || imp.Reason != "ticket JRN-1" || imp.SourceSessionID.UUID != sourceID {
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
			name:    "the configured impersonation timeout caps the session",
			options: []PasswordOption{WithImpersonationTimeout(15 * time.Minute)},
			req:     &ImpersonationRequest{Actor: "alice", ActorRealm: "admin-portal", Principal: accesstypes.RolePrincipal("Editor"), MaxDuration: time.Hour},
			prepare: func(storage *mock_sessionstorage.MockPasswordAuthStore, cookieHandler *mock_cookie.MockHandler) {
				storage.EXPECT().ImpersonationEnabled().Return(true)
				storage.EXPECT().UserByUserName(gomock.Any(), "alice").Return(nil, httpio.NewNotFoundMessage("no such user"))
				storage.EXPECT().CreateImpersonatedSession(gomock.Any(), gomock.Any(), gomock.Any()).
					DoAndReturn(func(_ context.Context, _ *sessioninfo.NewSessionRequest, imp *sessioninfo.Impersonation) (ccc.UUID, error) {
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
			req:  &ImpersonationRequest{Actor: "alice", ActorRealm: "admin-portal", Principal: accesstypes.RolePrincipal("Editor")},
			prepare: func(storage *mock_sessionstorage.MockPasswordAuthStore, _ *mock_cookie.MockHandler) {
				storage.EXPECT().ImpersonationEnabled().Return(true)
				storage.EXPECT().UserByUserName(gomock.Any(), "alice").Return(nil, httpio.NewNotFoundMessage("no such user"))
				storage.EXPECT().CreateImpersonatedSession(gomock.Any(), gomock.Any(), gomock.Any()).Return(sessionID, nil)
				storage.EXPECT().DestroySession(gomock.Any(), sessionID).Return(nil)
			},
			wantErr: true,
		},
		{
			name:       "more than one custom data value is refused before any insert",
			req:        &ImpersonationRequest{Actor: "alice", Principal: accesstypes.RolePrincipal("Editor")},
			customData: []*NoCustomData{customData, customData},
			wantErr:    true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			ctrl := gomock.NewController(t)
			storage := newPasswordStoreMock(ctrl)
			cookieHandler := mock_cookie.NewMockHandler(ctrl)

			var started []sessioninfo.ImpersonationEventKind
			options := append([]PasswordOption{WithImpersonationAudit(hookOrRecorder(tt.hook, &started))}, tt.options...)

			p, err := NewPasswordAuth[NoCustomData, NoCustomData](storage, cookieKey, options...)
			if err != nil {
				t.Fatalf("NewPasswordAuth() error = %v", err)
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
			assertErrorShape(t, err, tt.wantBadRequest, tt.wantForbidden, tt.wantUnauthorized)
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

// createdAsLocalActor is a CreateImpersonatedSession stand-in asserting a local actor's
// role session: the actor's name with the zero ID, no realm, and their source session.
func createdAsLocalActor(actor string, sourceID, sessionID ccc.UUID) func(context.Context, *sessioninfo.NewSessionRequest, *sessioninfo.Impersonation) (ccc.UUID, error) {
	return func(_ context.Context, req *sessioninfo.NewSessionRequest, imp *sessioninfo.Impersonation) (ccc.UUID, error) {
		if req.Username != actor || req.UserID != ccc.NilUUID || imp.ActorRealm != "" || imp.SourceSessionID.UUID != sourceID {
			return ccc.NilUUID, errors.Newf("unexpected request %+v / impersonation %+v", req, imp)
		}

		return sessionID, nil
	}
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

func TestPasswordAuth_ValidateSession_Impersonation(t *testing.T) {
	t.Parallel()

	sessionID := ccc.Must(ccc.NewUUID())
	userID := ccc.Must(ccc.NewUUID())

	tests := []struct {
		name           string
		session        *sessioninfo.SessionData
		prepare        func(storage *mock_sessionstorage.MockPasswordAuthStore)
		wantStatusCode int
		wantUserInfo   *sessioninfo.UserInfo
	}{
		{
			name: "a foreign actor's role principal needs no local user record",
			session: &sessioninfo.SessionData{
				SessionInfo:   &sessioninfo.SessionInfo{ID: sessionID, Username: "alice", UpdatedAt: time.Now()},
				Impersonation: &sessioninfo.Impersonation{SessionID: sessionID, Actor: "alice", ActorRealm: "admin-portal", Principal: accesstypes.RolePrincipal("PartnerViewer"), ExpiresAt: time.Now().Add(time.Hour)},
			},
			wantStatusCode: http.StatusOK,
			wantUserInfo:   &sessioninfo.UserInfo{Username: "alice"},
		},
		{
			name: "a local actor's role principal resolves the actor's own record",
			session: &sessioninfo.SessionData{
				SessionInfo:   &sessioninfo.SessionInfo{ID: sessionID, Username: "alice", UpdatedAt: time.Now()},
				Impersonation: &sessioninfo.Impersonation{SessionID: sessionID, Actor: "alice", Principal: accesstypes.RolePrincipal("Editor"), ExpiresAt: time.Now().Add(time.Hour)},
			},
			prepare: func(storage *mock_sessionstorage.MockPasswordAuthStore) {
				storage.EXPECT().UserByUserName(gomock.Any(), "alice").Return(&dbtype.SessionUser{ID: userID, Username: "alice"}, nil)
			},
			wantStatusCode: http.StatusOK,
			wantUserInfo:   &sessioninfo.UserInfo{ID: userID, Username: "alice"},
		},
		{
			name: "a user principal resolves the impersonated user's record",
			session: &sessioninfo.SessionData{
				SessionInfo:   &sessioninfo.SessionInfo{ID: sessionID, Username: "bob", UpdatedAt: time.Now()},
				Impersonation: &sessioninfo.Impersonation{SessionID: sessionID, Actor: "alice", Principal: accesstypes.UserPrincipal("bob"), ExpiresAt: time.Now().Add(time.Hour)},
			},
			prepare: func(storage *mock_sessionstorage.MockPasswordAuthStore) {
				storage.EXPECT().UserByUserName(gomock.Any(), "bob").Return(&dbtype.SessionUser{ID: userID, Username: "bob"}, nil)
			},
			wantStatusCode: http.StatusOK,
			wantUserInfo:   &sessioninfo.UserInfo{ID: userID, Username: "bob"},
		},
		{
			name: "an impersonated user who was disabled ends the session",
			session: &sessioninfo.SessionData{
				SessionInfo:   &sessioninfo.SessionInfo{ID: sessionID, Username: "bob", UpdatedAt: time.Now()},
				Impersonation: &sessioninfo.Impersonation{SessionID: sessionID, Actor: "alice", Principal: accesstypes.UserPrincipal("bob"), ExpiresAt: time.Now().Add(time.Hour)},
			},
			prepare: func(storage *mock_sessionstorage.MockPasswordAuthStore) {
				storage.EXPECT().UserByUserName(gomock.Any(), "bob").Return(&dbtype.SessionUser{ID: userID, Username: "bob", Disabled: true}, nil)
			},
			wantStatusCode: http.StatusUnauthorized,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			ctrl := gomock.NewController(t)
			storage := newPasswordStoreMock(ctrl)
			storage.EXPECT().Session(gomock.Any(), sessionID).Return(tt.session, nil)
			if tt.prepare != nil {
				tt.prepare(storage)
			}

			p, err := NewPasswordAuth[NoCustomData, NoCustomData](storage, cookieKey)
			if err != nil {
				t.Fatalf("NewPasswordAuth() error = %v", err)
			}

			var gotUserInfo *sessioninfo.UserInfo
			next := http.HandlerFunc(func(_ http.ResponseWriter, r *http.Request) {
				gotUserInfo = sessioninfo.UserFromRequest(r)
			})

			ctx := context.WithValue(context.Background(), sessioninfo.CTXSessionID, sessionID)
			rr := httptest.NewRecorder()
			p.ValidateSession(next).ServeHTTP(rr, httptest.NewRequestWithContext(ctx, http.MethodGet, "/", http.NoBody))

			if rr.Code != tt.wantStatusCode {
				t.Errorf("status = %d, want %d", rr.Code, tt.wantStatusCode)
			}
			if diff := cmp.Diff(tt.wantUserInfo, gotUserInfo); diff != "" {
				t.Errorf("UserInfo mismatch (-want +got):\n%s", diff)
			}
		})
	}
}

func TestPasswordAuth_refuseImpersonated(t *testing.T) {
	t.Parallel()

	sessionID := ccc.Must(ccc.NewUUID())
	masked := &sessioninfo.Impersonation{SessionID: sessionID, Actor: "alice", Principal: accesstypes.UserPrincipal("bob"), Mask: accesstypes.MaskPermissions(accesstypes.DenyAll(), accesstypes.Read)}
	unmasked := &sessioninfo.Impersonation{SessionID: sessionID, Actor: "alice", Principal: accesstypes.RolePrincipal("Editor")}

	tests := []struct {
		name          string
		ctx           context.Context
		selfOperation bool
		wantForbidden bool
	}{
		{name: "no session in context is allowed", ctx: context.Background()},
		{name: "an ordinary session is allowed", ctx: impersonatedCtx(sessionID, "alice", nil), selfOperation: true},
		{name: "a self operation is refused under any impersonation", ctx: impersonatedCtx(sessionID, "alice", unmasked), selfOperation: true, wantForbidden: true},
		{name: "user management is allowed in an unmasked impersonation", ctx: impersonatedCtx(sessionID, "alice", unmasked)},
		{name: "user management is refused under a mask", ctx: impersonatedCtx(sessionID, "bob", masked), wantForbidden: true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			ctrl := gomock.NewController(t)

			var events []sessioninfo.ImpersonationEvent
			p, err := NewPasswordAuth[NoCustomData, NoCustomData](newPasswordStoreMock(ctrl), cookieKey, WithImpersonationAudit(func(_ context.Context, event sessioninfo.ImpersonationEvent) error {
				events = append(events, event)

				return nil
			}))
			if err != nil {
				t.Fatalf("NewPasswordAuth() error = %v", err)
			}

			err = p.refuseImpersonated(tt.ctx, "CreateUser", tt.selfOperation)
			if httpio.HasForbidden(err) != tt.wantForbidden || (err != nil) != tt.wantForbidden {
				t.Fatalf("refuseImpersonated() error = %v, wantForbidden %v", err, tt.wantForbidden)
			}
			if !tt.wantForbidden {
				if len(events) != 0 {
					t.Errorf("events = %v, want none", events)
				}

				return
			}
			if len(events) != 1 || events[0].Kind != sessioninfo.ImpersonationIdentityOperationBlocked || events[0].Operation != "CreateUser" {
				t.Errorf("events = %+v, want one IdentityOperationBlocked for CreateUser", events)
			}
		})
	}
}

func TestPasswordAuth_ChangeUsername_RefusedWhenImpersonated(t *testing.T) {
	t.Parallel()
	ctrl := gomock.NewController(t)

	p, err := NewPasswordAuth[NoCustomData, NoCustomData](newPasswordStoreMock(ctrl), cookieKey)
	if err != nil {
		t.Fatalf("NewPasswordAuth() error = %v", err)
	}

	sessionID := ccc.Must(ccc.NewUUID())
	ctx := impersonatedCtx(sessionID, "alice", &sessioninfo.Impersonation{SessionID: sessionID, Actor: "alice", Principal: accesstypes.RolePrincipal("Editor")})
	rr := httptest.NewRecorder()
	p.ChangeUsername().ServeHTTP(rr, httptest.NewRequestWithContext(ctx, http.MethodPost, "/", http.NoBody))

	if rr.Code != http.StatusForbidden {
		t.Errorf("status = %d, want %d", rr.Code, http.StatusForbidden)
	}
}

func TestPasswordAuthAPI_DestroyImpersonatedSessions(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name    string
		prepare func(storage *mock_sessionstorage.MockPasswordAuthStore)
		wantErr bool
	}{
		{
			name: "refused when impersonation is not configured",
			prepare: func(storage *mock_sessionstorage.MockPasswordAuthStore) {
				storage.EXPECT().ImpersonationEnabled().Return(false)
			},
			wantErr: true,
		},
		{
			name: "delegates by actor",
			prepare: func(storage *mock_sessionstorage.MockPasswordAuthStore) {
				storage.EXPECT().ImpersonationEnabled().Return(true)
				storage.EXPECT().DestroyImpersonatedSessions(gomock.Any(), "alice").Return(nil)
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			ctrl := gomock.NewController(t)
			storage := newPasswordStoreMock(ctrl)
			tt.prepare(storage)

			p, err := NewPasswordAuth[NoCustomData, NoCustomData](storage, cookieKey)
			if err != nil {
				t.Fatalf("NewPasswordAuth() error = %v", err)
			}

			if err := p.API().DestroyImpersonatedSessions(context.Background(), "alice"); (err != nil) != tt.wantErr {
				t.Errorf("DestroyImpersonatedSessions() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

// The Preauth, OIDC Azure and OIDC Google APIs share the establishing flow with
// password auth; what differs per type is the identity a user principal resolves to (the
// name as given, zero user ID — there is no username-keyed local record) and the storage
// the session is written through. Preauth exercises the shared refusals in full; the
// OIDC types are wired the same way and get the establishing cases.

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

func TestOIDCAzureAPI_StartImpersonatedSession(t *testing.T) {
	t.Parallel()

	sessionID := ccc.Must(ccc.NewUUID())

	tests := []struct {
		name         string
		req          *ImpersonationRequest
		prepare      func(storage *mock_sessionstorage.MockOIDCStore, cookieHandler *mock_cookie.MockHandler)
		wantErr      bool
		wantUsername string
	}{
		{
			name: "refused when impersonation is not configured on the storage",
			req:  &ImpersonationRequest{Actor: "alice@example.com", Principal: accesstypes.UserPrincipal("bob@example.com")},
			prepare: func(storage *mock_sessionstorage.MockOIDCStore, _ *mock_cookie.MockHandler) {
				storage.EXPECT().ImpersonationEnabled().Return(false)
			},
			wantErr: true,
		},
		{
			name:         "a user principal is the session's username as given, with the zero user ID",
			req:          &ImpersonationRequest{Actor: "alice@example.com", ActorRealm: "admin-portal", Principal: accesstypes.UserPrincipal("bob@example.com"), Mask: accesstypes.MaskPermissions(accesstypes.DenyAll(), accesstypes.Read)},
			wantUsername: "bob@example.com",
		},
		{
			name:         "a role principal is the actor",
			req:          &ImpersonationRequest{Actor: "alice@example.com", ActorRealm: "admin-portal", Principal: accesstypes.RolePrincipal("Auditor")},
			wantUsername: "alice@example.com",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			ctrl := gomock.NewController(t)
			storage := newOIDCStoreMock(ctrl)
			cookieHandler := mock_cookie.NewMockHandler(ctrl)
			if tt.prepare != nil {
				tt.prepare(storage, cookieHandler)
			} else {
				expectEstablished(storage.EXPECT().ImpersonationEnabled(), storage.EXPECT().CreateImpersonatedSession(gomock.Any(), gomock.Any(), gomock.Any()), cookieHandler, sessionID, tt.wantUsername, tt.req)
			}

			var started []sessioninfo.ImpersonationEventKind
			a := &OIDCAzure[NoCustomData, NoCustomData]{
				storage: storage,
				baseSession: &basesession.BaseSession{
					Storage:            storage,
					CookieHandler:      cookieHandler,
					ImpersonationAudit: hookOrRecorder(nil, &started),
				},
			}

			got, err := a.API().StartImpersonatedSession(context.Background(), httptest.NewRecorder(), tt.req)
			if (err != nil) != tt.wantErr {
				t.Fatalf("StartImpersonatedSession() error = %v, wantErr %v", err, tt.wantErr)
			}
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

func TestOIDCGoogleAPI_StartImpersonatedSession(t *testing.T) {
	t.Parallel()

	sessionID := ccc.Must(ccc.NewUUID())

	tests := []struct {
		name         string
		req          *ImpersonationRequest
		prepare      func(storage *mock_sessionstorage.MockGoogleOIDCStore, cookieHandler *mock_cookie.MockHandler)
		wantErr      bool
		wantUsername string
	}{
		{
			name: "refused when impersonation is not configured on the storage",
			req:  &ImpersonationRequest{Actor: "alice@example.com", Principal: accesstypes.UserPrincipal("bob@example.com")},
			prepare: func(storage *mock_sessionstorage.MockGoogleOIDCStore, _ *mock_cookie.MockHandler) {
				storage.EXPECT().ImpersonationEnabled().Return(false)
			},
			wantErr: true,
		},
		{
			name:         "a user principal is the session's username as given, with the zero user ID",
			req:          &ImpersonationRequest{Actor: "alice@example.com", ActorRealm: "admin-portal", Principal: accesstypes.UserPrincipal("bob@example.com"), Mask: accesstypes.MaskPermissions(accesstypes.DenyAll(), accesstypes.Read)},
			wantUsername: "bob@example.com",
		},
		{
			name:         "a role principal is the actor",
			req:          &ImpersonationRequest{Actor: "alice@example.com", ActorRealm: "admin-portal", Principal: accesstypes.RolePrincipal("Auditor")},
			wantUsername: "alice@example.com",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			ctrl := gomock.NewController(t)
			storage := newGoogleOIDCStoreMock(ctrl)
			cookieHandler := mock_cookie.NewMockHandler(ctrl)
			if tt.prepare != nil {
				tt.prepare(storage, cookieHandler)
			} else {
				expectEstablished(storage.EXPECT().ImpersonationEnabled(), storage.EXPECT().CreateImpersonatedSession(gomock.Any(), gomock.Any(), gomock.Any()), cookieHandler, sessionID, tt.wantUsername, tt.req)
			}

			var started []sessioninfo.ImpersonationEventKind
			a := &OIDCGoogle[NoCustomData, NoCustomData]{
				storage: storage,
				baseSession: &basesession.BaseSession{
					Storage:            storage,
					CookieHandler:      cookieHandler,
					ImpersonationAudit: hookOrRecorder(nil, &started),
				},
			}

			got, err := a.API().StartImpersonatedSession(context.Background(), httptest.NewRecorder(), tt.req)
			if (err != nil) != tt.wantErr {
				t.Fatalf("StartImpersonatedSession() error = %v, wantErr %v", err, tt.wantErr)
			}
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

// expectEstablished arms the storage and cookie expectations for a successful
// establishment through a store with no user record: the session is created for
// wantUsername with the zero user ID, then both cookies are written for sessionID.
func expectEstablished(enabled, create *gomock.Call, cookieHandler *mock_cookie.MockHandler, sessionID ccc.UUID, wantUsername string, req *ImpersonationRequest) {
	enabled.Return(true)
	create.DoAndReturn(func(_ context.Context, newReq *sessioninfo.NewSessionRequest, imp *sessioninfo.Impersonation) (ccc.UUID, error) {
		want := sessioninfo.NewSessionRequest{Reason: sessioninfo.ReasonImpersonation, Username: wantUsername}
		if diff := cmp.Diff(want, *newReq); diff != "" {
			return ccc.NilUUID, errors.New("unexpected NewSessionRequest: " + diff)
		}
		if imp.Actor != req.Actor || imp.Principal != req.Principal || imp.Mask.String() != req.Mask.String() {
			return ccc.NilUUID, errors.Newf("unexpected impersonation %+v", imp)
		}
		if lifetime := imp.ExpiresAt.Sub(imp.StartedAt); lifetime != basesession.DefaultImpersonationTimeout {
			return ccc.NilUUID, errors.Newf("lifetime = %v, want %v", lifetime, basesession.DefaultImpersonationTimeout)
		}

		return sessionID, nil
	})
	cookieHandler.EXPECT().NewAuthCookie(gomock.Any(), true, sessionID).Return(cookie.NewValues())
	cookieHandler.EXPECT().CreateXSRFTokenCookie(gomock.Any(), sessionID)
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

	t.Run("OIDC Azure delegates by actor", func(t *testing.T) {
		t.Parallel()
		ctrl := gomock.NewController(t)
		storage := newOIDCStoreMock(ctrl)
		storage.EXPECT().ImpersonationEnabled().Return(true)
		storage.EXPECT().DestroyImpersonatedSessions(gomock.Any(), "alice").Return(nil)

		a := &OIDCAzure[NoCustomData, NoCustomData]{storage: storage, baseSession: &basesession.BaseSession{Storage: storage}}
		if err := a.API().DestroyImpersonatedSessions(context.Background(), "alice"); err != nil {
			t.Errorf("DestroyImpersonatedSessions() error = %v", err)
		}
	})

	t.Run("single revocation refuses when not configured and delegates by session on every type", func(t *testing.T) {
		t.Parallel()
		ctrl := gomock.NewController(t)
		sessionID := ccc.Must(ccc.NewUUID())

		password := newPasswordStoreMock(ctrl)
		password.EXPECT().ImpersonationEnabled().Return(false)
		p, err := NewPasswordAuth[NoCustomData, NoCustomData](password, cookieKey)
		if err != nil {
			t.Fatalf("NewPasswordAuth() error = %v", err)
		}
		if err := p.API().DestroyImpersonatedSession(context.Background(), sessionID); err == nil {
			t.Error("PasswordAuth DestroyImpersonatedSession() error = nil, want not configured")
		}

		preauth := newPreauthStoreMock(ctrl)
		preauth.EXPECT().ImpersonationEnabled().Return(true)
		preauth.EXPECT().DestroyImpersonatedSession(gomock.Any(), sessionID).Return(nil)
		pa, err := NewPreauth[NoCustomData](preauth, cookieKey)
		if err != nil {
			t.Fatalf("NewPreauth() error = %v", err)
		}
		if err := pa.API().DestroyImpersonatedSession(context.Background(), sessionID); err != nil {
			t.Errorf("Preauth DestroyImpersonatedSession() error = %v", err)
		}

		azure := newOIDCStoreMock(ctrl)
		azure.EXPECT().ImpersonationEnabled().Return(true)
		azure.EXPECT().DestroyImpersonatedSession(gomock.Any(), sessionID).Return(nil)
		a := &OIDCAzure[NoCustomData, NoCustomData]{storage: azure, baseSession: &basesession.BaseSession{Storage: azure}}
		if err := a.API().DestroyImpersonatedSession(context.Background(), sessionID); err != nil {
			t.Errorf("OIDCAzure DestroyImpersonatedSession() error = %v", err)
		}

		google := newGoogleOIDCStoreMock(ctrl)
		google.EXPECT().ImpersonationEnabled().Return(true)
		google.EXPECT().DestroyImpersonatedSession(gomock.Any(), sessionID).Return(nil)
		g := &OIDCGoogle[NoCustomData, NoCustomData]{storage: google, baseSession: &basesession.BaseSession{Storage: google}}
		if err := g.API().DestroyImpersonatedSession(context.Background(), sessionID); err != nil {
			t.Errorf("OIDCGoogle DestroyImpersonatedSession() error = %v", err)
		}
	})

	t.Run("OIDC Google delegates by actor", func(t *testing.T) {
		t.Parallel()
		ctrl := gomock.NewController(t)
		storage := newGoogleOIDCStoreMock(ctrl)
		storage.EXPECT().ImpersonationEnabled().Return(true)
		storage.EXPECT().DestroyImpersonatedSessions(gomock.Any(), "alice").Return(nil)

		a := &OIDCGoogle[NoCustomData, NoCustomData]{storage: storage, baseSession: &basesession.BaseSession{Storage: storage}}
		if err := a.API().DestroyImpersonatedSessions(context.Background(), "alice"); err != nil {
			t.Errorf("DestroyImpersonatedSessions() error = %v", err)
		}
	})
}

func TestWithPrincipalResolver_AppliesToEverySessionType(t *testing.T) {
	t.Parallel()
	ctrl := gomock.NewController(t)

	resolver := func(context.Context) (accesstypes.Principal, error) { return accesstypes.RolePrincipal("Editor"), nil }
	opt := WithPrincipalResolver(resolver)

	password, err := NewPasswordAuth[NoCustomData, NoCustomData](newPasswordStoreMock(ctrl), cookieKey, opt)
	if err != nil {
		t.Fatalf("NewPasswordAuth() error = %v", err)
	}
	preauth, err := NewPreauth[NoCustomData](newPreauthStoreMock(ctrl), cookieKey, opt)
	if err != nil {
		t.Fatalf("NewPreauth() error = %v", err)
	}
	for name, base := range map[string]*basesession.BaseSession{"PasswordAuth": password.baseSession, "Preauth": preauth.baseSession} {
		if base.PrincipalResolver == nil {
			t.Errorf("%s: PrincipalResolver not installed", name)
		}
	}

	var _ OIDCAzureOption = opt
	var _ OIDCGoogleOption = opt
}

func TestSessionAPIs_ActiveImpersonations(t *testing.T) {
	t.Parallel()

	sessionID := ccc.Must(ccc.NewUUID())
	listed := []*sessioninfo.Impersonation{{SessionID: sessionID, Actor: "alice", Principal: accesstypes.RolePrincipal("Editor")}}
	q := &ImpersonationQuery{Actor: "alice"}

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

	t.Run("PasswordAuth passes the query through", func(t *testing.T) {
		t.Parallel()
		ctrl := gomock.NewController(t)
		storage := newPasswordStoreMock(ctrl)
		expectListing(storage.EXPECT().ImpersonationEnabled(), storage.EXPECT().ActiveImpersonations(gomock.Any(), gomock.Any(), gomock.Any()), defaultSessionTimeout, q)

		p, err := NewPasswordAuth[NoCustomData, NoCustomData](storage, cookieKey)
		if err != nil {
			t.Fatalf("NewPasswordAuth() error = %v", err)
		}
		if _, err := p.API().ActiveImpersonations(context.Background(), q); err != nil {
			t.Errorf("ActiveImpersonations() error = %v", err)
		}
	})

	t.Run("OIDC Azure delegates", func(t *testing.T) {
		t.Parallel()
		ctrl := gomock.NewController(t)
		storage := newOIDCStoreMock(ctrl)
		expectListing(storage.EXPECT().ImpersonationEnabled(), storage.EXPECT().ActiveImpersonations(gomock.Any(), gomock.Any(), gomock.Any()), time.Minute, q)

		a := &OIDCAzure[NoCustomData, NoCustomData]{storage: storage, baseSession: &basesession.BaseSession{Storage: storage, SessionTimeout: time.Minute}}
		if _, err := a.API().ActiveImpersonations(context.Background(), q); err != nil {
			t.Errorf("ActiveImpersonations() error = %v", err)
		}
	})

	t.Run("OIDC Google delegates", func(t *testing.T) {
		t.Parallel()
		ctrl := gomock.NewController(t)
		storage := newGoogleOIDCStoreMock(ctrl)
		expectListing(storage.EXPECT().ImpersonationEnabled(), storage.EXPECT().ActiveImpersonations(gomock.Any(), gomock.Any(), gomock.Any()), time.Minute, q)

		a := &OIDCGoogle[NoCustomData, NoCustomData]{storage: storage, baseSession: &basesession.BaseSession{Storage: storage, SessionTimeout: time.Minute}}
		if _, err := a.API().ActiveImpersonations(context.Background(), q); err != nil {
			t.Errorf("ActiveImpersonations() error = %v", err)
		}
	})
}
