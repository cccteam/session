package basesession

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/cccteam/ccc"
	"github.com/cccteam/ccc/accesstypes"
	"github.com/cccteam/httpio"
	"github.com/cccteam/session/cookie"
	"github.com/cccteam/session/mock/mock_cookie"
	"github.com/cccteam/session/sessioninfo"
	"github.com/cccteam/session/sessionstorage/mock/mock_sessionstorage"
	"github.com/go-playground/errors/v5"
	"github.com/google/go-cmp/cmp"
	gomock "go.uber.org/mock/gomock"
)

// ordinarySession is a non-impersonated session row for username, last active at updatedAt.
func ordinarySession(id ccc.UUID, username string, updatedAt time.Time) *sessioninfo.SessionData {
	return &sessioninfo.SessionData{SessionInfo: &sessioninfo.SessionInfo{ID: id, Username: username, UpdatedAt: updatedAt}}
}

func TestBaseSession_StartImpersonatedSession_LocalActor(t *testing.T) {
	t.Parallel()

	sessionID := ccc.Must(ccc.NewUUID())
	sourceID := ccc.Must(ccc.NewUUID())
	source := ccc.NullUUID{UUID: sourceID, Valid: true}

	tests := []struct {
		name           string
		imp            *sessioninfo.Impersonation
		prepare        func(storage *mock_sessionstorage.MockBaseStore, cookieHandler *mock_cookie.MockHandler)
		wantBadRequest bool
		wantForbidden  bool
	}{
		{
			name: "a foreign actor is not checked here",
			imp:  &sessioninfo.Impersonation{Actor: "alice", ActorRealm: "admin-portal", Principal: accesstypes.RolePrincipal("Editor")},
			prepare: func(storage *mock_sessionstorage.MockBaseStore, cookieHandler *mock_cookie.MockHandler) {
				storage.EXPECT().CreateImpersonatedSession(gomock.Any(), gomock.Any(), gomock.Any()).Return(sessionID, nil)
				cookieHandler.EXPECT().NewAuthCookie(gomock.Any(), true, sessionID).Return(cookie.NewValues())
				cookieHandler.EXPECT().CreateXSRFTokenCookie(gomock.Any(), sessionID)
			},
		},
		{
			name: "a local actor with a live source session of their own is verified",
			imp:  &sessioninfo.Impersonation{Actor: "alice", SourceSessionID: source, Principal: accesstypes.RolePrincipal("Editor")},
			prepare: func(storage *mock_sessionstorage.MockBaseStore, cookieHandler *mock_cookie.MockHandler) {
				storage.EXPECT().Session(gomock.Any(), sourceID).Return(ordinarySession(sourceID, "alice", time.Now()), nil)
				storage.EXPECT().CreateImpersonatedSession(gomock.Any(), gomock.Any(), gomock.Any()).Return(sessionID, nil)
				cookieHandler.EXPECT().NewAuthCookie(gomock.Any(), true, sessionID).Return(cookie.NewValues())
				cookieHandler.EXPECT().CreateXSRFTokenCookie(gomock.Any(), sessionID)
			},
		},
		{
			name:           "a local actor without a source session is a bad request",
			imp:            &sessioninfo.Impersonation{Actor: "alice", Principal: accesstypes.RolePrincipal("Editor")},
			prepare:        func(*mock_sessionstorage.MockBaseStore, *mock_cookie.MockHandler) {},
			wantBadRequest: true,
		},
		{
			name: "a source session that is not here is refused",
			imp:  &sessioninfo.Impersonation{Actor: "alice", SourceSessionID: source, Principal: accesstypes.RolePrincipal("Editor")},
			prepare: func(storage *mock_sessionstorage.MockBaseStore, _ *mock_cookie.MockHandler) {
				storage.EXPECT().Session(gomock.Any(), sourceID).Return(nil, httpio.NewNotFoundMessage("no such session"))
			},
			wantForbidden: true,
		},
		{
			name: "a source session of another user is refused",
			imp:  &sessioninfo.Impersonation{Actor: "alice", SourceSessionID: source, Principal: accesstypes.RolePrincipal("Editor")},
			prepare: func(storage *mock_sessionstorage.MockBaseStore, _ *mock_cookie.MockHandler) {
				storage.EXPECT().Session(gomock.Any(), sourceID).Return(ordinarySession(sourceID, "carol", time.Now()), nil)
			},
			wantForbidden: true,
		},
		{
			name: "a destroyed source session is refused",
			imp:  &sessioninfo.Impersonation{Actor: "alice", SourceSessionID: source, Principal: accesstypes.RolePrincipal("Editor")},
			prepare: func(storage *mock_sessionstorage.MockBaseStore, _ *mock_cookie.MockHandler) {
				src := ordinarySession(sourceID, "alice", time.Now())
				src.Expired = true
				storage.EXPECT().Session(gomock.Any(), sourceID).Return(src, nil)
			},
			wantForbidden: true,
		},
		{
			name: "an idle-expired source session is refused",
			imp:  &sessioninfo.Impersonation{Actor: "alice", SourceSessionID: source, Principal: accesstypes.RolePrincipal("Editor")},
			prepare: func(storage *mock_sessionstorage.MockBaseStore, _ *mock_cookie.MockHandler) {
				storage.EXPECT().Session(gomock.Any(), sourceID).Return(ordinarySession(sourceID, "alice", time.Now().Add(-time.Hour)), nil)
			},
			wantForbidden: true,
		},
		{
			name: "an impersonated source session is refused",
			imp:  &sessioninfo.Impersonation{Actor: "alice", SourceSessionID: source, Principal: accesstypes.RolePrincipal("Editor")},
			prepare: func(storage *mock_sessionstorage.MockBaseStore, _ *mock_cookie.MockHandler) {
				src := ordinarySession(sourceID, "alice", time.Now())
				src.Impersonation = &sessioninfo.Impersonation{SessionID: sourceID, Actor: "root", Principal: accesstypes.UserPrincipal("alice")}
				storage.EXPECT().Session(gomock.Any(), sourceID).Return(src, nil)
			},
			wantForbidden: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			ctrl := gomock.NewController(t)
			storage := mock_sessionstorage.NewMockBaseStore(ctrl)
			cookieHandler := mock_cookie.NewMockHandler(ctrl)
			tt.prepare(storage, cookieHandler)

			s := &BaseSession{SessionTimeout: 10 * time.Minute, Storage: storage, CookieHandler: cookieHandler}
			req := &sessioninfo.NewSessionRequest{Reason: sessioninfo.ReasonImpersonation, Username: "alice"}
			_, err := s.StartImpersonatedSession(context.Background(), httptest.NewRecorder(), req, tt.imp)
			wantErr := tt.wantBadRequest || tt.wantForbidden
			if (err != nil) != wantErr {
				t.Fatalf("StartImpersonatedSession() error = %v, wantErr %v", err, wantErr)
			}
			if httpio.HasBadRequest(err) != tt.wantBadRequest || httpio.HasForbidden(err) != tt.wantForbidden {
				t.Errorf("error = %v; want badRequest=%v forbidden=%v", err, tt.wantBadRequest, tt.wantForbidden)
			}
		})
	}
}

func TestBaseSession_ValidateSessionAPI_RefreshesLocalActorSource(t *testing.T) {
	t.Parallel()

	sessionID := ccc.Must(ccc.NewUUID())
	sourceID := ccc.Must(ccc.NewUUID())

	newSession := func(imp *sessioninfo.Impersonation) *sessioninfo.SessionData {
		imp.SessionID = sessionID
		imp.ExpiresAt = time.Now().Add(time.Hour)

		return &sessioninfo.SessionData{
			// Last activity is past the five-second rate limit, so activity is written.
			SessionInfo:   &sessioninfo.SessionInfo{ID: sessionID, Username: "alice", UpdatedAt: time.Now().Add(-10 * time.Second)},
			Impersonation: imp,
		}
	}

	tests := []struct {
		name    string
		session *sessioninfo.SessionData
		prepare func(storage *mock_sessionstorage.MockBaseStore)
	}{
		{
			name:    "a local actor's source session is refreshed with the impersonated session",
			session: newSession(&sessioninfo.Impersonation{Actor: "alice", SourceSessionID: ccc.NullUUID{UUID: sourceID, Valid: true}, Principal: accesstypes.RolePrincipal("Editor")}),
			prepare: func(storage *mock_sessionstorage.MockBaseStore) {
				storage.EXPECT().UpdateSessionActivity(gomock.Any(), sessionID).Return(nil)
				storage.EXPECT().UpdateSessionActivity(gomock.Any(), sourceID).Return(nil)
			},
		},
		{
			name:    "a foreign actor's source session lives elsewhere and is not touched",
			session: newSession(&sessioninfo.Impersonation{Actor: "alice", ActorRealm: "admin-portal", SourceSessionID: ccc.NullUUID{UUID: sourceID, Valid: true}, Principal: accesstypes.RolePrincipal("Editor")}),
			prepare: func(storage *mock_sessionstorage.MockBaseStore) {
				storage.EXPECT().UpdateSessionActivity(gomock.Any(), sessionID).Return(nil)
			},
		},
		{
			name:    "a failed source refresh is logged, not returned",
			session: newSession(&sessioninfo.Impersonation{Actor: "alice", SourceSessionID: ccc.NullUUID{UUID: sourceID, Valid: true}, Principal: accesstypes.UserPrincipal("bob")}),
			prepare: func(storage *mock_sessionstorage.MockBaseStore) {
				storage.EXPECT().UpdateSessionActivity(gomock.Any(), sessionID).Return(nil)
				storage.EXPECT().UpdateSessionActivity(gomock.Any(), sourceID).Return(httpio.NewNotFoundMessage("gone"))
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			ctrl := gomock.NewController(t)
			storage := mock_sessionstorage.NewMockBaseStore(ctrl)
			storage.EXPECT().Session(gomock.Any(), sessionID).Return(tt.session, nil)
			tt.prepare(storage)

			s := &BaseSession{SessionTimeout: 10 * time.Minute, Storage: storage}
			ctx := context.WithValue(context.Background(), sessioninfo.CTXSessionID, sessionID)
			if _, err := s.ValidateSessionAPI(ctx); err != nil {
				t.Fatalf("ValidateSessionAPI() error = %v", err)
			}
		})
	}
}

func TestBaseSession_EndImpersonationAPI(t *testing.T) {
	t.Parallel()

	sessionID := ccc.Must(ccc.NewUUID())
	sourceID := ccc.Must(ccc.NewUUID())
	source := ccc.NullUUID{UUID: sourceID, Valid: true}

	impersonated := func(imp *sessioninfo.Impersonation) *sessioninfo.SessionData {
		imp.SessionID = sessionID

		return &sessioninfo.SessionData{SessionInfo: &sessioninfo.SessionInfo{ID: sessionID, Username: "alice"}, Impersonation: imp}
	}
	ended := func(storage *mock_sessionstorage.MockBaseStore) {
		storage.EXPECT().EndImpersonation(gomock.Any(), sessionID, sessioninfo.ImpersonationEndedByRelease).Return(nil)
		storage.EXPECT().DestroySession(gomock.Any(), sessionID).Return(nil)
	}

	tests := []struct {
		name           string
		session        *sessioninfo.SessionData
		prepare        func(storage *mock_sessionstorage.MockBaseStore, cookieHandler *mock_cookie.MockHandler)
		wantRestored   bool
		wantBadRequest bool
		wantErr        bool
		wantEvents     []sessioninfo.ImpersonationEventKind
	}{
		{
			name:           "an ordinary session is not impersonated",
			session:        ordinarySession(sessionID, "alice", time.Now()),
			prepare:        func(*mock_sessionstorage.MockBaseStore, *mock_cookie.MockHandler) {},
			wantBadRequest: true,
			wantErr:        true,
		},
		{
			name:    "a local actor returns to their live source session",
			session: impersonated(&sessioninfo.Impersonation{Actor: "alice", SourceSessionID: source, Principal: accesstypes.RolePrincipal("Editor")}),
			prepare: func(storage *mock_sessionstorage.MockBaseStore, cookieHandler *mock_cookie.MockHandler) {
				ended(storage)
				storage.EXPECT().Session(gomock.Any(), sourceID).Return(ordinarySession(sourceID, "alice", time.Now()), nil)
				cookieHandler.EXPECT().NewAuthCookie(gomock.Any(), true, sourceID).Return(cookie.NewValues())
				cookieHandler.EXPECT().CreateXSRFTokenCookie(gomock.Any(), sourceID)
			},
			wantRestored: true,
			wantEvents:   []sessioninfo.ImpersonationEventKind{sessioninfo.ImpersonationEnded},
		},
		{
			name:    "a source session that has since expired cannot be returned to",
			session: impersonated(&sessioninfo.Impersonation{Actor: "alice", SourceSessionID: source, Principal: accesstypes.UserPrincipal("bob")}),
			prepare: func(storage *mock_sessionstorage.MockBaseStore, _ *mock_cookie.MockHandler) {
				ended(storage)
				src := ordinarySession(sourceID, "alice", time.Now())
				src.Expired = true
				storage.EXPECT().Session(gomock.Any(), sourceID).Return(src, nil)
			},
			wantEvents: []sessioninfo.ImpersonationEventKind{sessioninfo.ImpersonationEnded},
		},
		{
			name:    "a source session renamed away from the actor cannot be returned to",
			session: impersonated(&sessioninfo.Impersonation{Actor: "alice", SourceSessionID: source, Principal: accesstypes.RolePrincipal("Editor")}),
			prepare: func(storage *mock_sessionstorage.MockBaseStore, _ *mock_cookie.MockHandler) {
				ended(storage)
				storage.EXPECT().Session(gomock.Any(), sourceID).Return(ordinarySession(sourceID, "alicia", time.Now()), nil)
			},
			wantEvents: []sessioninfo.ImpersonationEventKind{sessioninfo.ImpersonationEnded},
		},
		{
			name:    "a source session that is gone cannot be returned to",
			session: impersonated(&sessioninfo.Impersonation{Actor: "alice", SourceSessionID: source, Principal: accesstypes.RolePrincipal("Editor")}),
			prepare: func(storage *mock_sessionstorage.MockBaseStore, _ *mock_cookie.MockHandler) {
				ended(storage)
				storage.EXPECT().Session(gomock.Any(), sourceID).Return(nil, httpio.NewNotFoundMessage("gone"))
			},
			wantEvents: []sessioninfo.ImpersonationEventKind{sessioninfo.ImpersonationEnded},
		},
		{
			name:    "a foreign actor's session ends without a lookup: their own session is in another application",
			session: impersonated(&sessioninfo.Impersonation{Actor: "alice", ActorRealm: "admin-portal", SourceSessionID: source, Principal: accesstypes.RolePrincipal("Editor")}),
			prepare: func(storage *mock_sessionstorage.MockBaseStore, _ *mock_cookie.MockHandler) {
				ended(storage)
			},
			wantEvents: []sessioninfo.ImpersonationEventKind{sessioninfo.ImpersonationEnded},
		},
		{
			name:    "a failed record end fails the call before the session is destroyed",
			session: impersonated(&sessioninfo.Impersonation{Actor: "alice", SourceSessionID: source, Principal: accesstypes.RolePrincipal("Editor")}),
			prepare: func(storage *mock_sessionstorage.MockBaseStore, _ *mock_cookie.MockHandler) {
				storage.EXPECT().EndImpersonation(gomock.Any(), sessionID, sessioninfo.ImpersonationEndedByRelease).Return(errors.New("db down"))
			},
			wantErr: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			ctrl := gomock.NewController(t)
			storage := mock_sessionstorage.NewMockBaseStore(ctrl)
			cookieHandler := mock_cookie.NewMockHandler(ctrl)
			tt.prepare(storage, cookieHandler)

			var events []sessioninfo.ImpersonationEventKind
			s := &BaseSession{
				SessionTimeout: 10 * time.Minute,
				Storage:        storage,
				CookieHandler:  cookieHandler,
				ImpersonationAudit: func(_ context.Context, event sessioninfo.ImpersonationEvent) error {
					events = append(events, event.Kind)
					if event.Impersonation.EndReason != sessioninfo.ImpersonationEndedByRelease || event.Impersonation.EndedAt == nil {
						return errors.Newf("unexpected end %+v", event.Impersonation)
					}

					return nil
				},
			}

			ctx := context.WithValue(context.Background(), sessioninfo.CTXSessionID, sessionID)
			ctx = context.WithValue(ctx, sessioninfo.CtxSessionInfo, tt.session)
			restored, err := s.EndImpersonationAPI(ctx, httptest.NewRecorder())
			if (err != nil) != tt.wantErr {
				t.Fatalf("EndImpersonationAPI() error = %v, wantErr %v", err, tt.wantErr)
			}
			if httpio.HasBadRequest(err) != tt.wantBadRequest {
				t.Errorf("error = %v; want badRequest=%v", err, tt.wantBadRequest)
			}
			if restored != tt.wantRestored {
				t.Errorf("restored = %v, want %v", restored, tt.wantRestored)
			}
			if diff := cmp.Diff(tt.wantEvents, events); diff != "" {
				t.Errorf("events mismatch (-want +got):\n%s", diff)
			}
		})
	}
}

func TestBaseSession_EndImpersonation(t *testing.T) {
	t.Parallel()

	sessionID := ccc.Must(ccc.NewUUID())
	sourceID := ccc.Must(ccc.NewUUID())

	ctrl := gomock.NewController(t)
	storage := mock_sessionstorage.NewMockBaseStore(ctrl)
	storage.EXPECT().EndImpersonation(gomock.Any(), sessionID, sessioninfo.ImpersonationEndedByRelease).Return(nil)
	storage.EXPECT().DestroySession(gomock.Any(), sessionID).Return(nil)
	storage.EXPECT().Session(gomock.Any(), sourceID).Return(ordinarySession(sourceID, "alice", time.Now()), nil)
	cookieHandler := mock_cookie.NewMockHandler(ctrl)
	cookieHandler.EXPECT().NewAuthCookie(gomock.Any(), true, sourceID).Return(cookie.NewValues())
	cookieHandler.EXPECT().CreateXSRFTokenCookie(gomock.Any(), sourceID)

	s := &BaseSession{
		SessionTimeout: 10 * time.Minute,
		Storage:        storage,
		CookieHandler:  cookieHandler,
		Handle: func(handler func(w http.ResponseWriter, r *http.Request) error) http.HandlerFunc {
			return func(w http.ResponseWriter, r *http.Request) { _ = handler(w, r) }
		},
	}

	session := &sessioninfo.SessionData{
		SessionInfo:   &sessioninfo.SessionInfo{ID: sessionID, Username: "alice"},
		Impersonation: &sessioninfo.Impersonation{SessionID: sessionID, Actor: "alice", SourceSessionID: ccc.NullUUID{UUID: sourceID, Valid: true}, Principal: accesstypes.RolePrincipal("Editor")},
	}
	ctx := context.WithValue(context.Background(), sessioninfo.CTXSessionID, sessionID)
	ctx = context.WithValue(ctx, sessioninfo.CtxSessionInfo, session)
	rr := httptest.NewRecorder()
	s.EndImpersonation().ServeHTTP(rr, httptest.NewRequestWithContext(ctx, http.MethodPost, "/end", http.NoBody))

	if rr.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200: %s", rr.Code, rr.Body.String())
	}
	var body EndImpersonationResponse
	if err := json.Unmarshal(rr.Body.Bytes(), &body); err != nil {
		t.Fatalf("json.Unmarshal() error = %v", err)
	}
	if !body.Restored {
		t.Errorf("Restored = false, want true")
	}
}
