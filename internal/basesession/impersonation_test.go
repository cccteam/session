package basesession

import (
	"context"
	"testing"
	"time"

	"github.com/cccteam/ccc"
	"github.com/cccteam/ccc/accesstypes"
	"github.com/cccteam/httpio"
	"github.com/cccteam/session/sessioninfo"
	"github.com/cccteam/session/sessionstorage/mock/mock_sessionstorage"
	"github.com/go-playground/errors/v5"
	"github.com/google/go-cmp/cmp"
	gomock "go.uber.org/mock/gomock"
)

func TestBaseSession_ValidateSessionAPI_Impersonation(t *testing.T) {
	t.Parallel()

	sessionID := ccc.Must(ccc.UUIDFromString("92922509-82d2-4bc7-853a-d73b8926a55f"))

	newSession := func(expiresIn time.Duration) *sessioninfo.SessionData {
		return &sessioninfo.SessionData{
			SessionInfo: &sessioninfo.SessionInfo{ID: sessionID, Username: "bob", UpdatedAt: time.Now()},
			Impersonation: &sessioninfo.Impersonation{
				SessionID: sessionID,
				Actor:     "alice",
				Principal: accesstypes.UserPrincipal("bob"),
				Mask:      accesstypes.MaskPermissions(accesstypes.DenyAll(), accesstypes.Read),
				StartedAt: time.Now().Add(-time.Minute),
				ExpiresAt: time.Now().Add(expiresIn),
			},
		}
	}

	tests := []struct {
		name             string
		session          *sessioninfo.SessionData
		prepare          func(storage *mock_sessionstorage.MockBaseStore, session *sessioninfo.SessionData)
		wantUnauthorized bool
		wantEnded        bool
		wantEvents       []sessioninfo.ImpersonationEventKind
	}{
		{
			name:    "live impersonated session reaches the context",
			session: newSession(time.Hour),
			prepare: func(storage *mock_sessionstorage.MockBaseStore, session *sessioninfo.SessionData) {
				storage.EXPECT().Session(gomock.Any(), sessionID).Return(session, nil)
			},
		},
		{
			name:    "hard cap passed: refused, record ended as Expired, event announced",
			session: newSession(-time.Second),
			prepare: func(storage *mock_sessionstorage.MockBaseStore, session *sessioninfo.SessionData) {
				storage.EXPECT().Session(gomock.Any(), sessionID).Return(session, nil)
				storage.EXPECT().EndImpersonation(gomock.Any(), sessionID, sessioninfo.ImpersonationEndedByExpiry).Return(nil)
			},
			wantUnauthorized: true,
			wantEnded:        true,
			wantEvents:       []sessioninfo.ImpersonationEventKind{sessioninfo.ImpersonationEnded},
		},
		{
			name: "idle timeout passed: refused and record ended as Expired",
			session: func() *sessioninfo.SessionData {
				s := newSession(time.Hour)
				s.UpdatedAt = time.Now().Add(-time.Hour)

				return s
			}(),
			prepare: func(storage *mock_sessionstorage.MockBaseStore, session *sessioninfo.SessionData) {
				storage.EXPECT().Session(gomock.Any(), sessionID).Return(session, nil)
				storage.EXPECT().EndImpersonation(gomock.Any(), sessionID, sessioninfo.ImpersonationEndedByExpiry).Return(nil)
			},
			wantUnauthorized: true,
			wantEnded:        true,
			wantEvents:       []sessioninfo.ImpersonationEventKind{sessioninfo.ImpersonationEnded},
		},
		{
			name: "destroyed session whose record already ended is not ended again",
			session: func() *sessioninfo.SessionData {
				s := newSession(time.Hour)
				s.Expired = true
				ended := time.Now()
				s.Impersonation.EndedAt = &ended
				s.Impersonation.EndReason = sessioninfo.ImpersonationEndedByLogout

				return s
			}(),
			prepare: func(storage *mock_sessionstorage.MockBaseStore, session *sessioninfo.SessionData) {
				storage.EXPECT().Session(gomock.Any(), sessionID).Return(session, nil)
			},
			wantUnauthorized: true,
			wantEnded:        true,
		},
		{
			name:    "a failing end write is logged, not returned",
			session: newSession(-time.Second),
			prepare: func(storage *mock_sessionstorage.MockBaseStore, session *sessioninfo.SessionData) {
				storage.EXPECT().Session(gomock.Any(), sessionID).Return(session, nil)
				storage.EXPECT().EndImpersonation(gomock.Any(), sessionID, sessioninfo.ImpersonationEndedByExpiry).Return(errors.New("db down"))
			},
			wantUnauthorized: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			ctrl := gomock.NewController(t)
			storage := mock_sessionstorage.NewMockBaseStore(ctrl)
			tt.prepare(storage, tt.session)

			var events []sessioninfo.ImpersonationEventKind
			s := &BaseSession{
				SessionTimeout: time.Minute,
				Storage:        storage,
				ImpersonationAudit: func(_ context.Context, event sessioninfo.ImpersonationEvent) error {
					events = append(events, event.Kind)

					return nil
				},
			}

			ctx := context.WithValue(context.Background(), sessioninfo.CTXSessionID, sessionID)
			gotCtx, err := s.ValidateSessionAPI(ctx)
			if httpio.HasUnauthorized(err) != tt.wantUnauthorized {
				t.Fatalf("ValidateSessionAPI() error = %v, wantUnauthorized %v", err, tt.wantUnauthorized)
			}
			if tt.wantUnauthorized {
				if (tt.session.Impersonation.EndedAt != nil) != tt.wantEnded {
					t.Errorf("record EndedAt set = %v, want %v", tt.session.Impersonation.EndedAt != nil, tt.wantEnded)
				}
				if diff := cmp.Diff(tt.wantEvents, events); diff != "" {
					t.Errorf("events mismatch (-want +got):\n%s", diff)
				}

				return
			}

			imp, ok := sessioninfo.ImpersonationFromCtx(gotCtx)
			if !ok || imp != tt.session.Impersonation {
				t.Errorf("ImpersonationFromCtx() = (%v, %v), want the loaded record", imp, ok)
			}
			if got := sessioninfo.ActorFromCtx(gotCtx); got != "alice" {
				t.Errorf("ActorFromCtx() = %q, want alice", got)
			}
			if got := sessioninfo.MaskFromCtx(gotCtx); got.Allows(accesstypes.Update) || !got.Allows(accesstypes.Read) {
				t.Errorf("MaskFromCtx() = %v, want read-only", got)
			}
		})
	}
}

func TestBaseSession_EmitImpersonationEvent(t *testing.T) {
	t.Parallel()

	imp := &sessioninfo.Impersonation{Actor: "alice", Principal: accesstypes.RolePrincipal("Editor")}

	tests := []struct {
		name    string
		hook    func(context.Context, sessioninfo.ImpersonationEvent) error
		wantErr bool
	}{
		{name: "no hook: logs only"},
		{
			name: "hook receives the event",
			hook: func(_ context.Context, event sessioninfo.ImpersonationEvent) error {
				if event.Kind != sessioninfo.ImpersonationIdentityOperationBlocked || event.Operation != "ChangeUserPassword" || event.Impersonation != imp || event.At.IsZero() {
					return errors.Newf("unexpected event %+v", event)
				}

				return nil
			},
		},
		{
			name:    "hook error is returned wrapped",
			hook:    func(context.Context, sessioninfo.ImpersonationEvent) error { return errors.New("audit store down") },
			wantErr: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			s := &BaseSession{ImpersonationAudit: tt.hook}
			err := s.EmitImpersonationEvent(context.Background(), sessioninfo.ImpersonationIdentityOperationBlocked, imp, "ChangeUserPassword")
			if (err != nil) != tt.wantErr {
				t.Errorf("EmitImpersonationEvent() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func TestBaseSession_LogoutAPI_Impersonation(t *testing.T) {
	t.Parallel()

	sessionID := ccc.Must(ccc.UUIDFromString("92922509-82d2-4bc7-853a-d73b8926a55f"))

	tests := []struct {
		name       string
		session    *sessioninfo.SessionData
		wantEvents []sessioninfo.ImpersonationEventKind
	}{
		{name: "unvalidated context: destroy only"},
		{
			name:       "validated impersonated session announces Ended by Logout",
			session:    &sessioninfo.SessionData{SessionInfo: &sessioninfo.SessionInfo{ID: sessionID}, Impersonation: &sessioninfo.Impersonation{SessionID: sessionID, Actor: "alice", Principal: accesstypes.UserPrincipal("bob")}},
			wantEvents: []sessioninfo.ImpersonationEventKind{sessioninfo.ImpersonationEnded},
		},
		{
			name:    "validated ordinary session: no event",
			session: &sessioninfo.SessionData{SessionInfo: &sessioninfo.SessionInfo{ID: sessionID}},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			ctrl := gomock.NewController(t)
			storage := mock_sessionstorage.NewMockBaseStore(ctrl)
			storage.EXPECT().DestroySession(gomock.Any(), sessionID).Return(nil)

			var events []sessioninfo.ImpersonationEventKind
			s := &BaseSession{
				Storage: storage,
				ImpersonationAudit: func(_ context.Context, event sessioninfo.ImpersonationEvent) error {
					events = append(events, event.Kind)
					if event.Impersonation.EndReason != sessioninfo.ImpersonationEndedByLogout || event.Impersonation.EndedAt == nil {
						return errors.Newf("unexpected end %+v", event.Impersonation)
					}

					return nil
				},
			}

			ctx := context.WithValue(context.Background(), sessioninfo.CTXSessionID, sessionID)
			if tt.session != nil {
				ctx = context.WithValue(ctx, sessioninfo.CtxSessionInfo, tt.session)
			}
			if err := s.LogoutAPI(ctx); err != nil {
				t.Fatalf("LogoutAPI() error = %v", err)
			}
			if diff := cmp.Diff(tt.wantEvents, events); diff != "" {
				t.Errorf("events mismatch (-want +got):\n%s", diff)
			}
		})
	}
}

func TestNewImpersonationResponse(t *testing.T) {
	t.Parallel()

	expires := time.Date(2026, 8, 27, 11, 0, 0, 0, time.UTC)

	tests := []struct {
		name string
		imp  *sessioninfo.Impersonation
		want *ImpersonationResponse
	}{
		{name: "nil in, nil out"},
		{
			name: "read-only user impersonation",
			imp: &sessioninfo.Impersonation{
				Actor:      "alice",
				ActorRealm: "admin-portal",
				Principal:  accesstypes.UserPrincipal("bob"),
				Mask:       accesstypes.MaskPermissions(accesstypes.DenyAll(), accesstypes.Read, accesstypes.List),
				Reason:     "ticket",
				ExpiresAt:  expires,
			},
			want: &ImpersonationResponse{
				Actor: "alice", ActorRealm: "admin-portal", PrincipalKind: "User", Principal: "bob",
				Mask: []string{"List", "Read"}, Reason: "ticket", ExpiresAt: expires,
			},
		},
		{
			name: "unrestricted role impersonation omits the mask",
			imp:  &sessioninfo.Impersonation{Actor: "alice", Principal: accesstypes.RolePrincipal("Editor"), ExpiresAt: expires},
			want: &ImpersonationResponse{Actor: "alice", PrincipalKind: "Role", Principal: "Editor", ExpiresAt: expires},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			if diff := cmp.Diff(tt.want, NewImpersonationResponse(tt.imp)); diff != "" {
				t.Errorf("NewImpersonationResponse() mismatch (-want +got):\n%s", diff)
			}
		})
	}
}
