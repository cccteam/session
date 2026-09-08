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
	gomock "go.uber.org/mock/gomock"
)

func TestBaseSession_ValidateSessionAPI_PrincipalResolver(t *testing.T) {
	t.Parallel()

	sessionID := ccc.Must(ccc.UUIDFromString("92922509-82d2-4bc7-853a-d73b8926a55f"))
	editor := accesstypes.RolePrincipal("Editor")

	type customData struct{ RoleID string }

	ordinary := func() *sessioninfo.SessionData {
		return &sessioninfo.SessionData{
			SessionInfo: &sessioninfo.SessionInfo{ID: sessionID, Username: "alice", UpdatedAt: time.Now()},
			CustomData:  &customData{RoleID: "Editor"},
		}
	}
	impersonated := func(principal accesstypes.Principal) *sessioninfo.SessionData {
		s := ordinary()
		s.Username = "bob"
		s.Impersonation = &sessioninfo.Impersonation{SessionID: sessionID, Actor: "alice", Principal: principal, ExpiresAt: time.Now().Add(time.Hour)}

		return s
	}
	fromCustomData := func(ctx context.Context) (accesstypes.Principal, error) {
		data, err := sessioninfo.CustomDataFromCtx[*customData](ctx)
		if err != nil {
			return accesstypes.Principal{}, err
		}

		return accesstypes.RolePrincipal(accesstypes.Role(data.RoleID)), nil
	}

	tests := []struct {
		name          string
		session       *sessioninfo.SessionData
		resolver      func(ctx context.Context) (accesstypes.Principal, error)
		wantErr       bool
		wantPrincipal accesstypes.Principal
		wantStored    bool
	}{
		{
			name:          "no resolver: the session user's own principal",
			session:       ordinary(),
			wantPrincipal: accesstypes.UserPrincipal("alice"),
		},
		{
			name:          "an ordinary session acts as the resolver's choice, read from custom session data",
			session:       ordinary(),
			resolver:      fromCustomData,
			wantPrincipal: editor,
			wantStored:    true,
		},
		{
			name:          "a user-principal impersonation runs the resolver too",
			session:       impersonated(accesstypes.UserPrincipal("bob")),
			resolver:      fromCustomData,
			wantPrincipal: editor,
			wantStored:    true,
		},
		{
			name:    "a role-principal impersonation skips the resolver",
			session: impersonated(accesstypes.RolePrincipal("PartnerViewer")),
			resolver: func(context.Context) (accesstypes.Principal, error) {
				return accesstypes.Principal{}, errors.New("must not run")
			},
			wantPrincipal: accesstypes.RolePrincipal("PartnerViewer"),
		},
		{
			name:    "the zero principal keeps the default",
			session: ordinary(),
			resolver: func(context.Context) (accesstypes.Principal, error) {
				return accesstypes.Principal{}, nil
			},
			wantPrincipal: accesstypes.UserPrincipal("alice"),
		},
		{
			name:    "returning the default leaves nothing recorded",
			session: ordinary(),
			resolver: func(ctx context.Context) (accesstypes.Principal, error) {
				return accesstypes.UserPrincipal(accesstypes.User(sessioninfo.FromCtx(ctx).Username)), nil
			},
			wantPrincipal: accesstypes.UserPrincipal("alice"),
		},
		{
			name:    "a resolver error fails the request as a server error, not unauthorized",
			session: ordinary(),
			resolver: func(context.Context) (accesstypes.Principal, error) {
				return accesstypes.Principal{}, errors.New("role lookup failed")
			},
			wantErr: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			ctrl := gomock.NewController(t)
			storage := mock_sessionstorage.NewMockBaseStore(ctrl)
			storage.EXPECT().Session(gomock.Any(), sessionID).Return(tt.session, nil)

			s := &BaseSession{SessionTimeout: time.Minute, Storage: storage, PrincipalResolver: tt.resolver}

			ctx := context.WithValue(context.Background(), sessioninfo.CTXSessionID, sessionID)
			gotCtx, err := s.ValidateSessionAPI(ctx)
			if (err != nil) != tt.wantErr {
				t.Fatalf("ValidateSessionAPI() error = %v, wantErr %v", err, tt.wantErr)
			}
			if tt.wantErr {
				if httpio.HasUnauthorized(err) {
					t.Errorf("ValidateSessionAPI() error = %v, want a server error, not unauthorized", err)
				}

				return
			}
			if got := sessioninfo.PrincipalFromCtx(gotCtx); got != tt.wantPrincipal {
				t.Errorf("PrincipalFromCtx() = %v, want %v", got, tt.wantPrincipal)
			}
			if stored := tt.session.Principal != (accesstypes.Principal{}); stored != tt.wantStored {
				t.Errorf("SessionData.Principal recorded = %v, want %v", stored, tt.wantStored)
			}
		})
	}
}
