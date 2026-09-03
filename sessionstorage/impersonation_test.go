package sessionstorage

import (
	"context"
	"testing"
	"time"

	"github.com/cccteam/ccc"
	"github.com/cccteam/ccc/accesstypes"
	"github.com/cccteam/session/internal/dbtype"
	"github.com/cccteam/session/sessioninfo"
	"github.com/cccteam/session/sessionstorage/internal/postgres"
	"github.com/cccteam/session/sessionstorage/internal/spanner"
	"github.com/go-playground/errors/v5"
	"github.com/google/go-cmp/cmp"
	gomock "go.uber.org/mock/gomock"
)

func TestNewImpersonationTable(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name      string
		tableName string
		wantErr   bool
	}{
		{name: "valid", tableName: "PartnerSessionImpersonations"},
		{name: "underscore prefix", tableName: "_imp"},
		{name: "rejects digits first", tableName: "1imp", wantErr: true},
		{name: "rejects punctuation", tableName: "Session-Impersonations", wantErr: true},
		{name: "rejects empty", tableName: "", wantErr: true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			table, err := NewImpersonationTable(tt.tableName)
			if (err != nil) != tt.wantErr {
				t.Fatalf("NewImpersonationTable() error = %v, wantErr %v", err, tt.wantErr)
			}
			if err == nil && table.TableName() != tt.tableName {
				t.Errorf("TableName() = %q, want %q", table.TableName(), tt.tableName)
			}
		})
	}
}

func TestWithImpersonation_EnablesBothDrivers(t *testing.T) {
	t.Parallel()

	table, err := NewImpersonationTable("SessionImpersonations")
	if err != nil {
		t.Fatal(err)
	}
	opt := WithImpersonation(table)

	sp := spanner.NewSessionStorageDriver(nil)
	opt.applySpanner(sp)
	if !sp.ImpersonationEnabled() {
		t.Error("spanner driver not enabled")
	}

	pg := postgres.NewSessionStorageDriver(nil)
	opt.applyPostgres(pg)
	if !pg.ImpersonationEnabled() {
		t.Error("postgres driver not enabled")
	}

	if spanner.NewSessionStorageDriver(nil).ImpersonationEnabled() {
		t.Error("driver enabled without the option")
	}
}

func Test_sessionStorage_Session_MapsImpersonation(t *testing.T) {
	t.Parallel()

	sessionID := ccc.Must(ccc.UUIDFromString("123e4567-e89b-12d3-a456-426614174000"))
	started := time.Date(2026, 8, 27, 10, 0, 0, 0, time.UTC)

	tests := []struct {
		name string
		row  *dbtype.Impersonation
		want *sessioninfo.Impersonation
	}{
		{name: "not impersonated"},
		{
			name: "impersonated role",
			row: &dbtype.Impersonation{
				SessionID:     sessionID,
				ActorUsername: "alice",
				PrincipalKind: dbtype.PrincipalKindRole,
				PrincipalRole: strPtr("Editor"),
				StartedAt:     started,
				ExpiresAt:     started.Add(time.Hour),
			},
			want: &sessioninfo.Impersonation{
				SessionID: sessionID,
				Actor:     "alice",
				Principal: accesstypes.RolePrincipal("Editor"),
				StartedAt: started,
				ExpiresAt: started.Add(time.Hour),
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			ctrl := gomock.NewController(t)
			mockDB := NewMockdb(ctrl)
			mockDB.EXPECT().Session(gomock.Any(), sessionID).Return(&dbtype.SessionData{
				Session:       &dbtype.Session{ID: sessionID, Username: "alice"},
				Impersonation: tt.row,
			}, nil)

			s := &sessionStorage{db: mockDB}
			got, err := s.Session(context.Background(), sessionID)
			if err != nil {
				t.Fatalf("Session() error = %v", err)
			}
			if diff := cmp.Diff(tt.want, got.Impersonation, principalComparer, maskComparer); diff != "" {
				t.Errorf("Session().Impersonation mismatch (-want +got):\n%s", diff)
			}
		})
	}
}

func Test_sessionStorage_CreateImpersonatedSession(t *testing.T) {
	t.Parallel()

	sessionID := ccc.Must(ccc.UUIDFromString("123e4567-e89b-12d3-a456-426614174000"))
	expires := time.Date(2026, 8, 27, 11, 0, 0, 0, time.UTC)

	tests := []struct {
		name    string
		prepare func(*Mockdb)
		wantErr bool
	}{
		{
			name: "renders the insert row and returns the id",
			prepare: func(mockDB *Mockdb) {
				mockDB.EXPECT().
					InsertImpersonatedSession(gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any()).
					DoAndReturn(func(_ context.Context, session *dbtype.InsertSession, req *sessioninfo.NewSessionRequest, imp *dbtype.InsertImpersonation) (ccc.UUID, error) {
						if session.Username != "bob" || req.Reason != sessioninfo.ReasonImpersonation {
							return ccc.NilUUID, errors.Newf("unexpected session %+v / request %+v", session, req)
						}
						want := &dbtype.InsertImpersonation{
							ActorUsername: "alice",
							PrincipalKind: dbtype.PrincipalKindUser,
							PrincipalUser: strPtr("bob"),
							Mask:          strPtr("List,Read"),
							ExpiresAt:     expires,
						}
						if diff := cmp.Diff(want, imp); diff != "" {
							return ccc.NilUUID, errors.New("unexpected InsertImpersonation: " + diff)
						}

						return sessionID, nil
					})
			},
		},
		{
			name: "propagates the driver error",
			prepare: func(mockDB *Mockdb) {
				mockDB.EXPECT().InsertImpersonatedSession(gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any()).Return(ccc.NilUUID, errors.New("not configured"))
			},
			wantErr: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			ctrl := gomock.NewController(t)
			mockDB := NewMockdb(ctrl)
			tt.prepare(mockDB)

			s := &sessionStorage{db: mockDB}
			imp := &sessioninfo.Impersonation{
				Actor:     "alice",
				Principal: accesstypes.UserPrincipal("bob"),
				Mask:      accesstypes.MaskPermissions(accesstypes.Read, accesstypes.List),
				ExpiresAt: expires,
			}
			got, err := s.CreateImpersonatedSession(context.Background(), &sessioninfo.NewSessionRequest{Reason: sessioninfo.ReasonImpersonation, Username: "bob"}, imp)
			if (err != nil) != tt.wantErr {
				t.Fatalf("CreateImpersonatedSession() error = %v, wantErr %v", err, tt.wantErr)
			}
			if !tt.wantErr && got != sessionID {
				t.Errorf("CreateImpersonatedSession() = %v, want %v", got, sessionID)
			}
		})
	}
}

func TestOIDC_CreateImpersonatedSession(t *testing.T) {
	t.Parallel()

	sessionID := ccc.Must(ccc.UUIDFromString("123e4567-e89b-12d3-a456-426614174000"))
	expires := time.Date(2026, 8, 27, 11, 0, 0, 0, time.UTC)

	tests := []struct {
		name    string
		prepare func(*Mockdb)
		wantErr bool
	}{
		{
			name: "renders an OIDC session row without an identity provider session ID",
			prepare: func(mockDB *Mockdb) {
				mockDB.EXPECT().
					InsertImpersonatedSessionOIDC(gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any()).
					DoAndReturn(func(_ context.Context, session *dbtype.InsertOIDCSession, req *sessioninfo.NewSessionRequest, imp *dbtype.InsertImpersonation) (ccc.UUID, error) {
						if session.OidcSID != "" || session.Username != "alice" || req.Reason != sessioninfo.ReasonImpersonation {
							return ccc.NilUUID, errors.Newf("unexpected session %+v / request %+v", session, req)
						}
						want := &dbtype.InsertImpersonation{
							ActorUsername: "alice",
							PrincipalKind: dbtype.PrincipalKindRole,
							PrincipalRole: strPtr("Editor"),
							ExpiresAt:     expires,
						}
						if diff := cmp.Diff(want, imp); diff != "" {
							return ccc.NilUUID, errors.New("unexpected InsertImpersonation: " + diff)
						}

						return sessionID, nil
					})
			},
		},
		{
			name: "propagates the driver error",
			prepare: func(mockDB *Mockdb) {
				mockDB.EXPECT().InsertImpersonatedSessionOIDC(gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any()).Return(ccc.NilUUID, errors.New("not configured"))
			},
			wantErr: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			ctrl := gomock.NewController(t)
			mockDB := NewMockdb(ctrl)
			tt.prepare(mockDB)

			s := &OIDC{sessionStorage: sessionStorage{db: mockDB}}
			imp := &sessioninfo.Impersonation{Actor: "alice", Principal: accesstypes.RolePrincipal("Editor"), ExpiresAt: expires}
			got, err := s.CreateImpersonatedSession(context.Background(), &sessioninfo.NewSessionRequest{Reason: sessioninfo.ReasonImpersonation, Username: "alice"}, imp)
			if (err != nil) != tt.wantErr {
				t.Fatalf("CreateImpersonatedSession() error = %v, wantErr %v", err, tt.wantErr)
			}
			if !tt.wantErr && got != sessionID {
				t.Errorf("CreateImpersonatedSession() = %v, want %v", got, sessionID)
			}
		})
	}
}

func Test_sessionStorage_ImpersonationDelegates(t *testing.T) {
	t.Parallel()

	sessionID := ccc.Must(ccc.UUIDFromString("123e4567-e89b-12d3-a456-426614174000"))

	t.Run("ImpersonationEnabled", func(t *testing.T) {
		t.Parallel()
		ctrl := gomock.NewController(t)
		mockDB := NewMockdb(ctrl)
		mockDB.EXPECT().ImpersonationEnabled().Return(true)

		if !(&sessionStorage{db: mockDB}).ImpersonationEnabled() {
			t.Error("ImpersonationEnabled() = false, want true")
		}
	})

	t.Run("EndImpersonation passes the reason as text and wraps errors", func(t *testing.T) {
		t.Parallel()
		ctrl := gomock.NewController(t)
		mockDB := NewMockdb(ctrl)
		mockDB.EXPECT().EndImpersonation(gomock.Any(), sessionID, "Expired").Return(errors.New("boom"))

		if err := (&sessionStorage{db: mockDB}).EndImpersonation(context.Background(), sessionID, sessioninfo.ImpersonationEndedByExpiry); err == nil {
			t.Error("EndImpersonation() error = nil, want error")
		}
	})

	t.Run("DestroyImpersonatedSessions delegates by actor", func(t *testing.T) {
		t.Parallel()
		ctrl := gomock.NewController(t)
		mockDB := NewMockdb(ctrl)
		mockDB.EXPECT().DestroyImpersonatedSessions(gomock.Any(), "alice").Return(nil)

		if err := (&sessionStorage{db: mockDB}).DestroyImpersonatedSessions(context.Background(), "alice"); err != nil {
			t.Errorf("DestroyImpersonatedSessions() error = %v", err)
		}
	})
}

var (
	principalComparer = cmp.Comparer(func(a, b accesstypes.Principal) bool { return a == b })
	maskComparer      = cmp.Comparer(func(a, b accesstypes.PermissionMask) bool { return a.String() == b.String() })
)

func strPtr(s string) *string { return &s }

func Test_sessionStorage_ActiveImpersonations(t *testing.T) {
	t.Parallel()

	sessionID := ccc.Must(ccc.UUIDFromString("123e4567-e89b-12d3-a456-426614174000"))
	started := time.Date(2026, 8, 27, 10, 0, 0, 0, time.UTC)
	activeSince := started.Add(-10 * time.Minute)
	q := &sessioninfo.ImpersonationQuery{Actor: "alice"}

	tests := []struct {
		name    string
		prepare func(*Mockdb)
		want    []*sessioninfo.Impersonation
		wantErr bool
	}{
		{
			name: "maps every row and passes the cutoff and query through",
			prepare: func(mockDB *Mockdb) {
				mockDB.EXPECT().ActiveImpersonations(gomock.Any(), activeSince, q).Return([]*dbtype.Impersonation{{
					SessionID:     sessionID,
					ActorUsername: "alice",
					PrincipalKind: dbtype.PrincipalKindRole,
					PrincipalRole: strPtr("Editor"),
					StartedAt:     started,
					ExpiresAt:     started.Add(time.Hour),
				}}, nil)
			},
			want: []*sessioninfo.Impersonation{{
				SessionID: sessionID,
				Actor:     "alice",
				Principal: accesstypes.RolePrincipal("Editor"),
				StartedAt: started,
				ExpiresAt: started.Add(time.Hour),
			}},
		},
		{
			name: "no rows is an empty listing",
			prepare: func(mockDB *Mockdb) {
				mockDB.EXPECT().ActiveImpersonations(gomock.Any(), activeSince, q).Return([]*dbtype.Impersonation{}, nil)
			},
			want: []*sessioninfo.Impersonation{},
		},
		{
			name: "propagates the driver error",
			prepare: func(mockDB *Mockdb) {
				mockDB.EXPECT().ActiveImpersonations(gomock.Any(), activeSince, q).Return(nil, errors.New("not configured"))
			},
			wantErr: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			ctrl := gomock.NewController(t)
			mockDB := NewMockdb(ctrl)
			tt.prepare(mockDB)

			got, err := (&sessionStorage{db: mockDB}).ActiveImpersonations(context.Background(), activeSince, q)
			if (err != nil) != tt.wantErr {
				t.Fatalf("ActiveImpersonations() error = %v, wantErr %v", err, tt.wantErr)
			}
			if diff := cmp.Diff(tt.want, got, principalComparer, maskComparer); diff != "" {
				t.Errorf("ActiveImpersonations() mismatch (-want +got):\n%s", diff)
			}
		})
	}
}
