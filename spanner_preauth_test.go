package session

import (
	"context"
	"testing"
	"time"

	"github.com/cccteam/ccc"
	"github.com/cccteam/session/dbtype"
	"github.com/cccteam/session/mock/mock_session"
	"github.com/cccteam/session/sessioninfo"
	"github.com/go-playground/errors/v5"
	"github.com/google/go-cmp/cmp"
	gomock "go.uber.org/mock/gomock"
)

func TestSpannerPreauthSessionStorage_NewSession(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name       string
		username   string
		prepare    func(*mock_session.MockDB)
		wantErr    bool
		expectedID ccc.UUID
	}{
		{
			name:     "successful session creation",
			username: "test_user",
			prepare: func(mockDB *mock_session.MockDB) {
				mockDB.EXPECT().
					InsertSession(gomock.Any(), gomock.Any()).
					Return(ccc.Must(ccc.UUIDFromString("123e4567-e89b-12d3-a456-426614174000")), nil).
					Times(1)
			},
			expectedID: ccc.Must(ccc.UUIDFromString("123e4567-e89b-12d3-a456-426614174000")),
		},
		{
			name:     "failed session creation",
			username: "test_user",
			prepare: func(mockDB *mock_session.MockDB) {
				mockDB.EXPECT().
					InsertSession(gomock.Any(), gomock.Any()).
					Return(ccc.NilUUID, errors.New("insert failed")).
					Times(1)
			},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			ctrl := gomock.NewController(t)
			mockDB := mock_session.NewMockDB(ctrl)
			storage := &SpannerPreauthSessionStorage{
				db: mockDB,
			}

			if tt.prepare != nil {
				tt.prepare(mockDB)
			}

			id, err := storage.NewSession(context.Background(), tt.username)
			if (err != nil) != tt.wantErr {
				t.Errorf("NewSession() error = %v, wantErr = %v", err, tt.wantErr)
			}
			if id != tt.expectedID {
				t.Errorf("NewSession() id = %v, expectedID = %v", id, tt.expectedID)
			}
		})
	}
}

func TestSpannerPreauthSessionStorage_Session(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name       string
		sessionID  ccc.UUID
		prepare    func(*mock_session.MockDB)
		wantErr    bool
		expectedSI *sessioninfo.SessionInfo
	}{
		{
			name:      "successful session retrieval",
			sessionID: ccc.Must(ccc.UUIDFromString("123e4567-e89b-12d3-a456-426614174000")),
			prepare: func(mockDB *mock_session.MockDB) {
				mockDB.EXPECT().
					Session(gomock.Any(), gomock.Any()).
					Return(&dbtype.Session{
						ID:        ccc.Must(ccc.UUIDFromString("123e4567-e89b-12d3-a456-426614174000")),
						Username:  "test_user",
						CreatedAt: ccc.Must(time.Parse(time.RFC3339, "2021-01-01T00:00:00Z")),
						UpdatedAt: ccc.Must(time.Parse(time.RFC3339, "2021-01-01T00:00:00Z")),
						Expired:   false,
					}, nil).
					Times(1)
			},
			expectedSI: &sessioninfo.SessionInfo{
				ID:        ccc.Must(ccc.UUIDFromString("123e4567-e89b-12d3-a456-426614174000")),
				Username:  "test_user",
				CreatedAt: ccc.Must(time.Parse(time.RFC3339, "2021-01-01T00:00:00Z")),
				UpdatedAt: ccc.Must(time.Parse(time.RFC3339, "2021-01-01T00:00:00Z")),
				Expired:   false,
			},
		},
		{
			name:      "failed session retrieval",
			sessionID: ccc.Must(ccc.UUIDFromString("123e4567-e89b-12d3-a456-426614174000")),
			prepare: func(mockDB *mock_session.MockDB) {
				mockDB.EXPECT().
					Session(gomock.Any(), gomock.Any()).
					Return(nil, errors.New("session not found")).
					Times(1)
			},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			ctrl := gomock.NewController(t)
			mockDB := mock_session.NewMockDB(ctrl)
			storage := &SpannerPreauthSessionStorage{
				db: mockDB,
			}

			if tt.prepare != nil {
				tt.prepare(mockDB)
			}

			si, err := storage.Session(context.Background(), tt.sessionID)
			if (err != nil) != tt.wantErr {
				t.Errorf("Session() error = %v, wantErr = %v", err, tt.wantErr)
			}

			if cmp.Diff(si, tt.expectedSI) != "" {
				t.Errorf("Session() = %v, expectedSI = %v", si, tt.expectedSI)
			}
		})
	}
}

func TestSpannerPreauthSessionStorage_UpdateSessionActivity(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name      string
		sessionID ccc.UUID
		prepare   func(*mock_session.MockDB)
		wantErr   bool
	}{
		{
			name:      "successful session activity update",
			sessionID: ccc.Must(ccc.UUIDFromString("123e4567-e89b-12d3-a456-426614174000")),
			prepare: func(mockDB *mock_session.MockDB) {
				mockDB.EXPECT().
					UpdateSessionActivity(gomock.Any(), gomock.Any()).
					Return(nil).
					Times(1)
			},
		},
		{
			name:      "failed session activity update",
			sessionID: ccc.Must(ccc.UUIDFromString("123e4567-e89b-12d3-a456-426614174000")),
			prepare: func(mockDB *mock_session.MockDB) {
				mockDB.EXPECT().
					UpdateSessionActivity(gomock.Any(), gomock.Any()).
					Return(errors.New("update failed")).
					Times(1)
			},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			ctrl := gomock.NewController(t)
			mockDB := mock_session.NewMockDB(ctrl)
			storage := &SpannerPreauthSessionStorage{
				db: mockDB,
			}

			if tt.prepare != nil {
				tt.prepare(mockDB)
			}

			err := storage.UpdateSessionActivity(context.Background(), tt.sessionID)
			if (err != nil) != tt.wantErr {
				t.Errorf("UpdateSessionActivity() error = %v, wantErr = %v", err, tt.wantErr)
			}
		})
	}
}

func TestSpannerPreauthSessionStorage_DestroySession(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name      string
		sessionID ccc.UUID
		prepare   func(*mock_session.MockDB)
		wantErr   bool
	}{
		{
			name:      "successful session destruction",
			sessionID: ccc.Must(ccc.UUIDFromString("123e4567-e89b-12d3-a456-426614174000")),
			prepare: func(mockDB *mock_session.MockDB) {
				mockDB.EXPECT().
					DestroySession(gomock.Any(), gomock.Any()).
					Return(nil).
					Times(1)
			},
		},
		{
			name:      "failed session destruction",
			sessionID: ccc.Must(ccc.UUIDFromString("123e4567-e89b-12d3-a456-426614174000")),
			prepare: func(mockDB *mock_session.MockDB) {
				mockDB.EXPECT().
					DestroySession(gomock.Any(), gomock.Any()).
					Return(errors.New("destroy failed")).
					Times(1)
			},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			ctrl := gomock.NewController(t)
			mockDB := mock_session.NewMockDB(ctrl)
			storage := &SpannerPreauthSessionStorage{
				db: mockDB,
			}

			if tt.prepare != nil {
				tt.prepare(mockDB)
			}

			err := storage.DestroySession(context.Background(), tt.sessionID)
			if (err != nil) != tt.wantErr {
				t.Errorf("DestroySession() error = %v, wantErr = %v", err, tt.wantErr)
			}
		})
	}
}
