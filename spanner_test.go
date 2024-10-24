package session

import (
	"context"
	"testing"
	"time"

	"github.com/cccteam/ccc"
	"github.com/cccteam/session/mock/mock_spanner"
	"github.com/cccteam/session/spanner"
	"github.com/go-playground/errors/v5"
	gomock "go.uber.org/mock/gomock"
)

func Test_spannerSessionStorage_Session(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name      string
		sessionID ccc.UUID
		prepare   func(*mock_spanner.MockDB)
		wantErr   bool
	}{
		{
			name:      "successful session retrieval",
			sessionID: ccc.Must(ccc.UUIDFromString("123e4567-e89b-12d3-a456-426614174000")),
			prepare: func(mockDB *mock_spanner.MockDB) {
				mockDB.EXPECT().
					Session(gomock.Any(), gomock.Any()).
					Return(&spanner.Session{
						ID:        ccc.Must(ccc.UUIDFromString("123e4567-e89b-12d3-a456-426614174000")),
						Username:  "test_user",
						CreatedAt: time.Now(),
						UpdatedAt: time.Now(),
						Expired:   false,
					}, nil).
					Times(1)
			},
		},
		{
			name:      "failed session retrieval",
			sessionID: ccc.Must(ccc.UUIDFromString("123e4567-e89b-12d3-a456-426614174000")),
			prepare: func(mockDB *mock_spanner.MockDB) {
				mockDB.EXPECT().
					Session(gomock.Any(), gomock.Any()).
					Return(nil, errors.New("session not found")).
					Times(1)
			},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			ctrl := gomock.NewController(t)
			mockDB := mock_spanner.NewMockDB(ctrl)
			storage := &spannerSessionStorage{db: mockDB}

			if tt.prepare != nil {
				tt.prepare(mockDB)
			}

			sessionInfo, err := storage.Session(context.Background(), tt.sessionID)
			if (err != nil) != tt.wantErr {
				t.Errorf("Session() error = %v, wantErr = %v", err, tt.wantErr)
			}
			if err == nil && sessionInfo.ID != tt.sessionID {
				t.Errorf("Session() ID = %v, expectedID = %v", sessionInfo.ID, tt.sessionID)
			}
		})
	}
}

func Test_spannerSessionStorage_UpdateSessionActivity(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name      string
		sessionID ccc.UUID
		prepare   func(*mock_spanner.MockDB)
		wantErr   bool
	}{
		{
			name:      "successful activity update",
			sessionID: ccc.Must(ccc.UUIDFromString("123e4567-e89b-12d3-a456-426614174000")),
			prepare: func(mockDB *mock_spanner.MockDB) {
				mockDB.EXPECT().
					UpdateSessionActivity(gomock.Any(), gomock.Any()).
					Return(nil).
					Times(1)
			},
		},
		{
			name:      "failed activity update",
			sessionID: ccc.Must(ccc.UUIDFromString("123e4567-e89b-12d3-a456-426614174000")),
			prepare: func(mockDB *mock_spanner.MockDB) {
				mockDB.EXPECT().
					UpdateSessionActivity(gomock.Any(), gomock.Any()).
					Return(errors.New("update failed")).
					Times(1)
			},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			ctrl := gomock.NewController(t)
			mockDB := mock_spanner.NewMockDB(ctrl)
			storage := &spannerSessionStorage{db: mockDB}

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

func Test_spannerSessionStorage_DestroySession(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name      string
		sessionID ccc.UUID
		prepare   func(*mock_spanner.MockDB)
		wantErr   bool
	}{
		{
			name:      "successful session destruction",
			sessionID: ccc.Must(ccc.UUIDFromString("123e4567-e89b-12d3-a456-426614174000")),
			prepare: func(mockDB *mock_spanner.MockDB) {
				mockDB.EXPECT().
					DestroySession(gomock.Any(), gomock.Any()).
					Return(nil).
					Times(1)
			},
		},
		{
			name:      "failed session destruction",
			sessionID: ccc.Must(ccc.UUIDFromString("123e4567-e89b-12d3-a456-426614174000")),
			prepare: func(mockDB *mock_spanner.MockDB) {
				mockDB.EXPECT().
					DestroySession(gomock.Any(), gomock.Any()).
					Return(errors.New("destroy failed")).
					Times(1)
			},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			ctrl := gomock.NewController(t)
			mockDB := mock_spanner.NewMockDB(ctrl)
			storage := &spannerSessionStorage{db: mockDB}

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
