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

// Custom matcher for InsertSession
func matchInsertSession(expected *spanner.InsertSession) gomock.Matcher {
	return gomock.AssignableToTypeOf(expected)
}

func TestSpannerPreauthSessionStorage_NewSession(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name       string
		username   string
		prepare    func(*mock_spanner.MockDB)
		wantErr    bool
		expectedID ccc.UUID
	}{
		{
			name:     "successful session creation",
			username: "test_user",
			prepare: func(mockDB *mock_spanner.MockDB) {
				session := &spanner.InsertSession{
					Username:  "test_user",
					CreatedAt: time.Now(),
					UpdatedAt: time.Now(),
				}
				mockDB.EXPECT().
					InsertSession(gomock.Any(), matchInsertSession(session)).
					Return(ccc.Must(ccc.UUIDFromString("123e4567-e89b-12d3-a456-426614174000")), nil).
					Times(1)
			},
			expectedID: ccc.Must(ccc.UUIDFromString("123e4567-e89b-12d3-a456-426614174000")),
		},
		{
			name:     "failed session creation",
			username: "test_user",
			prepare: func(mockDB *mock_spanner.MockDB) {
				session := &spanner.InsertSession{
					Username:  "test_user",
					CreatedAt: time.Now(),
					UpdatedAt: time.Now(),
				}
				mockDB.EXPECT().
					InsertSession(gomock.Any(), matchInsertSession(session)).
					Return(ccc.NilUUID, errors.New("insert failed")).
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
			defer ctrl.Finish()

			mockDB := mock_spanner.NewMockDB(ctrl)
			storage := &SpannerPreauthSessionStorage{
				spannerSessionStorage: &spannerSessionStorage{db: mockDB},
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
