package session

import (
	"context"
	"testing"

	"github.com/cccteam/ccc"
	"github.com/cccteam/session/mock/mock_session"
	"github.com/go-playground/errors/v5"
	gomock "go.uber.org/mock/gomock"
)

func TestSpannerOIDCSessionStorage_NewSession(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name       string
		username   string
		oidcSID    string
		prepare    func(*mock_session.MockDB)
		wantErr    bool
		expectedID ccc.UUID
	}{
		{
			name:     "successful OIDC session creation",
			username: "user1",
			oidcSID:  "oidc-12345",
			prepare: func(mockDB *mock_session.MockDB) {
				mockDB.EXPECT().
					InsertSession(gomock.Any(), gomock.Any()).
					Return(ccc.Must(ccc.UUIDFromString("123e4567-e89b-12d3-a456-426614174001")), nil).
					Times(1)
			},
			expectedID: ccc.Must(ccc.UUIDFromString("123e4567-e89b-12d3-a456-426614174001")),
		},
		{
			name:     "failed OIDC session creation",
			username: "user2",
			oidcSID:  "oidc-67890",
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
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			ctrl := gomock.NewController(t)
			mockDB := mock_session.NewMockDB(ctrl)
			storage := &SpannerOIDCSessionStorage{
				db: mockDB,
			}

			if tt.prepare != nil {
				tt.prepare(mockDB)
			}

			id, err := storage.NewSession(context.Background(), tt.username, tt.oidcSID)
			if (err != nil) != tt.wantErr {
				t.Errorf("NewSession() error = %v, wantErr = %v", err, tt.wantErr)
			}
			if id != tt.expectedID {
				t.Errorf("NewSession() id = %v, expectedID = %v", id, tt.expectedID)
			}
		})
	}
}

func TestSpannerOIDCSessionStorage_DestroySessionOIDC(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name    string
		oidcSID string
		prepare func(*mock_session.MockDB)
		wantErr bool
	}{
		{
			name:    "successful OIDC session destruction",
			oidcSID: "oidc-12345",
			prepare: func(mockDB *mock_session.MockDB) {
				mockDB.EXPECT().
					DestroySessionOIDC(gomock.Any(), "oidc-12345").
					Return(nil).
					Times(1)
			},
		},
		{
			name:    "failed OIDC session destruction",
			oidcSID: "oidc-67890",
			prepare: func(mockDB *mock_session.MockDB) {
				mockDB.EXPECT().
					DestroySessionOIDC(gomock.Any(), "oidc-67890").
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
			mockDB := mock_session.NewMockDB(ctrl)
			storage := &SpannerOIDCSessionStorage{
				db: mockDB,
			}

			if tt.prepare != nil {
				tt.prepare(mockDB)
			}

			err := storage.DestroySessionOIDC(context.Background(), tt.oidcSID)
			if (err != nil) != tt.wantErr {
				t.Errorf("DestroySessionOIDC() error = %v, wantErr = %v", err, tt.wantErr)
			}
		})
	}
}
