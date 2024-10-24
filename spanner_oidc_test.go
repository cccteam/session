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
func matchOIDCSession(expected *spanner.InsertSession) gomock.Matcher {
	return gomock.AssignableToTypeOf(expected)
}

func TestSpannerOIDCSessionStorage_NewSession(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name       string
		username   string
		oidcSID    string
		prepare    func(*mock_spanner.MockDB)
		wantErr    bool
		expectedID ccc.UUID
	}{
		{
			name:     "successful OIDC session creation",
			username: "user1",
			oidcSID:  "oidc-12345",
			prepare: func(mockDB *mock_spanner.MockDB) {
				session := &spanner.InsertSession{
					Username:  "user1",
					OidcSID:   "oidc-12345",
					CreatedAt: time.Now(),
					UpdatedAt: time.Now(),
				}
				mockDB.EXPECT().
					InsertSession(gomock.Any(), matchOIDCSession(session)).
					Return(ccc.Must(ccc.UUIDFromString("123e4567-e89b-12d3-a456-426614174001")), nil).
					Times(1)
			},
			expectedID: ccc.Must(ccc.UUIDFromString("123e4567-e89b-12d3-a456-426614174001")),
		},
		{
			name:     "failed OIDC session creation",
			username: "user2",
			oidcSID:  "oidc-67890",
			prepare: func(mockDB *mock_spanner.MockDB) {
				session := &spanner.InsertSession{
					Username:  "user2",
					OidcSID:   "oidc-67890",
					CreatedAt: time.Now(),
					UpdatedAt: time.Now(),
				}
				mockDB.EXPECT().
					InsertSession(gomock.Any(), matchOIDCSession(session)).
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
			mockDB := mock_spanner.NewMockDB(ctrl)
			storage := &SpannerOIDCSessionStorage{
				spannerSessionStorage: &spannerSessionStorage{db: mockDB},
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
		prepare func(*mock_spanner.MockDB)
		wantErr bool
	}{
		{
			name:    "successful OIDC session destruction",
			oidcSID: "oidc-12345",
			prepare: func(mockDB *mock_spanner.MockDB) {
				mockDB.EXPECT().
					DestroySessionOIDC(gomock.Any(), "oidc-12345").
					Return(nil).
					Times(1)
			},
		},
		{
			name:    "failed OIDC session destruction",
			oidcSID: "oidc-67890",
			prepare: func(mockDB *mock_spanner.MockDB) {
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
			mockDB := mock_spanner.NewMockDB(ctrl)
			storage := &SpannerOIDCSessionStorage{
				spannerSessionStorage: &spannerSessionStorage{db: mockDB},
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
