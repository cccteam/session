package session

import (
	"reflect"
	"testing"

	"github.com/cccteam/session/sessionstorage/mock/mock_sessionstorage"
	gomock "go.uber.org/mock/gomock"
)

// testUserProfile is the custom user data struct used by the root package tests.
type testUserProfile struct {
	Email string `spanner:"Email"`
	Theme string `spanner:"Theme"`
}

func TestNewPreauth_CustomUserDataRejected(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name    string
		prepare func(storage *mock_sessionstorage.MockPreauthStore)
		wantErr bool
	}{
		{
			name: "clean storage constructs",
			prepare: func(storage *mock_sessionstorage.MockPreauthStore) {
				storage.EXPECT().CustomUserDataType().Return(nil)
				storage.EXPECT().OIDCUsersEnabled().Return(false)
			},
		},
		{
			name: "custom user data config is rejected",
			prepare: func(storage *mock_sessionstorage.MockPreauthStore) {
				storage.EXPECT().CustomUserDataType().Return(reflect.TypeFor[testUserProfile]())
			},
			wantErr: true,
		},
		{
			name: "OIDC user anchor is rejected",
			prepare: func(storage *mock_sessionstorage.MockPreauthStore) {
				storage.EXPECT().CustomUserDataType().Return(nil)
				storage.EXPECT().OIDCUsersEnabled().Return(true)
			},
			wantErr: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			ctrl := gomock.NewController(t)
			storage := mock_sessionstorage.NewMockPreauthStore(ctrl)
			tt.prepare(storage)

			if _, err := NewPreauth[NoCustomData](storage, cookieKey); (err != nil) != tt.wantErr {
				t.Errorf("NewPreauth() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}
