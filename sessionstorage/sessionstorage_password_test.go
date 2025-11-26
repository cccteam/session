package sessionstorage

import (
	"context"
	"reflect"
	"testing"

	"github.com/cccteam/ccc"
	"github.com/cccteam/ccc/securehash"
	"github.com/cccteam/session/internal/dbtype"
	"github.com/cccteam/session/sessionstorage/mock/mock_sessionstorage"
	"github.com/go-playground/errors/v5"
	gomock "go.uber.org/mock/gomock"
)

func TestPassword_User(t *testing.T) {
	t.Parallel()
	userID := ccc.Must(ccc.NewUUID())
	tests := []struct {
		name     string
		id       ccc.UUID
		prepare  func(mockDB *mock_sessionstorage.Mockdb)
		wantUser *dbtype.SessionUser
		wantErr  bool
	}{
		{
			name: "success",
			id:   userID,
			prepare: func(mockDB *mock_sessionstorage.Mockdb) {
				mockDB.EXPECT().User(gomock.Any(), userID).Return(&dbtype.SessionUser{ID: userID, Username: "test"}, nil)
			},
			wantUser: &dbtype.SessionUser{ID: userID, Username: "test"},
		},
		{
			name: "failure",
			id:   userID,
			prepare: func(mockDB *mock_sessionstorage.Mockdb) {
				mockDB.EXPECT().User(gomock.Any(), userID).Return(nil, errors.New("db error"))
			},
			wantErr: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			ctrl := gomock.NewController(t)
			mockDB := mock_sessionstorage.NewMockdb(ctrl)
			storage := &Password{
				sessionStorage: sessionStorage{
					db: mockDB,
				},
			}
			if tt.prepare != nil {
				tt.prepare(mockDB)
			}
			gotUser, err := storage.User(context.Background(), tt.id)
			if (err != nil) != tt.wantErr {
				t.Errorf("Password.User() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !reflect.DeepEqual(gotUser, tt.wantUser) {
				t.Errorf("Password.User() = %v, want %v", gotUser, tt.wantUser)
			}
		})
	}
}

func TestPassword_UserByUserName(t *testing.T) {
	t.Parallel()
	userID := ccc.Must(ccc.NewUUID())
	tests := []struct {
		name     string
		username string
		prepare  func(mockDB *mock_sessionstorage.Mockdb)
		wantUser *dbtype.SessionUser
		wantErr  bool
	}{
		{
			name:     "success",
			username: "test",
			prepare: func(mockDB *mock_sessionstorage.Mockdb) {
				mockDB.EXPECT().UserByUserName(gomock.Any(), "test").Return(&dbtype.SessionUser{ID: userID, Username: "test"}, nil)
			},
			wantUser: &dbtype.SessionUser{ID: userID, Username: "test"},
		},
		{
			name:     "failure",
			username: "test",
			prepare: func(mockDB *mock_sessionstorage.Mockdb) {
				mockDB.EXPECT().UserByUserName(gomock.Any(), "test").Return(nil, errors.New("db error"))
			},
			wantErr: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			ctrl := gomock.NewController(t)
			mockDB := mock_sessionstorage.NewMockdb(ctrl)
			storage := &Password{
				sessionStorage: sessionStorage{
					db: mockDB,
				},
			}
			if tt.prepare != nil {
				tt.prepare(mockDB)
			}
			gotUser, err := storage.UserByUserName(context.Background(), tt.username)
			if (err != nil) != tt.wantErr {
				t.Errorf("Password.UserByUserName() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !reflect.DeepEqual(gotUser, tt.wantUser) {
				t.Errorf("Password.UserByUserName() = %v, want %v", gotUser, tt.wantUser)
			}
		})
	}
}

func TestPassword_UpdateUserPasswordHash(t *testing.T) {
	t.Parallel()
	userID := ccc.Must(ccc.NewUUID())
	hash, err := securehash.New(securehash.Argon2()).Hash("password")
	if err != nil {
		t.Fatal(err)
	}
	tests := []struct {
		name    string
		id      ccc.UUID
		hash    *securehash.Hash
		prepare func(mockDB *mock_sessionstorage.Mockdb)
		wantErr bool
	}{
		{
			name: "success",
			id:   userID,
			hash: hash,
			prepare: func(mockDB *mock_sessionstorage.Mockdb) {
				mockDB.EXPECT().UpdateUserPasswordHash(gomock.Any(), userID, hash).Return(nil)
			},
		},
		{
			name: "failure",
			id:   userID,
			hash: hash,
			prepare: func(mockDB *mock_sessionstorage.Mockdb) {
				mockDB.EXPECT().UpdateUserPasswordHash(gomock.Any(), userID, hash).Return(errors.New("db error"))
			},
			wantErr: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			ctrl := gomock.NewController(t)
			mockDB := mock_sessionstorage.NewMockdb(ctrl)
			storage := &Password{
				sessionStorage: sessionStorage{
					db: mockDB,
				},
			}
			if tt.prepare != nil {
				tt.prepare(mockDB)
			}
			if err := storage.UpdateUserPasswordHash(context.Background(), tt.id, tt.hash); (err != nil) != tt.wantErr {
				t.Errorf("Password.UpdateUserPasswordHash() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func TestNewSpannerPassword(t *testing.T) {
	t.Parallel()
	p := NewSpannerPassword(nil)
	if p == nil {
		t.Error("NewSpannerPassword() returned nil")
	}
}

func TestNewPostgresPassword(t *testing.T) {
	t.Parallel()
	p := NewPostgresPassword(nil)
	if p == nil {
		t.Error("NewPostgresPassword() returned nil")
	}
}
