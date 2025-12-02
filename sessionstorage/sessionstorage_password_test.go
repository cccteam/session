package sessionstorage

import (
	"context"
	"reflect"
	"testing"

	"github.com/cccteam/ccc"
	"github.com/cccteam/ccc/accesstypes"
	"github.com/cccteam/ccc/securehash"
	"github.com/cccteam/session/internal/dbtype"
	"github.com/cccteam/session/sessionstorage/mock/mock_sessionstorage"
	"github.com/go-playground/errors/v5"
	gomock "go.uber.org/mock/gomock"
)

func TestPasswordAuth_User(t *testing.T) {
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
			storage := &PasswordAuth{
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

func TestPasswordAuth_UserByUserName(t *testing.T) {
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
			storage := &PasswordAuth{
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

func TestPasswordAuth_CreateUser(t *testing.T) {
	t.Parallel()
	userID := ccc.Must(ccc.NewUUID())
	hash, err := securehash.New(securehash.Argon2()).Hash("password")
	if err != nil {
		t.Fatal(err)
	}
	tests := []struct {
		name     string
		username string
		domain   accesstypes.Domain
		hash     *securehash.Hash
		prepare  func(mockDB *mock_sessionstorage.Mockdb)
		wantUser *dbtype.SessionUser
		wantErr  bool
	}{
		{
			name:     "success",
			username: "test",
			domain:   "test.com",
			hash:     hash,
			prepare: func(mockDB *mock_sessionstorage.Mockdb) {
				mockDB.EXPECT().CreateUser(gomock.Any(), "test", accesstypes.Domain("test.com"), hash).Return(&dbtype.SessionUser{ID: userID, Username: "test", Domain: "test.com"}, nil)
			},
			wantUser: &dbtype.SessionUser{ID: userID, Username: "test", Domain: "test.com"},
		},
		{
			name:     "failure",
			username: "test",
			domain:   "test.com",
			hash:     hash,
			prepare: func(mockDB *mock_sessionstorage.Mockdb) {
				mockDB.EXPECT().CreateUser(gomock.Any(), "test", accesstypes.Domain("test.com"), hash).Return(nil, errors.New("db error"))
			},
			wantErr: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			ctrl := gomock.NewController(t)
			mockDB := mock_sessionstorage.NewMockdb(ctrl)
			storage := &PasswordAuth{
				sessionStorage: sessionStorage{
					db: mockDB,
				},
			}
			if tt.prepare != nil {
				tt.prepare(mockDB)
			}
			gotUser, err := storage.CreateUser(context.Background(), tt.username, tt.domain, tt.hash)
			if (err != nil) != tt.wantErr {
				t.Errorf("Password.CreateUser() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !reflect.DeepEqual(gotUser, tt.wantUser) {
				t.Errorf("Password.CreateUser() = %v, want %v", gotUser, tt.wantUser)
			}
		})
	}
}

func TestPasswordAuth_SetUserPasswordHash(t *testing.T) {
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
				mockDB.EXPECT().SetUserPasswordHash(gomock.Any(), userID, hash).Return(nil)
			},
		},
		{
			name: "failure",
			id:   userID,
			hash: hash,
			prepare: func(mockDB *mock_sessionstorage.Mockdb) {
				mockDB.EXPECT().SetUserPasswordHash(gomock.Any(), userID, hash).Return(errors.New("db error"))
			},
			wantErr: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			ctrl := gomock.NewController(t)
			mockDB := mock_sessionstorage.NewMockdb(ctrl)
			storage := &PasswordAuth{
				sessionStorage: sessionStorage{
					db: mockDB,
				},
			}
			if tt.prepare != nil {
				tt.prepare(mockDB)
			}
			if err := storage.SetUserPasswordHash(context.Background(), tt.id, tt.hash); (err != nil) != tt.wantErr {
				t.Errorf("Password.SetUserPasswordHash() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func TestNewSpannerPassword(t *testing.T) {
	t.Parallel()
	p := NewSpannerPasswordAuth(nil)
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

func TestPassword_DeactivateUser(t *testing.T) {
	t.Parallel()

	someErr := errors.New("some error")
	userID, err := ccc.NewUUID()
	if err != nil {
		t.Fatalf("ccc.NewUUID(): error = %v, expected: nil", err)
	}

	tests := []struct {
		name    string
		id      ccc.UUID
		mock    func(m *mock_sessionstorage.Mockdb)
		wantErr bool
		err     error
	}{
		{
			name: "success",
			id:   userID,
			mock: func(m *mock_sessionstorage.Mockdb) {
				m.EXPECT().DeactivateUser(gomock.Any(), userID).Return(nil)
			},
		},
		{
			name: "error",
			id:   userID,
			mock: func(m *mock_sessionstorage.Mockdb) {
				m.EXPECT().DeactivateUser(gomock.Any(), userID).Return(someErr)
			},
			wantErr: true,
			err:     someErr,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			ctrl := gomock.NewController(t)
			mockdb := mock_sessionstorage.NewMockdb(ctrl)
			tt.mock(mockdb)

			p := &PasswordAuth{
				sessionStorage: sessionStorage{
					db: mockdb,
				},
			}

			if err := p.DeactivateUser(context.Background(), tt.id); (err != nil) != tt.wantErr {
				t.Errorf("Password.DeactivateUser() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func TestPassword_DeleteUser(t *testing.T) {
	t.Parallel()

	someErr := errors.New("some error")
	userID, err := ccc.NewUUID()
	if err != nil {
		t.Fatalf("ccc.NewUUID(): error = %v, expected: nil", err)
	}

	tests := []struct {
		name    string
		id      ccc.UUID
		mock    func(m *mock_sessionstorage.Mockdb)
		wantErr bool
		err     error
	}{
		{
			name: "success",
			id:   userID,
			mock: func(m *mock_sessionstorage.Mockdb) {
				m.EXPECT().DeleteUser(gomock.Any(), userID).Return(nil)
			},
		},
		{
			name: "error",
			id:   userID,
			mock: func(m *mock_sessionstorage.Mockdb) {
				m.EXPECT().DeleteUser(gomock.Any(), userID).Return(someErr)
			},
			wantErr: true,
			err:     someErr,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			ctrl := gomock.NewController(t)
			mockdb := mock_sessionstorage.NewMockdb(ctrl)
			tt.mock(mockdb)

			p := &PasswordAuth{
				sessionStorage: sessionStorage{
					db: mockdb,
				},
			}

			if err := p.DeleteUser(context.Background(), tt.id); (err != nil) != tt.wantErr {
				t.Errorf("Password.DeleteUser() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func TestPassword_ActivateUser(t *testing.T) {
	t.Parallel()

	someErr := errors.New("some error")
	userID, err := ccc.NewUUID()
	if err != nil {
		t.Fatalf("ccc.NewUUID(): error = %v, expected: nil", err)
	}

	tests := []struct {
		name    string
		id      ccc.UUID
		mock    func(m *mock_sessionstorage.Mockdb)
		wantErr bool
		err     error
	}{
		{
			name: "success",
			id:   userID,
			mock: func(m *mock_sessionstorage.Mockdb) {
				m.EXPECT().ActivateUser(gomock.Any(), userID).Return(nil)
			},
		},
		{
			name: "error",
			id:   userID,
			mock: func(m *mock_sessionstorage.Mockdb) {
				m.EXPECT().ActivateUser(gomock.Any(), userID).Return(someErr)
			},
			wantErr: true,
			err:     someErr,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			ctrl := gomock.NewController(t)
			mockdb := mock_sessionstorage.NewMockdb(ctrl)
			tt.mock(mockdb)

			p := &PasswordAuth{
				sessionStorage: sessionStorage{
					db: mockdb,
				},
			}

			if err := p.ActivateUser(context.Background(), tt.id); (err != nil) != tt.wantErr {
				t.Errorf("Password.ActivateUser() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func TestPassword_DestroyAllUserSessions(t *testing.T) {
	t.Parallel()

	someErr := errors.New("some error")
	username := "testuser"

	tests := []struct {
		name    string
		mock    func(m *mock_sessionstorage.Mockdb)
		wantErr bool
		err     error
	}{
		{
			name: "success",
			mock: func(m *mock_sessionstorage.Mockdb) {
				m.EXPECT().DestroyAllUserSessions(gomock.Any(), username).Return(nil)
			},
		},
		{
			name: "error",
			mock: func(m *mock_sessionstorage.Mockdb) {
				m.EXPECT().DestroyAllUserSessions(gomock.Any(), username).Return(someErr)
			},
			wantErr: true,
			err:     someErr,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			ctrl := gomock.NewController(t)
			mockdb := mock_sessionstorage.NewMockdb(ctrl)
			tt.mock(mockdb)

			p := &PasswordAuth{
				sessionStorage: sessionStorage{
					db: mockdb,
				},
			}

			if err := p.DestroyAllUserSessions(context.Background(), username); (err != nil) != tt.wantErr {
				t.Errorf("Password.DestroyAllUserSessions() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}
