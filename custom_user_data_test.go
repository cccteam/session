package session

import (
	"context"
	"reflect"
	"testing"

	"github.com/cccteam/ccc"
	"github.com/cccteam/session/sessionstorage"
	"github.com/cccteam/session/sessionstorage/mock/mock_sessionstorage"
	"github.com/go-playground/errors/v5"
	gomock "go.uber.org/mock/gomock"
)

// testUserProfile is the custom user data struct used by the root package tests.
type testUserProfile struct {
	Email string `spanner:"Email"`
	Theme string `spanner:"Theme"`
}

func TestNewPasswordAuth_CustomUserDataChecks(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name    string
		prepare func(storage *mock_sessionstorage.MockPasswordAuthStore)
		build   func(storage *mock_sessionstorage.MockPasswordAuthStore) error
		wantErr bool
	}{
		{
			name: "matching custom user data type",
			prepare: func(storage *mock_sessionstorage.MockPasswordAuthStore) {
				storage.EXPECT().CustomUserDataType().Return(reflect.TypeFor[testUserProfile]()).AnyTimes()
				storage.EXPECT().UserDataLoginHookConfigured().Return(false)
				storage.EXPECT().OIDCUsersEnabled().Return(false)
			},
			build: func(storage *mock_sessionstorage.MockPasswordAuthStore) error {
				_, err := NewPasswordAuth[NoCustomData, testUserProfile](storage, cookieKey)

				return err
			},
		},
		{
			name: "mismatched custom user data type",
			prepare: func(storage *mock_sessionstorage.MockPasswordAuthStore) {
				storage.EXPECT().CustomUserDataType().Return(reflect.TypeFor[otherTestData]()).AnyTimes()
			},
			build: func(storage *mock_sessionstorage.MockPasswordAuthStore) error {
				_, err := NewPasswordAuth[NoCustomData, testUserProfile](storage, cookieKey)

				return err
			},
			wantErr: true,
		},
		{
			name: "no custom user data config",
			prepare: func(storage *mock_sessionstorage.MockPasswordAuthStore) {
				storage.EXPECT().CustomUserDataType().Return(nil).AnyTimes()
			},
			build: func(storage *mock_sessionstorage.MockPasswordAuthStore) error {
				_, err := NewPasswordAuth[NoCustomData, testUserProfile](storage, cookieKey)

				return err
			},
			wantErr: true,
		},
		{
			name: "OIDC-only login hook is rejected",
			prepare: func(storage *mock_sessionstorage.MockPasswordAuthStore) {
				storage.EXPECT().UserDataLoginHookConfigured().Return(true)
			},
			build: func(storage *mock_sessionstorage.MockPasswordAuthStore) error {
				_, err := NewPasswordAuth[NoCustomData, NoCustomData](storage, cookieKey)

				return err
			},
			wantErr: true,
		},
		{
			name: "OIDC-only user anchor is rejected",
			prepare: func(storage *mock_sessionstorage.MockPasswordAuthStore) {
				storage.EXPECT().UserDataLoginHookConfigured().Return(false)
				storage.EXPECT().OIDCUsersEnabled().Return(true)
			},
			build: func(storage *mock_sessionstorage.MockPasswordAuthStore) error {
				_, err := NewPasswordAuth[NoCustomData, NoCustomData](storage, cookieKey)

				return err
			},
			wantErr: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			ctrl := gomock.NewController(t)
			storage := mock_sessionstorage.NewMockPasswordAuthStore(ctrl)
			if tt.prepare != nil {
				tt.prepare(storage)
			}

			if err := tt.build(storage); (err != nil) != tt.wantErr {
				t.Errorf("NewPasswordAuth() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func TestNewOIDCAzure_CustomUserDataChecks(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name    string
		prepare func(storage *mock_sessionstorage.MockOIDCStore)
		build   func(storage *mock_sessionstorage.MockOIDCStore) error
		wantErr bool
	}{
		{
			name: "custom user data with the anchor enabled",
			prepare: func(storage *mock_sessionstorage.MockOIDCStore) {
				storage.EXPECT().CustomUserDataType().Return(reflect.TypeFor[testUserProfile]()).AnyTimes()
				storage.EXPECT().OIDCUsersEnabled().Return(true)
			},
			build: func(storage *mock_sessionstorage.MockOIDCStore) error {
				_, err := NewOIDCAzure[NoCustomData, testUserProfile](storage, DisableRoleSync(), cookieKey, "issuerURL", "clientID", "clientSecret", "redirectURL")

				return err
			},
		},
		{
			name: "custom user data without the anchor is rejected",
			prepare: func(storage *mock_sessionstorage.MockOIDCStore) {
				storage.EXPECT().CustomUserDataType().Return(reflect.TypeFor[testUserProfile]()).AnyTimes()
				storage.EXPECT().OIDCUsersEnabled().Return(false)
			},
			build: func(storage *mock_sessionstorage.MockOIDCStore) error {
				_, err := NewOIDCAzure[NoCustomData, testUserProfile](storage, DisableRoleSync(), cookieKey, "issuerURL", "clientID", "clientSecret", "redirectURL")

				return err
			},
			wantErr: true,
		},
		{
			name: "attached config without the anchor is rejected even for NoCustomData",
			prepare: func(storage *mock_sessionstorage.MockOIDCStore) {
				storage.EXPECT().CustomUserDataType().Return(reflect.TypeFor[testUserProfile]()).AnyTimes()
				storage.EXPECT().OIDCUsersEnabled().Return(false)
			},
			build: func(storage *mock_sessionstorage.MockOIDCStore) error {
				_, err := NewOIDCAzure[NoCustomData, NoCustomData](storage, DisableRoleSync(), cookieKey, "issuerURL", "clientID", "clientSecret", "redirectURL")

				return err
			},
			wantErr: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			ctrl := gomock.NewController(t)
			storage := mock_sessionstorage.NewMockOIDCStore(ctrl)
			if tt.prepare != nil {
				tt.prepare(storage)
			}

			if err := tt.build(storage); (err != nil) != tt.wantErr {
				t.Errorf("NewOIDCAzure() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
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

func TestPasswordAuthAPI_CreateSessionUser_CustomUserData(t *testing.T) {
	t.Parallel()

	userID := ccc.Must(ccc.NewUUID())
	data := &testUserProfile{Email: "a@b.c"}

	tests := []struct {
		name       string
		customData []*testUserProfile
		prepare    func(storage *mock_sessionstorage.MockPasswordAuthStore)
		wantErr    bool
	}{
		{
			name:       "per-call data reaches the storage",
			customData: []*testUserProfile{data},
			prepare: func(storage *mock_sessionstorage.MockPasswordAuthStore) {
				storage.EXPECT().
					CreateUser(gomock.Any(), &sessionstorage.InsertSessionUser{Username: "user"}, data).
					Return(&sessionstorage.SessionUser{ID: userID, Username: "user"}, nil)
			},
		},
		{
			name: "no data passes untyped nil",
			prepare: func(storage *mock_sessionstorage.MockPasswordAuthStore) {
				storage.EXPECT().
					CreateUser(gomock.Any(), &sessionstorage.InsertSessionUser{Username: "user"}, gomock.Nil()).
					Return(&sessionstorage.SessionUser{ID: userID, Username: "user"}, nil)
			},
		},
		{
			name:       "more than one data value is rejected",
			customData: []*testUserProfile{data, data},
			wantErr:    true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			ctrl := gomock.NewController(t)
			storage := mock_sessionstorage.NewMockPasswordAuthStore(ctrl)
			if tt.prepare != nil {
				tt.prepare(storage)
			}
			p := &PasswordAuth[NoCustomData, testUserProfile]{storage: storage}

			_, err := p.API().CreateSessionUser(t.Context(), &CreateUserRequest{Username: "user"}, tt.customData...)
			if (err != nil) != tt.wantErr {
				t.Errorf("CreateSessionUser() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func TestPasswordAuthAPI_CustomUserData(t *testing.T) {
	t.Parallel()

	userID := ccc.Must(ccc.NewUUID())

	tests := []struct {
		name    string
		prepare func(storage *mock_sessionstorage.MockPasswordAuthStore)
		want    testUserProfile
		wantErr bool
	}{
		{
			name: "typed read",
			prepare: func(storage *mock_sessionstorage.MockPasswordAuthStore) {
				storage.EXPECT().CustomUserData(gomock.Any(), userID).Return(&testUserProfile{Email: "a@b.c"}, nil)
			},
			want: testUserProfile{Email: "a@b.c"},
		},
		{
			name: "storage error",
			prepare: func(storage *mock_sessionstorage.MockPasswordAuthStore) {
				storage.EXPECT().CustomUserData(gomock.Any(), userID).Return(nil, errors.New("db error"))
			},
			wantErr: true,
		},
		{
			name: "type mismatch is a clear error",
			prepare: func(storage *mock_sessionstorage.MockPasswordAuthStore) {
				storage.EXPECT().CustomUserData(gomock.Any(), userID).Return(&otherTestData{}, nil)
			},
			wantErr: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			ctrl := gomock.NewController(t)
			storage := mock_sessionstorage.NewMockPasswordAuthStore(ctrl)
			tt.prepare(storage)
			p := &PasswordAuth[NoCustomData, testUserProfile]{storage: storage}

			got, err := p.API().CustomUserData(t.Context(), userID)
			if (err != nil) != tt.wantErr {
				t.Fatalf("CustomUserData() error = %v, wantErr %v", err, tt.wantErr)
			}
			if !tt.wantErr && got != tt.want {
				t.Errorf("CustomUserData() = %+v, want %+v", got, tt.want)
			}
		})
	}
}

func TestPasswordAuthAPI_UpdateCustomUserData(t *testing.T) {
	t.Parallel()

	userID := ccc.Must(ccc.NewUUID())

	tests := []struct {
		name    string
		prepare func(storage *mock_sessionstorage.MockPasswordAuthStore)
		wantErr bool
	}{
		{
			name: "typed mutate runs against the driver's row",
			prepare: func(storage *mock_sessionstorage.MockPasswordAuthStore) {
				storage.EXPECT().UpdateCustomUserData(gomock.Any(), userID, gomock.Any()).
					DoAndReturn(func(_ context.Context, _ ccc.UUID, mutate func(any) error) error {
						data := &testUserProfile{Email: "old"}
						if err := mutate(data); err != nil {
							return err
						}
						if data.Theme != "dark" || data.Email != "old" {
							return errors.Newf("unexpected row after mutate: %+v", data)
						}

						return nil
					})
			},
		},
		{
			name: "mismatched driver row type is a clear error",
			prepare: func(storage *mock_sessionstorage.MockPasswordAuthStore) {
				storage.EXPECT().UpdateCustomUserData(gomock.Any(), userID, gomock.Any()).
					DoAndReturn(func(_ context.Context, _ ccc.UUID, mutate func(any) error) error {
						return mutate(&otherTestData{})
					})
			},
			wantErr: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			ctrl := gomock.NewController(t)
			storage := mock_sessionstorage.NewMockPasswordAuthStore(ctrl)
			tt.prepare(storage)
			p := &PasswordAuth[NoCustomData, testUserProfile]{storage: storage}

			err := p.API().UpdateCustomUserData(t.Context(), userID, func(data *testUserProfile) error {
				data.Theme = "dark"

				return nil
			})
			if (err != nil) != tt.wantErr {
				t.Errorf("UpdateCustomUserData() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func TestOIDCAzureAPI_UserData(t *testing.T) {
	t.Parallel()

	userID := ccc.Must(ccc.NewUUID())
	anchor := &sessionstorage.OIDCUser{ID: userID, Tid: "tid-1", Oid: "oid-1", Username: "user@example.com"}

	ctrl := gomock.NewController(t)
	storage := mock_sessionstorage.NewMockOIDCStore(ctrl)
	o := &OIDCAzure[NoCustomData, testUserProfile]{storage: storage}

	storage.EXPECT().OIDCUser(gomock.Any(), userID).Return(anchor, nil)
	storage.EXPECT().OIDCUserByKey(gomock.Any(), "tid-1", "oid-1").Return(anchor, nil)
	storage.EXPECT().CustomUserData(gomock.Any(), userID).Return(&testUserProfile{Email: "a@b.c"}, nil)
	storage.EXPECT().UpdateCustomUserData(gomock.Any(), userID, gomock.Any()).
		DoAndReturn(func(_ context.Context, _ ccc.UUID, mutate func(any) error) error {
			return mutate(&testUserProfile{})
		})

	if got, err := o.API().OIDCUser(t.Context(), userID); err != nil || got != anchor {
		t.Errorf("OIDCUser() = %+v, %v; want %+v, nil", got, err, anchor)
	}
	if got, err := o.API().OIDCUserByKey(t.Context(), "tid-1", "oid-1"); err != nil || got != anchor {
		t.Errorf("OIDCUserByKey() = %+v, %v; want %+v, nil", got, err, anchor)
	}
	if got, err := o.API().CustomUserData(t.Context(), userID); err != nil || got.Email != "a@b.c" {
		t.Errorf("CustomUserData() = %+v, %v; want Email a@b.c, nil", got, err)
	}
	if err := o.API().UpdateCustomUserData(t.Context(), userID, func(*testUserProfile) error { return nil }); err != nil {
		t.Errorf("UpdateCustomUserData() error = %v", err)
	}
}
