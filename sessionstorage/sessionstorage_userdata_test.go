package sessionstorage

import (
	"context"
	"encoding/json"
	"reflect"
	"testing"

	"github.com/cccteam/ccc"
	"github.com/cccteam/session/internal/dbtype"
	"github.com/go-playground/errors/v5"
	gomock "go.uber.org/mock/gomock"
)

func TestSessionStorage_CustomUserData(t *testing.T) {
	t.Parallel()

	userID := ccc.Must(ccc.NewUUID())

	tests := []struct {
		name    string
		prepare func(mockDB *Mockdb)
		want    any
		wantErr bool
	}{
		{
			name: "returns the driver's data",
			prepare: func(mockDB *Mockdb) {
				mockDB.EXPECT().CustomUserData(gomock.Any(), userID).Return(&testUserData{Email: "a@b.c"}, nil)
			},
			want: &testUserData{Email: "a@b.c"},
		},
		{
			name: "wraps the driver error",
			prepare: func(mockDB *Mockdb) {
				mockDB.EXPECT().CustomUserData(gomock.Any(), userID).Return(nil, errors.New("db error"))
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
			storage := &PasswordAuth{sessionStorage: sessionStorage{db: mockDB}}

			got, err := storage.CustomUserData(context.Background(), userID)
			if (err != nil) != tt.wantErr {
				t.Fatalf("CustomUserData() error = %v, wantErr %v", err, tt.wantErr)
			}
			if !tt.wantErr && !reflect.DeepEqual(got, tt.want) {
				t.Errorf("CustomUserData() = %+v, want %+v", got, tt.want)
			}
		})
	}
}

func TestSessionStorage_UpdateCustomUserData(t *testing.T) {
	t.Parallel()

	userID := ccc.Must(ccc.NewUUID())

	tests := []struct {
		name    string
		prepare func(mockDB *Mockdb)
		wantErr bool
	}{
		{
			name: "passes the erased mutate through",
			prepare: func(mockDB *Mockdb) {
				mockDB.EXPECT().UpdateCustomUserData(gomock.Any(), userID, gomock.Any()).
					DoAndReturn(func(_ context.Context, _ ccc.UUID, mutate func(any) error) error {
						data := &testUserData{}
						if err := mutate(data); err != nil {
							return err
						}
						if data.Theme != "mutated" {
							return errors.New("mutate did not run")
						}

						return nil
					})
			},
		},
		{
			name: "wraps the driver error",
			prepare: func(mockDB *Mockdb) {
				mockDB.EXPECT().UpdateCustomUserData(gomock.Any(), userID, gomock.Any()).Return(errors.New("db error"))
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
			storage := &OIDC{sessionStorage: sessionStorage{db: mockDB}}

			err := storage.UpdateCustomUserData(context.Background(), userID, func(data any) error {
				typed, ok := data.(*testUserData)
				if !ok {
					return errors.Newf("unexpected mutate data type %T", data)
				}
				typed.Theme = "mutated"

				return nil
			})
			if (err != nil) != tt.wantErr {
				t.Fatalf("UpdateCustomUserData() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func TestSessionStorage_UserDataProbesDelegate(t *testing.T) {
	t.Parallel()

	ctrl := gomock.NewController(t)
	mockDB := NewMockdb(ctrl)
	storage := &PasswordAuth{sessionStorage: sessionStorage{db: mockDB}}

	uType := reflect.TypeFor[testUserData]()
	mockDB.EXPECT().CustomUserDataType().Return(uType)
	mockDB.EXPECT().UserDataLoginHookConfigured().Return(true)
	mockDB.EXPECT().OIDCUsersEnabled().Return(true)
	mockDB.EXPECT().SetOIDCUserTableName("MyOIDCUsers")

	if got := storage.CustomUserDataType(); got != uType {
		t.Errorf("CustomUserDataType() = %v, want %v", got, uType)
	}
	if !storage.UserDataLoginHookConfigured() {
		t.Error("UserDataLoginHookConfigured() = false, want true")
	}
	if !storage.OIDCUsersEnabled() {
		t.Error("OIDCUsersEnabled() = false, want true")
	}
	storage.SetOIDCUserTableName("MyOIDCUsers")
}

func TestOIDC_OIDCUserReadsDelegate(t *testing.T) {
	t.Parallel()

	id := ccc.Must(ccc.NewUUID())
	want := &dbtype.OIDCUser{ID: id, Tid: "tid-1", Oid: "oid-1", Username: "user@example.com"}

	ctrl := gomock.NewController(t)
	mockDB := NewMockdb(ctrl)
	storage := &OIDC{sessionStorage: sessionStorage{db: mockDB}}

	mockDB.EXPECT().OIDCUser(gomock.Any(), id).Return(want, nil)
	mockDB.EXPECT().OIDCUserByKey(gomock.Any(), "tid-1", "oid-1").Return(want, nil)

	if got, err := storage.OIDCUser(context.Background(), id); err != nil || got != want {
		t.Errorf("OIDCUser() = %+v, %v; want %+v, nil", got, err, want)
	}
	if got, err := storage.OIDCUserByKey(context.Background(), "tid-1", "oid-1"); err != nil || got != want {
		t.Errorf("OIDCUserByKey() = %+v, %v; want %+v, nil", got, err, want)
	}
}

func TestOIDC_NewSession_InvalidClaims(t *testing.T) {
	t.Parallel()

	ctrl := gomock.NewController(t)
	mockDB := NewMockdb(ctrl)
	storage := &OIDC{sessionStorage: sessionStorage{db: mockDB}}

	if _, err := storage.NewSession(context.Background(), "user", "sid", json.RawMessage(`not json`)); err == nil {
		t.Error("NewSession() error = nil for malformed claims, want error")
	}
}

func TestPasswordAuth_CreateUser_CustomDataPassthrough(t *testing.T) {
	t.Parallel()

	data := &testUserData{Email: "a@b.c"}

	ctrl := gomock.NewController(t)
	mockDB := NewMockdb(ctrl)
	storage := &PasswordAuth{sessionStorage: sessionStorage{db: mockDB}}

	mockDB.EXPECT().
		CreateUser(gomock.Any(), &dbtype.InsertSessionUser{Username: "user"}, data).
		Return(&dbtype.SessionUser{Username: "user"}, nil)

	if _, err := storage.CreateUser(context.Background(), &dbtype.InsertSessionUser{Username: "user"}, data); err != nil {
		t.Fatalf("CreateUser() error = %v", err)
	}
}
