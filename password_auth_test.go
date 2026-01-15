package session

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/cccteam/ccc"
	"github.com/cccteam/ccc/securehash"
	"github.com/cccteam/httpio"
	"github.com/cccteam/session/internal/dbtype"
	"github.com/cccteam/session/internal/types"
	"github.com/cccteam/session/mock/mock_cookie"
	"github.com/cccteam/session/sessioninfo"
	"github.com/cccteam/session/sessionstorage/mock/mock_sessionstorage"
	"github.com/go-playground/errors/v5"
	gomock "go.uber.org/mock/gomock"
)

func TestPasswordAuth_Login(t *testing.T) {
	t.Parallel()

	validHash, err := securehash.New(securehash.Argon2()).Hash("password")
	if err != nil {
		t.Fatal(err)
	}

	oldHash, err := securehash.New(securehash.Bcrypt()).Hash("password")
	if err != nil {
		t.Fatal(err)
	}

	tests := []struct {
		name           string
		reqBody        any
		prepare        func(storage *mock_sessionstorage.MockPasswordAuthStore, cookieHandler *mock_cookie.MockHandler)
		wantMessage    bool
		wantStatusCode int
	}{
		{
			name:           "fails on decode",
			reqBody:        "invalid json",
			wantStatusCode: http.StatusBadRequest,
			wantMessage:    true,
		},
		{
			name: "fails on user not found",
			reqBody: map[string]string{
				"username": "user",
				"password": "password",
			},
			prepare: func(storage *mock_sessionstorage.MockPasswordAuthStore, _ *mock_cookie.MockHandler) {
				storage.EXPECT().UserByUserName(gomock.Any(), "user").Return(nil, errors.New("not found"))
			},
			wantStatusCode: http.StatusUnauthorized,
			wantMessage:    true,
		},
		{
			name: "fails on invalid credentials",
			reqBody: map[string]string{
				"username": "user",
				"password": "wrongpassword",
			},
			prepare: func(storage *mock_sessionstorage.MockPasswordAuthStore, _ *mock_cookie.MockHandler) {
				storage.EXPECT().UserByUserName(gomock.Any(), "user").Return(&dbtype.SessionUser{
					PasswordHash: validHash,
				}, nil)
			},
			wantStatusCode: http.StatusUnauthorized,
			wantMessage:    true,
		},
		{
			name: "fails on disabled user",
			reqBody: map[string]string{
				"username": "user",
				"password": "password",
			},
			prepare: func(storage *mock_sessionstorage.MockPasswordAuthStore, _ *mock_cookie.MockHandler) {
				storage.EXPECT().UserByUserName(gomock.Any(), "user").Return(&dbtype.SessionUser{
					PasswordHash: validHash,
					Disabled:     true,
				}, nil)
			},
			wantStatusCode: http.StatusUnauthorized,
			wantMessage:    true,
		},
		{
			name: "fails on new session",
			reqBody: map[string]string{
				"username": "user",
				"password": "password",
			},
			prepare: func(storage *mock_sessionstorage.MockPasswordAuthStore, _ *mock_cookie.MockHandler) {
				storage.EXPECT().UserByUserName(gomock.Any(), "user").Return(&dbtype.SessionUser{
					Username:     "user",
					PasswordHash: validHash,
				}, nil)
				storage.EXPECT().NewSession(gomock.Any(), "user").Return(ccc.NilUUID, errors.New("new session failed"))
			},
			wantStatusCode: http.StatusInternalServerError,
		},
		{
			name: "fails on new auth cookie",
			reqBody: map[string]string{
				"username": "user",
				"password": "password",
			},
			prepare: func(storage *mock_sessionstorage.MockPasswordAuthStore, cookieHandler *mock_cookie.MockHandler) {
				storage.EXPECT().UserByUserName(gomock.Any(), "user").Return(&dbtype.SessionUser{
					Username:     "user",
					PasswordHash: validHash,
				}, nil)
				sessionID := ccc.Must(ccc.NewUUID())
				storage.EXPECT().NewSession(gomock.Any(), "user").Return(sessionID, nil)
				cookieHandler.EXPECT().NewAuthCookie(gomock.Any(), true, sessionID).Return(nil, errors.New("new auth cookie failed"))
			},
			wantStatusCode: http.StatusInternalServerError,
		},
		{
			name: "success",
			reqBody: map[string]string{
				"username": "user",
				"password": "password",
			},
			prepare: func(storage *mock_sessionstorage.MockPasswordAuthStore, cookieHandler *mock_cookie.MockHandler) {
				storage.EXPECT().UserByUserName(gomock.Any(), "user").Return(&dbtype.SessionUser{
					Username:     "user",
					PasswordHash: validHash,
				}, nil)
				sessionID := ccc.Must(ccc.NewUUID())
				storage.EXPECT().NewSession(gomock.Any(), "user").Return(sessionID, nil)
				cookieHandler.EXPECT().NewAuthCookie(gomock.Any(), true, sessionID).Return(map[types.SCKey]string{}, nil)
				cookieHandler.EXPECT().CreateXSRFTokenCookie(gomock.Any(), sessionID, types.XSRFCookieLife)
			},
			wantStatusCode: http.StatusOK,
		},
		{
			name: "success with password hash upgrade",
			reqBody: map[string]string{
				"username": "user",
				"password": "password",
			},
			prepare: func(storage *mock_sessionstorage.MockPasswordAuthStore, cookieHandler *mock_cookie.MockHandler) {
				userID := ccc.Must(ccc.NewUUID())
				storage.EXPECT().UserByUserName(gomock.Any(), "user").Return(&dbtype.SessionUser{
					ID:           userID,
					Username:     "user",
					PasswordHash: oldHash,
				}, nil)
				storage.EXPECT().SetUserPasswordHash(gomock.Any(), userID, gomock.Any()).Return(nil)
				sessionID := ccc.Must(ccc.NewUUID())
				storage.EXPECT().NewSession(gomock.Any(), "user").Return(sessionID, nil)
				cookieHandler.EXPECT().NewAuthCookie(gomock.Any(), true, sessionID).Return(map[types.SCKey]string{}, nil)
				cookieHandler.EXPECT().CreateXSRFTokenCookie(gomock.Any(), sessionID, types.XSRFCookieLife)
			},
			wantStatusCode: http.StatusOK,
		},
		{
			name: "password hash upgrade fails",
			reqBody: map[string]string{
				"username": "user",
				"password": "password",
			},
			prepare: func(storage *mock_sessionstorage.MockPasswordAuthStore, cookieHandler *mock_cookie.MockHandler) {
				userID := ccc.Must(ccc.NewUUID())
				storage.EXPECT().UserByUserName(gomock.Any(), "user").Return(&dbtype.SessionUser{
					ID:           userID,
					Username:     "user",
					PasswordHash: oldHash,
				}, nil)
				storage.EXPECT().SetUserPasswordHash(gomock.Any(), userID, gomock.Any()).Return(errors.New("db error"))
				sessionID := ccc.Must(ccc.NewUUID())
				storage.EXPECT().NewSession(gomock.Any(), "user").Return(sessionID, nil)
				cookieHandler.EXPECT().NewAuthCookie(gomock.Any(), true, sessionID).Return(map[types.SCKey]string{}, nil)
				cookieHandler.EXPECT().CreateXSRFTokenCookie(gomock.Any(), sessionID, types.XSRFCookieLife)
			},
			wantStatusCode: http.StatusOK,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			ctrl := gomock.NewController(t)

			storage := mock_sessionstorage.NewMockPasswordAuthStore(ctrl)
			cookieHandler := mock_cookie.NewMockHandler(ctrl)

			p, err := NewPasswordAuth(storage, cookieKey)
			if err != nil {
				t.Fatalf("NewPasswordAuth() error=%v", err)
			}
			p.hasher = securehash.New(securehash.Argon2())
			p.baseSession.CookieHandler = cookieHandler

			if tt.prepare != nil {
				tt.prepare(storage, cookieHandler)
			}

			var req *http.Request
			if tt.reqBody != nil {
				b, err := json.Marshal(tt.reqBody)
				if err != nil {
					t.Fatal(err)
				}

				req = httptest.NewRequest(http.MethodPost, "/login", bytes.NewReader(b))
			} else {
				req = httptest.NewRequest(http.MethodPost, "/login", http.NoBody)
			}

			rr := httptest.NewRecorder()

			p.Login().ServeHTTP(rr, req)

			if got := rr.Code; got != tt.wantStatusCode {
				t.Errorf("response.Code = %v, want %v", got, tt.wantStatusCode)
			}

			if tt.wantMessage {
				var got httpio.MessageResponse
				if err := json.Unmarshal(rr.Body.Bytes(), &got); err != nil {
					t.Errorf("json.Unmarshal() error=%v", err)
				}
				if got.Message == "" {
					t.Errorf("Password.Login() message = %v, wantMessage = %v", got, tt.wantMessage)
				}
			}
		})
	}
}

func TestPasswordAuth_ValidateSession(t *testing.T) {
	t.Parallel()

	tnow := time.Now()

	tests := []struct {
		name            string
		prepare         func(storage *mock_sessionstorage.MockPasswordAuthStore)
		wantMessage     bool
		wantStatusCode  int
		wantSessionInfo *sessioninfo.SessionInfo
		wantUserInfo    *sessioninfo.UserInfo
	}{
		{
			name: "fails on check session",
			prepare: func(storage *mock_sessionstorage.MockPasswordAuthStore) {
				storage.EXPECT().Session(gomock.Any(), gomock.Any()).Return(nil, errors.New("not found"))
			},
			wantStatusCode: http.StatusUnauthorized,
			wantMessage:    true,
		},
		{
			name: "fails on user not found",
			prepare: func(storage *mock_sessionstorage.MockPasswordAuthStore) {
				storage.EXPECT().Session(gomock.Any(), gomock.Any()).Return(&sessioninfo.SessionInfo{
					ID:        ccc.Must(ccc.NewUUID()),
					Username:  "user",
					CreatedAt: time.Now(),
					UpdatedAt: time.Now(),
				}, nil)
				storage.EXPECT().UserByUserName(gomock.Any(), "user").Return(nil, errors.New("not found"))
			},
			wantStatusCode: http.StatusInternalServerError,
		},
		{
			name: "fails on disabled user",
			prepare: func(storage *mock_sessionstorage.MockPasswordAuthStore) {
				storage.EXPECT().Session(gomock.Any(), gomock.Any()).Return(&sessioninfo.SessionInfo{
					ID:        ccc.Must(ccc.NewUUID()),
					Username:  "user",
					CreatedAt: time.Now(),
					UpdatedAt: time.Now(),
				}, nil)
				storage.EXPECT().UserByUserName(gomock.Any(), "user").Return(&dbtype.SessionUser{Disabled: true}, nil)
			},
			wantStatusCode: http.StatusUnauthorized,
			wantMessage:    true,
		},
		{
			name: "success",
			prepare: func(storage *mock_sessionstorage.MockPasswordAuthStore) {
				storage.EXPECT().Session(gomock.Any(), gomock.Any()).Return(&sessioninfo.SessionInfo{
					ID:        ccc.Must(ccc.UUIDFromString("66f0def8-f353-4bcf-97a2-12d719fb2dcf")),
					Username:  "user",
					CreatedAt: tnow,
					UpdatedAt: tnow.Add(5 * time.Minute),
				}, nil)
				storage.EXPECT().UserByUserName(gomock.Any(), "user").Return(&dbtype.SessionUser{
					ID:       ccc.Must(ccc.UUIDFromString("c3c2e09e-90f8-40f8-9857-88d420625a89")),
					Username: "user",
				}, nil)
			},
			wantStatusCode: http.StatusOK,
			wantSessionInfo: &sessioninfo.SessionInfo{
				ID:        ccc.Must(ccc.UUIDFromString("66f0def8-f353-4bcf-97a2-12d719fb2dcf")),
				Username:  "user",
				CreatedAt: tnow,
				UpdatedAt: tnow.Add(5 * time.Minute),
			},
			wantUserInfo: &sessioninfo.UserInfo{
				ID:       ccc.Must(ccc.UUIDFromString("c3c2e09e-90f8-40f8-9857-88d420625a89")),
				Username: "user",
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			ctrl := gomock.NewController(t)

			storage := mock_sessionstorage.NewMockPasswordAuthStore(ctrl)

			p, err := NewPasswordAuth(storage, cookieKey)
			if err != nil {
				t.Fatalf("NewPasswordAuth() error=%v", err)
			}
			p.storage = storage
			p.baseSession.SessionTimeout = time.Minute

			if tt.prepare != nil {
				tt.prepare(storage)
			}

			nextHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.WriteHeader(http.StatusOK)
				if got := sessioninfo.FromCtx(r.Context()); !reflect.DeepEqual(got, tt.wantSessionInfo) {
					t.Errorf("sessioninfo.SessionInfo = %v, want %v", *got, *tt.wantSessionInfo)
				}
				if got := sessioninfo.UserFromCtx(r.Context()); !reflect.DeepEqual(got, tt.wantUserInfo) {
					t.Errorf("sessioninfo.UserInfo = %v, want %v", *got, *tt.wantUserInfo)
				}
			})
			handler := p.ValidateSession(nextHandler)
			req, err := createHTTPRequest(http.MethodGet, nil, nil, nil, nil)
			if err != nil {
				t.Fatal(err)
			}
			rr := httptest.NewRecorder()

			handler.ServeHTTP(rr, req)

			if got := rr.Code; got != tt.wantStatusCode {
				t.Errorf("response.Code = %v, want %v", got, tt.wantStatusCode)
			}
			if tt.wantMessage {
				var got httpio.MessageResponse
				if err := json.Unmarshal(rr.Body.Bytes(), &got); err != nil {
					t.Errorf("json.Unmarshal() error=%v", err)
				}
				if got.Message == "" {
					t.Errorf("Password.Login() message = %v, wantMessage = %v", got, tt.wantMessage)
				}
			}
		})
	}
}

func TestPasswordAuth_Authenticated(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name           string
		prepare        func(storage *mock_sessionstorage.MockPasswordAuthStore)
		sessionInfo    *sessioninfo.SessionInfo
		wantMessage    bool
		wantStatusCode int
		wantBody       string
	}{
		{
			name: "fails on check session",
			prepare: func(storage *mock_sessionstorage.MockPasswordAuthStore) {
				storage.EXPECT().Session(gomock.Any(), gomock.Any()).Return(nil, errors.New("not found"))
			},
			wantStatusCode: http.StatusOK,
			wantBody:       `{"authenticated":false,"username":""}` + "\n",
		},
		{
			name: "fails on user not found",
			sessionInfo: &sessioninfo.SessionInfo{
				Username: "user",
			},
			prepare: func(storage *mock_sessionstorage.MockPasswordAuthStore) {
				storage.EXPECT().Session(gomock.Any(), gomock.Any()).Return(&sessioninfo.SessionInfo{
					ID:        ccc.Must(ccc.NewUUID()),
					Username:  "user",
					CreatedAt: time.Now(),
					UpdatedAt: time.Now(),
				}, nil)
				storage.EXPECT().UserByUserName(gomock.Any(), "user").Return(nil, errors.New("not found"))
			},
			wantStatusCode: http.StatusInternalServerError,
			wantMessage:    false,
		},
		{
			name: "fails on disabled user",
			sessionInfo: &sessioninfo.SessionInfo{
				Username: "user",
			},
			prepare: func(storage *mock_sessionstorage.MockPasswordAuthStore) {
				storage.EXPECT().Session(gomock.Any(), gomock.Any()).Return(&sessioninfo.SessionInfo{
					ID:        ccc.Must(ccc.NewUUID()),
					Username:  "user",
					CreatedAt: time.Now(),
					UpdatedAt: time.Now(),
				}, nil)
				storage.EXPECT().UserByUserName(gomock.Any(), "user").Return(&dbtype.SessionUser{Disabled: true}, nil)
			},
			wantStatusCode: http.StatusUnauthorized,
			wantMessage:    true,
		},
		{
			name: "success, skip update session activity",
			sessionInfo: &sessioninfo.SessionInfo{
				Username: "user",
			},
			prepare: func(storage *mock_sessionstorage.MockPasswordAuthStore) {
				storage.EXPECT().Session(gomock.Any(), gomock.Any()).Return(&sessioninfo.SessionInfo{
					ID:        ccc.Must(ccc.NewUUID()),
					Username:  "user",
					CreatedAt: time.Now(),
					UpdatedAt: time.Now(),
				}, nil)
				storage.EXPECT().UserByUserName(gomock.Any(), "user").Return(&dbtype.SessionUser{Username: "user"}, nil)
			},
			wantStatusCode: http.StatusOK,
			wantBody:       `{"authenticated":true,"username":"user"}` + "\n",
		},
		{
			name: "success, update session activity",
			sessionInfo: &sessioninfo.SessionInfo{
				Username: "user",
			},
			prepare: func(storage *mock_sessionstorage.MockPasswordAuthStore) {
				sessionID := ccc.Must(ccc.NewUUID())
				storage.EXPECT().Session(gomock.Any(), gomock.Any()).Return(&sessioninfo.SessionInfo{
					ID:        sessionID,
					Username:  "user",
					CreatedAt: time.Now().Add(-8 * time.Second),
					UpdatedAt: time.Now().Add(-6 * time.Second),
				}, nil)
				storage.EXPECT().UserByUserName(gomock.Any(), "user").Return(&dbtype.SessionUser{Username: "user"}, nil)
				storage.EXPECT().UpdateSessionActivity(gomock.Any(), sessionID).Return(nil)
			},
			wantStatusCode: http.StatusOK,
			wantBody:       `{"authenticated":true,"username":"user"}` + "\n",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			ctrl := gomock.NewController(t)

			storage := mock_sessionstorage.NewMockPasswordAuthStore(ctrl)

			p, err := NewPasswordAuth(storage, cookieKey)
			if err != nil {
				t.Fatalf("NewPasswordAuth() error=%v", err)
			}
			p.storage = storage

			if tt.prepare != nil {
				tt.prepare(storage)
			}

			req, err := createHTTPRequest(http.MethodGet, nil, tt.sessionInfo, nil, nil)
			if err != nil {
				t.Fatal(err)
			}
			rr := httptest.NewRecorder()

			p.Authenticated().ServeHTTP(rr, req)

			if got := rr.Code; got != tt.wantStatusCode {
				t.Errorf("response.Code = %v, want %v", got, tt.wantStatusCode)
			}
			if tt.wantMessage {
				var got httpio.MessageResponse
				if err := json.Unmarshal(rr.Body.Bytes(), &got); err != nil {
					t.Errorf("json.Unmarshal() error=%v", err)
				}
				if got.Message == "" {
					t.Errorf("Password.Login() message = %v, wantMessage = %v", got, tt.wantMessage)
				}
			} else {
				if got := rr.Body.String(); got != tt.wantBody {
					t.Errorf("response.Body = %v, want %v", got, tt.wantBody)
				}
			}
		})
	}
}

func TestPasswordAuth_ChangeUserPassword(t *testing.T) {
	t.Parallel()

	hasher := securehash.New(securehash.Argon2())
	validHash, err := hasher.Hash("oldpassword")
	if err != nil {
		t.Fatal(err)
	}
	userID := ccc.Must(ccc.NewUUID())

	tests := []struct {
		name           string
		reqBody        any
		userInfo       *sessioninfo.UserInfo
		prepare        func(storage *mock_sessionstorage.MockPasswordAuthStore)
		wantMessage    bool
		wantStatusCode int
	}{
		{
			name:           "fails on decode",
			reqBody:        "invalid json",
			userInfo:       &sessioninfo.UserInfo{ID: userID},
			wantStatusCode: http.StatusBadRequest,
			wantMessage:    true,
		},
		{
			name: "fails on user not found",
			reqBody: map[string]string{
				"oldPassword": "oldpassword",
				"newPassword": "newpassword",
			},
			userInfo: &sessioninfo.UserInfo{ID: userID},
			prepare: func(storage *mock_sessionstorage.MockPasswordAuthStore) {
				storage.EXPECT().User(gomock.Any(), userID).Return(nil, errors.New("not found"))
			},
			wantStatusCode: http.StatusInternalServerError,
		},
		{
			name: "fails on invalid old password",
			reqBody: map[string]string{
				"oldPassword": "wrong_oldpassword",
				"newPassword": "newpassword",
			},
			userInfo: &sessioninfo.UserInfo{ID: userID},
			prepare: func(storage *mock_sessionstorage.MockPasswordAuthStore) {
				storage.EXPECT().User(gomock.Any(), userID).Return(&dbtype.SessionUser{PasswordHash: validHash}, nil)
			},
			wantStatusCode: http.StatusBadRequest,
			wantMessage:    true,
		},
		{
			name: "fails on storing new password hash",
			reqBody: map[string]string{
				"oldPassword": "oldpassword",
				"newPassword": "newpassword",
			},
			userInfo: &sessioninfo.UserInfo{ID: userID},
			prepare: func(storage *mock_sessionstorage.MockPasswordAuthStore) {
				storage.EXPECT().User(gomock.Any(), userID).Return(&dbtype.SessionUser{
					ID:           userID,
					PasswordHash: validHash,
				}, nil)
				storage.EXPECT().SetUserPasswordHash(gomock.Any(), userID, gomock.Any()).Return(errors.New("db error"))
			},
			wantStatusCode: http.StatusInternalServerError,
		},
		{
			name: "success",
			reqBody: map[string]string{
				"oldPassword": "oldpassword",
				"newPassword": "newpassword",
			},
			userInfo: &sessioninfo.UserInfo{ID: userID},
			prepare: func(storage *mock_sessionstorage.MockPasswordAuthStore) {
				storage.EXPECT().User(gomock.Any(), userID).Return(&dbtype.SessionUser{
					ID:           userID,
					PasswordHash: validHash,
				}, nil)
				storage.EXPECT().SetUserPasswordHash(gomock.Any(), userID, gomock.Any()).Return(nil)
			},
			wantStatusCode: http.StatusOK,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			ctrl := gomock.NewController(t)

			storage := mock_sessionstorage.NewMockPasswordAuthStore(ctrl)
			p, err := NewPasswordAuth(storage, cookieKey)
			if err != nil {
				t.Fatalf("NewPasswordAuth() error=%v", err)
			}
			p.storage = storage
			p.hasher = hasher

			if tt.prepare != nil {
				tt.prepare(storage)
			}

			var body io.Reader
			if tt.reqBody != nil {
				b, err := json.Marshal(tt.reqBody)
				if err != nil {
					t.Fatal(err)
				}
				body = bytes.NewReader(b)
			}

			req, err := createHTTPRequest(http.MethodPost, body, nil, tt.userInfo, nil)
			if err != nil {
				t.Fatal(err)
			}

			rr := httptest.NewRecorder()

			p.ChangeUserPassword().ServeHTTP(rr, req)

			if got := rr.Code; got != tt.wantStatusCode {
				t.Errorf("response.Code = %v, want %v", got, tt.wantStatusCode)
			}
			if tt.wantMessage {
				var got httpio.MessageResponse
				if err := json.Unmarshal(rr.Body.Bytes(), &got); err != nil {
					t.Errorf("json.Unmarshal() error=%v", err)
				}
				if got.Message == "" {
					t.Errorf("Password.ChangeUserPassword() message = %v, wantMessage = %v", got, tt.wantMessage)
				}
			}
		})
	}
}

func TestPasswordAuth_CreateUser(t *testing.T) {
	t.Parallel()

	hasher := securehash.New(securehash.Argon2())
	userID := ccc.Must(ccc.NewUUID())

	tests := []struct {
		name           string
		reqBody        string
		prepare        func(storage *mock_sessionstorage.MockPasswordAuthStore)
		wantStatusCode int
		wantBody       string
		wantMessage    bool
	}{
		{
			name:           "fails on decode",
			reqBody:        "invalid json",
			wantStatusCode: http.StatusBadRequest,
			wantMessage:    true,
		},
		{
			name:    "fails on create user",
			reqBody: `{"username": "user", "password": "password"}`,
			prepare: func(storage *mock_sessionstorage.MockPasswordAuthStore) {
				storage.EXPECT().CreateUser(gomock.Any(), gomock.Any()).Return(nil, errors.New("db error"))
			},
			wantStatusCode: http.StatusInternalServerError,
		},
		{
			name:    "success",
			reqBody: `{"username": "user", "password": "password"}`,
			prepare: func(storage *mock_sessionstorage.MockPasswordAuthStore) {
				storage.EXPECT().CreateUser(gomock.Any(), gomock.Any()).Return(&dbtype.SessionUser{
					ID:       userID,
					Username: "user",
				}, nil)
			},
			wantStatusCode: http.StatusOK,
			wantBody:       `{"id":"` + userID.String() + `"}` + "\n",
		},
		{
			name:    "success with empty password",
			reqBody: `{"username": "user"}`,
			prepare: func(storage *mock_sessionstorage.MockPasswordAuthStore) {
				storage.EXPECT().CreateUser(gomock.Any(), &dbtype.InsertSessionUser{Username: "user"}).Return(&dbtype.SessionUser{
					ID:       userID,
					Username: "user",
				}, nil)
			},
			wantStatusCode: http.StatusOK,
			wantBody:       `{"id":"` + userID.String() + `"}` + "\n",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			ctrl := gomock.NewController(t)

			storage := mock_sessionstorage.NewMockPasswordAuthStore(ctrl)
			p, err := NewPasswordAuth(storage, cookieKey)
			if err != nil {
				t.Fatalf("NewPasswordAuth() error=%v", err)
			}
			p.storage = storage
			p.hasher = hasher

			if tt.prepare != nil {
				tt.prepare(storage)
			}

			var body io.Reader = http.NoBody
			if tt.reqBody != "" {
				body = strings.NewReader(tt.reqBody)
			}

			req, err := createHTTPRequest(http.MethodPost, body, nil, nil, nil)
			if err != nil {
				t.Fatal(err)
			}

			rr := httptest.NewRecorder()

			p.CreateUser().ServeHTTP(rr, req)

			if got := rr.Code; got != tt.wantStatusCode {
				t.Errorf("response.Code = %v, want %v", got, tt.wantStatusCode)
			}
			if tt.wantMessage {
				var got httpio.MessageResponse
				if err := json.Unmarshal(rr.Body.Bytes(), &got); err != nil {
					t.Errorf("json.Unmarshal() error=%v", err)
				}
				if got.Message == "" {
					t.Errorf("Password.CreateUser() message = %v, wantMessage = %v", got, tt.wantMessage)
				}
			} else if tt.wantBody != "" {
				if got := rr.Body.String(); got != tt.wantBody {
					t.Errorf("response.Body = %q, want %q", got, tt.wantBody)
				}
			}
		})
	}
}

func TestPassword_DeactivateUser(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name           string
		userID         ccc.UUID
		sameUserID     bool
		prepare        func(storage *mock_sessionstorage.MockPasswordAuthStore)
		wantMessage    bool
		wantStatusCode int
	}{
		{
			name:   "fails on storage error",
			userID: ccc.Must(ccc.UUIDFromString("123e4567-e89b-12d3-a456-426614174000")),
			prepare: func(storage *mock_sessionstorage.MockPasswordAuthStore) {
				storage.EXPECT().User(gomock.Any(), ccc.Must(ccc.UUIDFromString("123e4567-e89b-12d3-a456-426614174000"))).Return(nil, errors.New("db error"))
			},
			wantStatusCode: http.StatusInternalServerError,
		},
		{
			name:   "fails on destroy all sessions",
			userID: ccc.Must(ccc.UUIDFromString("123e4567-e89b-12d3-a456-426614174000")),
			prepare: func(storage *mock_sessionstorage.MockPasswordAuthStore) {
				storage.EXPECT().User(gomock.Any(), ccc.Must(ccc.UUIDFromString("123e4567-e89b-12d3-a456-426614174000"))).Return(&dbtype.SessionUser{
					ID:       ccc.Must(ccc.UUIDFromString("123e4567-e89b-12d3-a456-426614174000")),
					Username: "user",
				}, nil)
				storage.EXPECT().DeactivateUser(gomock.Any(), ccc.Must(ccc.UUIDFromString("123e4567-e89b-12d3-a456-426614174000"))).Return(nil)
				storage.EXPECT().DestroyAllUserSessions(gomock.Any(), "user").Return(errors.New("db error"))
			},
			wantStatusCode: http.StatusInternalServerError,
		},
		{
			name:   "success",
			userID: ccc.Must(ccc.UUIDFromString("123e4567-e89b-12d3-a456-426614174000")),
			prepare: func(storage *mock_sessionstorage.MockPasswordAuthStore) {
				storage.EXPECT().User(gomock.Any(), ccc.Must(ccc.UUIDFromString("123e4567-e89b-12d3-a456-426614174000"))).Return(&dbtype.SessionUser{
					ID:       ccc.Must(ccc.UUIDFromString("123e4567-e89b-12d3-a456-426614174000")),
					Username: "user",
				}, nil)
				storage.EXPECT().DeactivateUser(gomock.Any(), ccc.Must(ccc.UUIDFromString("123e4567-e89b-12d3-a456-426614174000"))).Return(nil)
				storage.EXPECT().DestroyAllUserSessions(gomock.Any(), "user").Return(nil)
			},
			wantStatusCode: http.StatusOK,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			ctrl := gomock.NewController(t)

			storage := mock_sessionstorage.NewMockPasswordAuthStore(ctrl)
			p, err := NewPasswordAuth(storage, cookieKey)
			if err != nil {
				t.Fatalf("NewPasswordAuth() error=%v", err)
			}
			p.storage = storage

			if tt.prepare != nil {
				tt.prepare(storage)
			}

			userID := ccc.Must(ccc.UUIDFromString("456e4567-e89b-12d3-a456-426614174001"))
			if tt.sameUserID {
				userID = tt.userID
			}
			req, err := createHTTPRequest(http.MethodPost, http.NoBody, nil, &sessioninfo.UserInfo{ID: userID}, map[httpio.ParamType]string{RouterSessionUserID: tt.userID.String()})
			if err != nil {
				t.Fatal(err)
			}

			rr := httptest.NewRecorder()

			p.DeactivateUser().ServeHTTP(rr, req)

			if got := rr.Code; got != tt.wantStatusCode {
				t.Errorf("response.Code = %v, want %v", got, tt.wantStatusCode)
			}
			if tt.wantMessage {
				var got httpio.MessageResponse
				if err := json.Unmarshal(rr.Body.Bytes(), &got); err != nil {
					t.Errorf("json.Unmarshal() error=%v", err)
				}
				if got.Message == "" {
					t.Errorf("Password.DeactivateUser() message = %v, wantMessage = %v", got, tt.wantMessage)
				}
			}
		})
	}
}

func TestPassword_DeleteUser(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name           string
		userID         ccc.UUID
		sameUserID     bool
		prepare        func(storage *mock_sessionstorage.MockPasswordAuthStore)
		wantMessage    bool
		wantStatusCode int
	}{
		{
			name:       "fails on self delete",
			userID:     ccc.Must(ccc.UUIDFromString("123e4567-e89b-12d3-a456-426614174000")),
			sameUserID: true,
			prepare: func(storage *mock_sessionstorage.MockPasswordAuthStore) {
				storage.EXPECT().User(gomock.Any(), ccc.Must(ccc.UUIDFromString("123e4567-e89b-12d3-a456-426614174000"))).Return(&dbtype.SessionUser{
					ID: ccc.Must(ccc.UUIDFromString("123e4567-e89b-12d3-a456-426614174000")),
				}, nil)
			},
			wantStatusCode: http.StatusBadRequest,
			wantMessage:    true,
		},
		{
			name:   "fails on storage error",
			userID: ccc.Must(ccc.UUIDFromString("123e4567-e89b-12d3-a456-426614174000")),
			prepare: func(storage *mock_sessionstorage.MockPasswordAuthStore) {
				storage.EXPECT().User(gomock.Any(), ccc.Must(ccc.UUIDFromString("123e4567-e89b-12d3-a456-426614174000"))).Return(&dbtype.SessionUser{
					ID:       ccc.Must(ccc.UUIDFromString("123e4567-e89b-12d3-a456-426614174000")),
					Username: "user",
				}, nil)
				storage.EXPECT().DeleteUser(gomock.Any(), ccc.Must(ccc.UUIDFromString("123e4567-e89b-12d3-a456-426614174000"))).Return(errors.New("db error"))
			},
			wantStatusCode: http.StatusInternalServerError,
		},
		{
			name:   "success",
			userID: ccc.Must(ccc.UUIDFromString("123e4567-e89b-12d3-a456-426614174000")),
			prepare: func(storage *mock_sessionstorage.MockPasswordAuthStore) {
				storage.EXPECT().User(gomock.Any(), ccc.Must(ccc.UUIDFromString("123e4567-e89b-12d3-a456-426614174000"))).Return(&dbtype.SessionUser{
					ID:       ccc.Must(ccc.UUIDFromString("123e4567-e89b-12d3-a456-426614174000")),
					Username: "user",
				}, nil)
				storage.EXPECT().DeleteUser(gomock.Any(), ccc.Must(ccc.UUIDFromString("123e4567-e89b-12d3-a456-426614174000"))).Return(nil)
				storage.EXPECT().DestroyAllUserSessions(gomock.Any(), "user").Return(nil)
			},
			wantStatusCode: http.StatusOK,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			ctrl := gomock.NewController(t)

			storage := mock_sessionstorage.NewMockPasswordAuthStore(ctrl)
			p, err := NewPasswordAuth(storage, cookieKey)
			if err != nil {
				t.Fatalf("NewPasswordAuth() error=%v", err)
			}
			p.storage = storage

			if tt.prepare != nil {
				tt.prepare(storage)
			}

			userID := ccc.Must(ccc.UUIDFromString("456e4567-e89b-12d3-a456-426614174001"))
			if tt.sameUserID {
				userID = tt.userID
			}
			req, err := createHTTPRequest(http.MethodPost, http.NoBody, nil, &sessioninfo.UserInfo{ID: userID}, map[httpio.ParamType]string{RouterSessionUserID: tt.userID.String()})
			if err != nil {
				t.Fatal(err)
			}

			rr := httptest.NewRecorder()

			p.DeleteUser().ServeHTTP(rr, req)

			if got := rr.Code; got != tt.wantStatusCode {
				t.Errorf("response.Code = %v, want %v", got, tt.wantStatusCode)
			}
			if tt.wantMessage {
				var got httpio.MessageResponse
				if err := json.Unmarshal(rr.Body.Bytes(), &got); err != nil {
					t.Errorf("json.Unmarshal() error=%v", err)
				}
				if got.Message == "" {
					t.Errorf("Password.DeleteUser() message = %v, wantMessage = %v", got, tt.wantMessage)
				}
			}
		})
	}
}

func TestPassword_ActivateUser(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name           string
		userID         ccc.UUID
		prepare        func(storage *mock_sessionstorage.MockPasswordAuthStore)
		wantMessage    bool
		wantStatusCode int
	}{
		{
			name:   "fails on storage error",
			userID: ccc.Must(ccc.UUIDFromString("123e4567-e89b-12d3-a456-426614174000")),
			prepare: func(storage *mock_sessionstorage.MockPasswordAuthStore) {
				storage.EXPECT().ActivateUser(gomock.Any(), ccc.Must(ccc.UUIDFromString("123e4567-e89b-12d3-a456-426614174000"))).Return(errors.New("db error"))
			},
			wantStatusCode: http.StatusInternalServerError,
		},
		{
			name:   "success",
			userID: ccc.Must(ccc.UUIDFromString("123e4567-e89b-12d3-a456-426614174000")),
			prepare: func(storage *mock_sessionstorage.MockPasswordAuthStore) {
				storage.EXPECT().ActivateUser(gomock.Any(), ccc.Must(ccc.UUIDFromString("123e4567-e89b-12d3-a456-426614174000"))).Return(nil)
			},
			wantStatusCode: http.StatusOK,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			ctrl := gomock.NewController(t)

			storage := mock_sessionstorage.NewMockPasswordAuthStore(ctrl)
			p, err := NewPasswordAuth(storage, cookieKey)
			if err != nil {
				t.Fatalf("NewPasswordAuth() error=%v", err)
			}
			p.storage = storage

			if tt.prepare != nil {
				tt.prepare(storage)
			}

			req, err := createHTTPRequest(http.MethodPost, http.NoBody, nil, nil, map[httpio.ParamType]string{RouterSessionUserID: tt.userID.String()})
			if err != nil {
				t.Fatal(err)
			}

			rr := httptest.NewRecorder()

			p.ActivateUser().ServeHTTP(rr, req)

			if got := rr.Code; got != tt.wantStatusCode {
				t.Errorf("response.Code = %v, want %v", got, tt.wantStatusCode)
			}
			if tt.wantMessage {
				var got httpio.MessageResponse
				if err := json.Unmarshal(rr.Body.Bytes(), &got); err != nil {
					t.Errorf("json.Unmarshal() error=%v", err)
				}
				if got.Message == "" {
					t.Errorf("Password.ActivateUser() message = %v, wantMessage = %v", got, tt.wantMessage)
				}
			}
		})
	}
}

func TestPasswordAuth_ChangeSessionUserPassword(t *testing.T) {
	t.Parallel()

	hasher := securehash.New(securehash.Argon2())
	validHash, err := hasher.Hash("oldpassword")
	if err != nil {
		t.Fatal(err)
	}
	userID := ccc.Must(ccc.NewUUID())

	tests := []struct {
		name    string
		userID  ccc.UUID
		req     *ChangeSessionUserPasswordRequest
		prepare func(storage *mock_sessionstorage.MockPasswordAuthStore)
		wantErr bool
	}{
		{
			name:   "fails on user not found",
			userID: userID,
			req: &ChangeSessionUserPasswordRequest{
				OldPassword: "oldpassword",
				NewPassword: "newpassword",
			},
			prepare: func(storage *mock_sessionstorage.MockPasswordAuthStore) {
				storage.EXPECT().User(gomock.Any(), userID).Return(nil, errors.New("not found"))
			},
			wantErr: true,
		},
		{
			name:   "fails on invalid old password",
			userID: userID,
			req: &ChangeSessionUserPasswordRequest{
				OldPassword: "wrong_oldpassword",
				NewPassword: "newpassword",
			},
			prepare: func(storage *mock_sessionstorage.MockPasswordAuthStore) {
				storage.EXPECT().User(gomock.Any(), userID).Return(&dbtype.SessionUser{PasswordHash: validHash}, nil)
			},
			wantErr: true,
		},
		{
			name:   "fails on storing new password hash",
			userID: userID,
			req: &ChangeSessionUserPasswordRequest{
				OldPassword: "oldpassword",
				NewPassword: "newpassword",
			},
			prepare: func(storage *mock_sessionstorage.MockPasswordAuthStore) {
				storage.EXPECT().User(gomock.Any(), userID).Return(&dbtype.SessionUser{
					ID:           userID,
					PasswordHash: validHash,
				}, nil)
				storage.EXPECT().SetUserPasswordHash(gomock.Any(), userID, gomock.Any()).Return(errors.New("db error"))
			},
			wantErr: true,
		},
		{
			name:   "success",
			userID: userID,
			req: &ChangeSessionUserPasswordRequest{
				OldPassword: "oldpassword",
				NewPassword: "newpassword",
			},
			prepare: func(storage *mock_sessionstorage.MockPasswordAuthStore) {
				storage.EXPECT().User(gomock.Any(), userID).Return(&dbtype.SessionUser{
					ID:           userID,
					PasswordHash: validHash,
				}, nil)
				storage.EXPECT().SetUserPasswordHash(gomock.Any(), userID, gomock.Any()).Return(nil)
			},
			wantErr: false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			ctrl := gomock.NewController(t)

			storage := mock_sessionstorage.NewMockPasswordAuthStore(ctrl)
			p, err := NewPasswordAuth(storage, cookieKey)
			if err != nil {
				t.Fatalf("NewPasswordAuth() error=%v", err)
			}
			p.storage = storage
			p.hasher = hasher

			if tt.prepare != nil {
				tt.prepare(storage)
			}

			err = p.changeSessionUserPassword(t.Context(), tt.userID, tt.req)
			if (err != nil) != tt.wantErr {
				t.Errorf("PasswordAuth.ChangeSessionUserPassword() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func TestPasswordAuth_ChangeSessionUserHash(t *testing.T) {
	t.Parallel()

	userID := ccc.Must(ccc.NewUUID())
	hash, err := securehash.New(securehash.Argon2()).Hash("password")
	if err != nil {
		t.Fatal(err)
	}

	tests := []struct {
		name    string
		userID  ccc.UUID
		hash    *securehash.Hash
		prepare func(storage *mock_sessionstorage.MockPasswordAuthStore)
		wantErr bool
	}{
		{
			name:   "fails on storage error",
			userID: userID,
			hash:   hash,
			prepare: func(storage *mock_sessionstorage.MockPasswordAuthStore) {
				storage.EXPECT().SetUserPasswordHash(gomock.Any(), userID, hash).Return(errors.New("db error"))
			},
			wantErr: true,
		},
		{
			name:   "success",
			userID: userID,
			hash:   hash,
			prepare: func(storage *mock_sessionstorage.MockPasswordAuthStore) {
				storage.EXPECT().SetUserPasswordHash(gomock.Any(), userID, hash).Return(nil)
			},
			wantErr: false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			ctrl := gomock.NewController(t)

			storage := mock_sessionstorage.NewMockPasswordAuthStore(ctrl)
			p, err := NewPasswordAuth(storage, cookieKey)
			if err != nil {
				t.Fatalf("NewPasswordAuth() error=%v", err)
			}
			p.storage = storage

			if tt.prepare != nil {
				tt.prepare(storage)
			}

			err = p.changeSessionUserHash(context.Background(), tt.userID, tt.hash)
			if (err != nil) != tt.wantErr {
				t.Errorf("PasswordAuth.ChangeSessionUserHash() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func TestPasswordAuth_CreateSessionUser(t *testing.T) {
	t.Parallel()

	hasher := securehash.New(securehash.Argon2())
	userID := ccc.Must(ccc.NewUUID())
	password := "password"

	tests := []struct {
		name    string
		req     *CreateUserRequest
		prepare func(storage *mock_sessionstorage.MockPasswordAuthStore)
		wantErr bool
	}{
		{
			name: "fails on create user",
			req: &CreateUserRequest{
				Username: "user",
				Password: &password,
			},
			prepare: func(storage *mock_sessionstorage.MockPasswordAuthStore) {
				storage.EXPECT().CreateUser(gomock.Any(), gomock.Any()).Return(nil, errors.New("db error"))
			},
			wantErr: true,
		},
		{
			name: "success",
			req: &CreateUserRequest{
				Username: "user",
				Password: &password,
			},
			prepare: func(storage *mock_sessionstorage.MockPasswordAuthStore) {
				storage.EXPECT().CreateUser(gomock.Any(), gomock.Any()).Return(&dbtype.SessionUser{
					ID:       userID,
					Username: "user",
				}, nil)
			},
			wantErr: false,
		},
		{
			name: "success with empty password",
			req: &CreateUserRequest{
				Username: "user",
			},
			prepare: func(storage *mock_sessionstorage.MockPasswordAuthStore) {
				storage.EXPECT().CreateUser(gomock.Any(), &dbtype.InsertSessionUser{Username: "user"}).Return(&dbtype.SessionUser{
					ID:       userID,
					Username: "user",
				}, nil)
			},
			wantErr: false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			ctrl := gomock.NewController(t)

			storage := mock_sessionstorage.NewMockPasswordAuthStore(ctrl)
			p, err := NewPasswordAuth(storage, cookieKey)
			if err != nil {
				t.Fatalf("NewPasswordAuth() error=%v", err)
			}
			p.storage = storage
			p.hasher = hasher

			if tt.prepare != nil {
				tt.prepare(storage)
			}

			_, err = p.createSessionUser(t.Context(), tt.req)
			if (err != nil) != tt.wantErr {
				t.Errorf("PasswordAuth.CreateSessionUser() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func TestPasswordAuth_ActivateSessionUser(t *testing.T) {
	t.Parallel()

	userID := ccc.Must(ccc.NewUUID())

	tests := []struct {
		name    string
		userID  ccc.UUID
		prepare func(storage *mock_sessionstorage.MockPasswordAuthStore)
		wantErr bool
	}{
		{
			name:   "fails on storage error",
			userID: userID,
			prepare: func(storage *mock_sessionstorage.MockPasswordAuthStore) {
				storage.EXPECT().ActivateUser(gomock.Any(), userID).Return(errors.New("db error"))
			},
			wantErr: true,
		},
		{
			name:   "success",
			userID: userID,
			prepare: func(storage *mock_sessionstorage.MockPasswordAuthStore) {
				storage.EXPECT().ActivateUser(gomock.Any(), userID).Return(nil)
			},
			wantErr: false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			ctrl := gomock.NewController(t)

			storage := mock_sessionstorage.NewMockPasswordAuthStore(ctrl)
			p, err := NewPasswordAuth(storage, cookieKey)
			if err != nil {
				t.Fatalf("NewPasswordAuth() error=%v", err)
			}

			if tt.prepare != nil {
				tt.prepare(storage)
			}

			err = p.activateSessionUser(t.Context(), tt.userID)
			if (err != nil) != tt.wantErr {
				t.Errorf("PasswordAuth.ActivateSessionUser() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func TestPasswordAuth_DeactivateSessionUser(t *testing.T) {
	t.Parallel()

	userID := ccc.Must(ccc.NewUUID())
	otherUserID := ccc.Must(ccc.NewUUID())

	tests := []struct {
		name    string
		userID  ccc.UUID
		ctx     context.Context
		prepare func(storage *mock_sessionstorage.MockPasswordAuthStore)
		wantErr bool
	}{
		{
			name:   "fails on self deactivate",
			userID: userID,
			ctx:    context.WithValue(context.Background(), sessioninfo.CtxUserInfo, &sessioninfo.UserInfo{ID: userID}),
			prepare: func(storage *mock_sessionstorage.MockPasswordAuthStore) {
				storage.EXPECT().User(gomock.Any(), userID).Return(&dbtype.SessionUser{ID: userID}, nil)
			},
			wantErr: true,
		},
		{
			name:   "fails on storage error",
			userID: userID,
			ctx:    context.WithValue(context.Background(), sessioninfo.CtxUserInfo, &sessioninfo.UserInfo{ID: otherUserID}),
			prepare: func(storage *mock_sessionstorage.MockPasswordAuthStore) {
				storage.EXPECT().User(gomock.Any(), userID).Return(nil, errors.New("db error"))
			},
			wantErr: true,
		},
		{
			name:   "fails on deactivate user",
			userID: userID,
			ctx:    context.WithValue(context.Background(), sessioninfo.CtxUserInfo, &sessioninfo.UserInfo{ID: otherUserID}),
			prepare: func(storage *mock_sessionstorage.MockPasswordAuthStore) {
				storage.EXPECT().User(gomock.Any(), userID).Return(&dbtype.SessionUser{ID: userID, Username: "user"}, nil)
				storage.EXPECT().DeactivateUser(gomock.Any(), userID).Return(errors.New("db error"))
			},
			wantErr: true,
		},
		{
			name:   "fails on destroy all sessions",
			userID: userID,
			ctx:    context.WithValue(context.Background(), sessioninfo.CtxUserInfo, &sessioninfo.UserInfo{ID: otherUserID}),
			prepare: func(storage *mock_sessionstorage.MockPasswordAuthStore) {
				storage.EXPECT().User(gomock.Any(), userID).Return(&dbtype.SessionUser{ID: userID, Username: "user"}, nil)
				storage.EXPECT().DeactivateUser(gomock.Any(), userID).Return(nil)
				storage.EXPECT().DestroyAllUserSessions(gomock.Any(), "user").Return(errors.New("db error"))
			},
			wantErr: true,
		},
		{
			name:   "success",
			userID: userID,
			ctx:    context.WithValue(context.Background(), sessioninfo.CtxUserInfo, &sessioninfo.UserInfo{ID: otherUserID}),
			prepare: func(storage *mock_sessionstorage.MockPasswordAuthStore) {
				storage.EXPECT().User(gomock.Any(), userID).Return(&dbtype.SessionUser{ID: userID, Username: "user"}, nil)
				storage.EXPECT().DeactivateUser(gomock.Any(), userID).Return(nil)
				storage.EXPECT().DestroyAllUserSessions(gomock.Any(), "user").Return(nil)
			},
			wantErr: false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			ctrl := gomock.NewController(t)

			storage := mock_sessionstorage.NewMockPasswordAuthStore(ctrl)
			p, err := NewPasswordAuth(storage, cookieKey)
			if err != nil {
				t.Fatalf("NewPasswordAuth() error=%v", err)
			}
			p.storage = storage

			if tt.prepare != nil {
				tt.prepare(storage)
			}

			err = p.deactivateSessionUser(tt.ctx, tt.userID)
			if (err != nil) != tt.wantErr {
				t.Errorf("PasswordAuth.DeactivateSessionUser() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func TestPasswordAuth_DeleteSessionUser(t *testing.T) {
	t.Parallel()

	userID := ccc.Must(ccc.NewUUID())
	otherUserID := ccc.Must(ccc.NewUUID())

	tests := []struct {
		name    string
		userID  ccc.UUID
		ctx     context.Context
		prepare func(storage *mock_sessionstorage.MockPasswordAuthStore)
		wantErr bool
	}{
		{
			name:   "fails on self delete",
			userID: userID,
			ctx:    context.WithValue(context.Background(), sessioninfo.CtxUserInfo, &sessioninfo.UserInfo{ID: userID}),
			prepare: func(storage *mock_sessionstorage.MockPasswordAuthStore) {
				storage.EXPECT().User(gomock.Any(), userID).Return(&dbtype.SessionUser{ID: userID}, nil)
			},
			wantErr: true,
		},
		{
			name:   "fails on storage error",
			userID: userID,
			ctx:    context.WithValue(context.Background(), sessioninfo.CtxUserInfo, &sessioninfo.UserInfo{ID: otherUserID}),
			prepare: func(storage *mock_sessionstorage.MockPasswordAuthStore) {
				storage.EXPECT().User(gomock.Any(), userID).Return(nil, errors.New("db error"))
			},
			wantErr: true,
		},
		{
			name:   "fails on delete user",
			userID: userID,
			ctx:    context.WithValue(context.Background(), sessioninfo.CtxUserInfo, &sessioninfo.UserInfo{ID: otherUserID}),
			prepare: func(storage *mock_sessionstorage.MockPasswordAuthStore) {
				storage.EXPECT().User(gomock.Any(), userID).Return(&dbtype.SessionUser{ID: userID, Username: "user"}, nil)
				storage.EXPECT().DeleteUser(gomock.Any(), userID).Return(errors.New("db error"))
			},
			wantErr: true,
		},
		{
			name:   "fails on destroy all sessions",
			userID: userID,
			ctx:    context.WithValue(context.Background(), sessioninfo.CtxUserInfo, &sessioninfo.UserInfo{ID: otherUserID}),
			prepare: func(storage *mock_sessionstorage.MockPasswordAuthStore) {
				storage.EXPECT().User(gomock.Any(), userID).Return(&dbtype.SessionUser{ID: userID, Username: "user"}, nil)
				storage.EXPECT().DeleteUser(gomock.Any(), userID).Return(nil)
				storage.EXPECT().DestroyAllUserSessions(gomock.Any(), "user").Return(errors.New("db error"))
			},
			wantErr: true,
		},
		{
			name:   "success",
			userID: userID,
			ctx:    context.WithValue(context.Background(), sessioninfo.CtxUserInfo, &sessioninfo.UserInfo{ID: otherUserID}),
			prepare: func(storage *mock_sessionstorage.MockPasswordAuthStore) {
				storage.EXPECT().User(gomock.Any(), userID).Return(&dbtype.SessionUser{ID: userID, Username: "user"}, nil)
				storage.EXPECT().DeleteUser(gomock.Any(), userID).Return(nil)
				storage.EXPECT().DestroyAllUserSessions(gomock.Any(), "user").Return(nil)
			},
			wantErr: false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			ctrl := gomock.NewController(t)

			storage := mock_sessionstorage.NewMockPasswordAuthStore(ctrl)
			p, err := NewPasswordAuth(storage, cookieKey)
			if err != nil {
				t.Fatalf("NewPasswordAuth() error=%v", err)
			}
			p.storage = storage

			if tt.prepare != nil {
				tt.prepare(storage)
			}

			err = p.deleteSessionUser(tt.ctx, tt.userID)
			if (err != nil) != tt.wantErr {
				t.Errorf("PasswordAuth.DeleteSessionUser() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}
