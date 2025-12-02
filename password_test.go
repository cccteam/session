package session

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
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
	"github.com/gorilla/securecookie"
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
		prepare        func(storage *mock_sessionstorage.MockPasswordStore, cookieHandler *mock_cookie.MockCookieHandler)
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
			prepare: func(storage *mock_sessionstorage.MockPasswordStore, _ *mock_cookie.MockCookieHandler) {
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
			prepare: func(storage *mock_sessionstorage.MockPasswordStore, _ *mock_cookie.MockCookieHandler) {
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
			prepare: func(storage *mock_sessionstorage.MockPasswordStore, _ *mock_cookie.MockCookieHandler) {
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
			prepare: func(storage *mock_sessionstorage.MockPasswordStore, _ *mock_cookie.MockCookieHandler) {
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
			prepare: func(storage *mock_sessionstorage.MockPasswordStore, cookieHandler *mock_cookie.MockCookieHandler) {
				storage.EXPECT().UserByUserName(gomock.Any(), "user").Return(&dbtype.SessionUser{
					Username:     "user",
					PasswordHash: validHash,
				}, nil)
				sessionID := ccc.Must(ccc.NewUUID())
				storage.EXPECT().NewSession(gomock.Any(), "user").Return(sessionID, nil)
				cookieHandler.EXPECT().NewAuthCookie(gomock.Any(), false, sessionID).Return(nil, errors.New("new auth cookie failed"))
			},
			wantStatusCode: http.StatusInternalServerError,
		},
		{
			name: "success",
			reqBody: map[string]string{
				"username": "user",
				"password": "password",
			},
			prepare: func(storage *mock_sessionstorage.MockPasswordStore, cookieHandler *mock_cookie.MockCookieHandler) {
				storage.EXPECT().UserByUserName(gomock.Any(), "user").Return(&dbtype.SessionUser{
					Username:     "user",
					PasswordHash: validHash,
				}, nil)
				sessionID := ccc.Must(ccc.NewUUID())
				storage.EXPECT().NewSession(gomock.Any(), "user").Return(sessionID, nil)
				cookieHandler.EXPECT().NewAuthCookie(gomock.Any(), false, sessionID).Return(map[types.SCKey]string{}, nil)
				cookieHandler.EXPECT().SetXSRFTokenCookie(gomock.Any(), gomock.Any(), sessionID, types.XSRFCookieLife)
			},
			wantStatusCode: http.StatusOK,
		},
		{
			name: "success with password hash upgrade",
			reqBody: map[string]string{
				"username": "user",
				"password": "password",
			},
			prepare: func(storage *mock_sessionstorage.MockPasswordStore, cookieHandler *mock_cookie.MockCookieHandler) {
				userID := ccc.Must(ccc.NewUUID())
				storage.EXPECT().UserByUserName(gomock.Any(), "user").Return(&dbtype.SessionUser{
					ID:           userID,
					Username:     "user",
					PasswordHash: oldHash,
				}, nil)
				storage.EXPECT().UpdateUserPasswordHash(gomock.Any(), userID, gomock.Any()).Return(nil)
				sessionID := ccc.Must(ccc.NewUUID())
				storage.EXPECT().NewSession(gomock.Any(), "user").Return(sessionID, nil)
				cookieHandler.EXPECT().NewAuthCookie(gomock.Any(), false, sessionID).Return(map[types.SCKey]string{}, nil)
				cookieHandler.EXPECT().SetXSRFTokenCookie(gomock.Any(), gomock.Any(), sessionID, types.XSRFCookieLife)
			},
			wantStatusCode: http.StatusOK,
		},
		{
			name: "password hash upgrade fails",
			reqBody: map[string]string{
				"username": "user",
				"password": "password",
			},
			prepare: func(storage *mock_sessionstorage.MockPasswordStore, cookieHandler *mock_cookie.MockCookieHandler) {
				userID := ccc.Must(ccc.NewUUID())
				storage.EXPECT().UserByUserName(gomock.Any(), "user").Return(&dbtype.SessionUser{
					ID:           userID,
					Username:     "user",
					PasswordHash: oldHash,
				}, nil)
				storage.EXPECT().UpdateUserPasswordHash(gomock.Any(), userID, gomock.Any()).Return(errors.New("db error"))
				sessionID := ccc.Must(ccc.NewUUID())
				storage.EXPECT().NewSession(gomock.Any(), "user").Return(sessionID, nil)
				cookieHandler.EXPECT().NewAuthCookie(gomock.Any(), false, sessionID).Return(map[types.SCKey]string{}, nil)
				cookieHandler.EXPECT().SetXSRFTokenCookie(gomock.Any(), gomock.Any(), sessionID, types.XSRFCookieLife)
			},
			wantStatusCode: http.StatusOK,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			ctrl := gomock.NewController(t)

			storage := mock_sessionstorage.NewMockPasswordStore(ctrl)
			cookieHandler := mock_cookie.NewMockCookieHandler(ctrl)

			p := NewPasswordAuth(storage, &securecookie.SecureCookie{})
			p.hasher = securehash.New(securehash.Argon2())
			p.CookieHandler = cookieHandler

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

	tests := []struct {
		name           string
		prepare        func(storage *mock_sessionstorage.MockPasswordStore)
		wantMessage    bool
		wantStatusCode int
	}{
		{
			name: "fails on check session",
			prepare: func(storage *mock_sessionstorage.MockPasswordStore) {
				storage.EXPECT().Session(gomock.Any(), gomock.Any()).Return(nil, errors.New("not found"))
			},
			wantStatusCode: http.StatusUnauthorized,
			wantMessage:    true,
		},
		{
			name: "fails on user not found",
			prepare: func(storage *mock_sessionstorage.MockPasswordStore) {
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
			prepare: func(storage *mock_sessionstorage.MockPasswordStore) {
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
			prepare: func(storage *mock_sessionstorage.MockPasswordStore) {
				storage.EXPECT().Session(gomock.Any(), gomock.Any()).Return(&sessioninfo.SessionInfo{
					ID:        ccc.Must(ccc.NewUUID()),
					Username:  "user",
					CreatedAt: time.Now(),
					UpdatedAt: time.Now(),
				}, nil)
				storage.EXPECT().UserByUserName(gomock.Any(), "user").Return(&dbtype.SessionUser{Username: "user"}, nil)
			},
			wantStatusCode: http.StatusOK,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			ctrl := gomock.NewController(t)

			storage := mock_sessionstorage.NewMockPasswordStore(ctrl)

			p := NewPasswordAuth(storage, &securecookie.SecureCookie{}, nil)
			p.storage = storage
			p.SessionTimeout = time.Minute

			if tt.prepare != nil {
				tt.prepare(storage)
			}

			nextHandler := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				w.WriteHeader(http.StatusOK)
			})
			handler := p.ValidateSession(nextHandler)
			req, err := createHTTPRequestWithUser(http.MethodGet, nil, nil, nil)
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
		prepare        func(storage *mock_sessionstorage.MockPasswordStore)
		sessionInfo    *sessioninfo.SessionInfo
		wantMessage    bool
		wantStatusCode int
		wantBody       string
	}{
		{
			name: "fails on check session",
			prepare: func(storage *mock_sessionstorage.MockPasswordStore) {
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
			prepare: func(storage *mock_sessionstorage.MockPasswordStore) {
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
			prepare: func(storage *mock_sessionstorage.MockPasswordStore) {
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
			prepare: func(storage *mock_sessionstorage.MockPasswordStore) {
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
			prepare: func(storage *mock_sessionstorage.MockPasswordStore) {
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

			storage := mock_sessionstorage.NewMockPasswordStore(ctrl)

			p := NewPasswordAuth(storage, &securecookie.SecureCookie{}, nil)
			p.storage = storage

			if tt.prepare != nil {
				tt.prepare(storage)
			}

			req, err := createHTTPRequestWithUser(http.MethodGet, nil, tt.sessionInfo, nil)
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
		prepare        func(storage *mock_sessionstorage.MockPasswordStore)
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
			prepare: func(storage *mock_sessionstorage.MockPasswordStore) {
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
			prepare: func(storage *mock_sessionstorage.MockPasswordStore) {
				storage.EXPECT().User(gomock.Any(), userID).Return(&dbtype.SessionUser{PasswordHash: validHash}, nil)
			},
			wantStatusCode: http.StatusUnauthorized,
			wantMessage:    true,
		},
		{
			name: "fails on storing new password hash",
			reqBody: map[string]string{
				"oldPassword": "oldpassword",
				"newPassword": "newpassword",
			},
			userInfo: &sessioninfo.UserInfo{ID: userID},
			prepare: func(storage *mock_sessionstorage.MockPasswordStore) {
				storage.EXPECT().User(gomock.Any(), userID).Return(&dbtype.SessionUser{
					ID:           userID,
					PasswordHash: validHash,
				}, nil)
				storage.EXPECT().UpdateUserPasswordHash(gomock.Any(), userID, gomock.Any()).Return(errors.New("db error"))
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
			prepare: func(storage *mock_sessionstorage.MockPasswordStore) {
				storage.EXPECT().User(gomock.Any(), userID).Return(&dbtype.SessionUser{
					ID:           userID,
					PasswordHash: validHash,
				}, nil)
				storage.EXPECT().UpdateUserPasswordHash(gomock.Any(), userID, gomock.Any()).Return(nil)
			},
			wantStatusCode: http.StatusOK,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			ctrl := gomock.NewController(t)

			storage := mock_sessionstorage.NewMockPasswordStore(ctrl)
			p := NewPasswordAuth(storage, &securecookie.SecureCookie{}, nil)
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

			req, err := createHTTPRequestWithUser(http.MethodPost, body, nil, tt.userInfo)
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
					t.Errorf("Password.Login() message = %v, wantMessage = %v", got, tt.wantMessage)
				}
			}
		})
	}
}

func createHTTPRequestWithUser(method string, body io.Reader, sessionInfo *sessioninfo.SessionInfo, userInfo *sessioninfo.UserInfo) (*http.Request, error) {
	ctx := context.Background()
	if sessionInfo != nil {
		ctx = context.WithValue(ctx, sessioninfo.CtxSessionInfo, sessionInfo)
	}
	if userInfo != nil {
		ctx = context.WithValue(ctx, sessioninfo.CtxUserInfo, userInfo)
	}
	req, err := http.NewRequestWithContext(ctx, method, "", body)
	if err != nil {
		return nil, errors.Wrap(err, "http.NewRequestWithContext()")
	}

	return req, nil
}
