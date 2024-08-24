package session

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/cccteam/access"
	"github.com/cccteam/ccc"
	"github.com/cccteam/httpio"
	"github.com/cccteam/session/mock/mock_session"
	"github.com/cccteam/session/sessiontypes"
	"github.com/go-chi/chi/v5"
	"github.com/go-playground/errors/v5"
	"github.com/google/go-cmp/cmp"
	gomock "go.uber.org/mock/gomock"
)

func TestApp_Authenticated(t *testing.T) {
	t.Parallel()
	type response struct {
		Authenticated bool                                  `json:"authenticated"`
		Username      string                                `json:"username"`
		Permissions   map[access.Domain][]access.Permission `json:"permissions"`
	}
	tests := []struct {
		name           string
		expectedStatus int
		prepare        func(*mock_session.MockStorageManager)
		cookieError    bool
		want           *response
	}{
		{
			name: "success but unauthorized",
			prepare: func(storage *mock_session.MockStorageManager) {
				storage.EXPECT().Session(gomock.Any(), gomock.Any()).Return(nil, errors.New("invalid session")).Times(1)
			},
			expectedStatus: http.StatusOK,
			want:           &response{},
		},
		{
			name: "fails to check the user's session",
			prepare: func(storage *mock_session.MockStorageManager) {
				storage.EXPECT().Session(gomock.Any(), gomock.Any()).Return(&sessiontypes.SessionInfo{UpdatedAt: time.Now()}, nil).Times(1)
				storage.EXPECT().UpdateSessionActivity(gomock.Any(), gomock.Any()).Return(errors.New("failed to update session activity")).Times(1)
			},
			expectedStatus: http.StatusInternalServerError,
		},
		{
			name: "successful authentication",
			prepare: func(storage *mock_session.MockStorageManager) {
				storage.EXPECT().Session(gomock.Any(), gomock.Any()).Return(&sessiontypes.SessionInfo{
					Username:  "test Username",
					UpdatedAt: time.Now(),
					Permissions: map[access.Domain][]access.Permission{
						access.GlobalDomain:         {access.Permission("ListRoleUsers"), access.Permission("ListRolePermissions")},
						access.Domain("testDomain"): {access.Permission("AddRole"), access.Permission("DeleteRole")},
					},
				}, nil).Times(1)
				storage.EXPECT().UpdateSessionActivity(gomock.Any(), gomock.Any()).Return(nil).Times(1)
			},
			expectedStatus: http.StatusOK,
			want: &response{
				Authenticated: true,
				Username:      "test Username",
				Permissions: map[access.Domain][]access.Permission{
					access.GlobalDomain:         {access.Permission("ListRoleUsers"), access.Permission("ListRolePermissions")},
					access.Domain("testDomain"): {access.Permission("AddRole"), access.Permission("DeleteRole")},
				},
			},
		},
	}
	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			storage := mock_session.NewMockStorageManager(gomock.NewController(t))

			session := &session{
				sessionTimeout: 15 * time.Minute,
				storage:        storage,
				handle: func(handler func(w http.ResponseWriter, r *http.Request) error) http.HandlerFunc {
					return func(w http.ResponseWriter, r *http.Request) {
						if err := handler(w, r); err != nil {
							_ = err
						}
					}
				},
			}
			tt.prepare(storage)

			recorder := httptest.NewRecorder()
			r := chi.NewRouter()
			req := httptest.NewRequest(http.MethodGet, "/testPath", http.NoBody)
			req = req.WithContext(context.WithValue(context.Background(), ctxSessionExpirationDuration, time.Minute))

			r.Route("/", func(r chi.Router) {
				r.Get("/testPath", session.Authenticated())
			})
			r.ServeHTTP(recorder, req)
			if recorder.Code != tt.expectedStatus {
				t.Errorf("App.Authenticated() = %v, want %v", recorder.Code, tt.expectedStatus)
			}
			if tt.expectedStatus != http.StatusOK {
				return
			}
			result := &response{}
			if err := json.Unmarshal(recorder.Body.Bytes(), result); err != nil {
				t.Error("Error unmarshalling the response body")
			}
			if diff := cmp.Diff(result, tt.want); diff != "" {
				t.Errorf("Response body not as expected: %v", diff)
			}
		})
	}
}

func TestApp_Logout(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name           string
		prepare        func(*mock_session.MockStorageManager)
		expectedStatus int
		wantSessionID  ccc.UUID
	}{
		{
			name: "success logging out, fails to destroy session in db",
			prepare: func(u *mock_session.MockStorageManager) {
				u.EXPECT().DestroySession(gomock.Any(), ccc.UUIDMustParse("bbee630a-0255-4dee-9283-8b7277bad0b0")).Return(httpio.NewNotFoundMessagef("session not found")).Times(1)
			},
			expectedStatus: http.StatusNotFound,
			wantSessionID:  ccc.UUIDMustParse("bbee630a-0255-4dee-9283-8b7277bad0b0"),
		},
		{
			name: "success logging out",
			prepare: func(u *mock_session.MockStorageManager) {
				u.EXPECT().DestroySession(gomock.Any(), gomock.Any()).Return(nil).Times(1)
			},
			expectedStatus: http.StatusOK,
		},
	}
	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			storage := mock_session.NewMockStorageManager(gomock.NewController(t))
			tt.prepare(storage)
			a := &session{
				sessionTimeout: 15 * time.Minute,
				storage:        storage,
				handle: func(handler func(w http.ResponseWriter, r *http.Request) error) http.HandlerFunc {
					return func(w http.ResponseWriter, r *http.Request) {
						if err := handler(w, r); err != nil {
							_ = err
						}
					}
				},
			}

			recorder := httptest.NewRecorder()
			r := chi.NewRouter()
			req := httptest.NewRequest(http.MethodDelete, "/testPath", http.NoBody)
			req = req.WithContext(context.WithValue(context.Background(), ctxSessionExpirationDuration, time.Minute))
			req = req.WithContext(context.WithValue(req.Context(), ctxSessionID, tt.wantSessionID))

			r.Route("/", func(r chi.Router) {
				r.Delete("/testPath", a.Logout())
			})
			r.ServeHTTP(recorder, req)
			if recorder.Code != tt.expectedStatus {
				t.Errorf("App.Logout() = %v, want %v", recorder.Code, tt.expectedStatus)
			}
			if tt.expectedStatus != http.StatusOK {
				return
			}
		})
	}
}

func Test_sessionExpirationFromRequest(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name string
		r    *http.Request
		want time.Duration
	}{
		{
			name: "does not find session expiration in request",
			r:    httptest.NewRequest(http.MethodGet, "/testPath", http.NoBody),
		},
		{
			name: "gets session expiration from request",
			r: func() *http.Request {
				req := httptest.NewRequest(http.MethodGet, "/testPath", http.NoBody)
				req = req.WithContext(context.WithValue(context.Background(), ctxSessionExpirationDuration, time.Minute))
				return req
			}(),
			want: time.Minute,
		},
	}
	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			if got := sessionExpirationFromRequest(tt.r); got != tt.want {
				t.Errorf("sessionExpirationFromRequest() = %v, want %v", got, tt.want)
			}
		})
	}
}