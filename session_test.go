package session

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"reflect"
	"testing"
	"time"

	"github.com/cccteam/ccc"
	"github.com/cccteam/ccc/accesstypes"
	"github.com/cccteam/httpio"
	"github.com/cccteam/session/mock/mock_session"
	"github.com/cccteam/session/sessioninfo"
	"github.com/go-chi/chi/v5"
	"github.com/go-playground/errors/v5"
	"github.com/google/go-cmp/cmp"
	"github.com/gorilla/securecookie"
	"go.uber.org/mock/gomock"
)

// mockRequestWithSession Mocks Request with Session Cookie
func mockRequestWithSession(ctx context.Context, t *testing.T, method string, sc *securecookie.SecureCookie, sessionID string) *http.Request {
	// Create request using cookie set in Response Recorder
	r := &http.Request{
		Method: method,
		URL:    &url.URL{},
	}

	r = r.WithContext(ctx)

	if sc != nil {
		// Use newAuthCookie() to generate a valid cookie
		w := httptest.NewRecorder()

		var id ccc.UUID
		var err error
		if sessionID != "" {
			id, err = ccc.UUIDFromString(sessionID)
			if err != nil {
				t.Fatalf("uuid.FromString() = %v", err)
			}
		} else {
			id, err = ccc.NewUUID()
			if err != nil {
				t.Fatalf("uuid.NewV4() = %v", err)
			}
		}

		a := &session{cookieManager: &cookieClient{secureCookie: sc}}
		if _, err := a.newAuthCookie(w, false, id); err != nil {
			t.Fatalf("newAuthCookie() = %v", err)
		}

		r.Header = http.Header{
			"Cookie": w.Header().Values("Set-Cookie"),
		}
	} else {
		// Store sessionID in context
		id, err := ccc.UUIDFromString(sessionID)
		if err != nil {
			t.Fatalf("uuid.FromString() = %v", err)
		}
		r = r.WithContext(context.WithValue(r.Context(), ctxSessionID, id))
	}

	return r
}

func TestAppStartSession(t *testing.T) {
	t.Parallel()

	type test struct {
		name           string
		req            *http.Request
		prepare        func(*MockcookieManager, *test)
		wantSessionID  ccc.UUID
		expectedStatus int
	}
	tests := []test{
		{
			name: "success starting new session (invalid session in pre-existing cookie)",
			req:  mockRequestWithSession(context.Background(), t, http.MethodGet, securecookie.New(securecookie.GenerateRandomKey(32), nil), ""),
			prepare: func(c *MockcookieManager, tt *test) {
				c.EXPECT().readAuthCookie(gomock.Any()).Return(map[scKey]string{
					scSessionID:      "92922509-82d2-4ba-853a-d73b8926a55f",
					scSameSiteStrict: "true",
				}, true)
				c.EXPECT().newAuthCookie(gomock.Any(), gomock.Any(), gomock.Any()).
					Do(func(_ http.ResponseWriter, _ bool, sessionID ccc.UUID) {
						tt.wantSessionID = sessionID
					}).
					Return(map[scKey]string{
						scSessionID:      "92922509-82d2-4ba1-853a-d73b8926a55f",
						scSameSiteStrict: "true",
					}, nil)
			},
			expectedStatus: http.StatusOK,
		},
		{
			name: "success starting new session (no pre-existing cookie)",
			req:  mockRequestWithSession(context.Background(), t, http.MethodGet, securecookie.New(securecookie.GenerateRandomKey(32), nil), ""),
			prepare: func(c *MockcookieManager, tt *test) {
				c.EXPECT().readAuthCookie(gomock.Any()).Return(nil, false)
				c.EXPECT().newAuthCookie(gomock.Any(), gomock.Any(), gomock.Any()).
					Do(func(_ http.ResponseWriter, _ bool, sessionID ccc.UUID) {
						tt.wantSessionID = sessionID
					}).
					Return(map[scKey]string{
						scSessionID:      "92922509-82d2-4ba1-853a-d73b8926a55f",
						scSameSiteStrict: "true",
					}, nil)
			},
			expectedStatus: http.StatusOK,
		},
		{
			name: "success with existing cookie upgraded",
			req:  mockRequestWithSession(context.Background(), t, http.MethodGet, securecookie.New(securecookie.GenerateRandomKey(32), nil), "92922509-82d2-4bc7-853a-d73b8926a55f"),
			prepare: func(c *MockcookieManager, _ *test) {
				c.EXPECT().readAuthCookie(gomock.Any()).Return(map[scKey]string{
					scSessionID: "92922509-82d2-4bc7-853a-d73b8926a55f",
				}, true)
				c.EXPECT().writeAuthCookie(gomock.Any(), true, map[scKey]string{
					scSessionID: "92922509-82d2-4bc7-853a-d73b8926a55f",
				}).Return(nil)
			},
			wantSessionID:  ccc.Must(ccc.UUIDFromString("92922509-82d2-4bc7-853a-d73b8926a55f")),
			expectedStatus: http.StatusOK,
		},
		{
			name: "success without upgrading existing cookie",
			req:  mockRequestWithSession(context.Background(), t, http.MethodGet, securecookie.New(securecookie.GenerateRandomKey(32), nil), "92922509-82d2-4bc7-853a-d73b8926a55f"),
			prepare: func(c *MockcookieManager, _ *test) {
				c.EXPECT().readAuthCookie(gomock.Any()).Return(map[scKey]string{
					scSessionID:      "92922509-82d2-4bc7-853a-d73b8926a55f",
					scSameSiteStrict: "true",
				}, true)
			},
			wantSessionID:  ccc.Must(ccc.UUIDFromString("92922509-82d2-4bc7-853a-d73b8926a55f")),
			expectedStatus: http.StatusOK,
		},
		{
			name: "fails to upgrade existing cookie",
			req:  mockRequestWithSession(context.Background(), t, http.MethodGet, securecookie.New(securecookie.GenerateRandomKey(32), nil), "92922509-82d2-4bc7-853a-d73b8926a55f"),
			prepare: func(c *MockcookieManager, _ *test) {
				c.EXPECT().readAuthCookie(gomock.Any()).Return(map[scKey]string{
					scSessionID:      "92922509-82d2-4bc7-853a-d73b8926a55f",
					scSameSiteStrict: "false",
				}, true)
				c.EXPECT().writeAuthCookie(gomock.Any(), true, map[scKey]string{
					scSessionID:      "92922509-82d2-4bc7-853a-d73b8926a55f",
					scSameSiteStrict: "false",
				}).Return(errors.New("error writing cookie"))
			},
			expectedStatus: http.StatusInternalServerError,
		},
		{
			name: "fail at newAuthCookie()",
			req:  &http.Request{URL: &url.URL{}},
			prepare: func(c *MockcookieManager, _ *test) {
				c.EXPECT().readAuthCookie(gomock.Any()).Return(nil, false)
				c.EXPECT().newAuthCookie(gomock.Any(), gomock.Any(), gomock.Any()).Return(nil, errors.New("error creating cookie"))
			},
			expectedStatus: http.StatusInternalServerError,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			c := NewMockcookieManager(gomock.NewController(t))
			a := &session{
				sessionTimeout: time.Second * 5,
				cookieManager:  c,
				handle: func(handler func(w http.ResponseWriter, r *http.Request) error) http.HandlerFunc {
					return func(w http.ResponseWriter, r *http.Request) {
						if err := handler(w, r); err != nil {
							_ = err
						}
					}
				},
			}
			if tt.prepare != nil {
				tt.prepare(c, &tt)
			}

			req := tt.req
			req.Method = http.MethodGet
			req.URL.Path = "/testPath"
			w := httptest.NewRecorder()
			r := chi.NewRouter()
			r.Route("/testPath", func(r chi.Router) {
				r.Use(a.StartSession) // Routing the request through the middleware that is being tested here
				r.Get("/", func(_ http.ResponseWriter, rq *http.Request) {
					req = rq // Request after middleware is applied
				})
			})
			r.ServeHTTP(w, req)

			if w.Code != tt.expectedStatus {
				t.Fatalf("Expected status code %d, got %d", tt.expectedStatus, w.Code)
			}

			got := sessionIDFromRequest(req)
			if diff := cmp.Diff(tt.wantSessionID, got); diff != "" {
				t.Errorf("sessionIDFromRequest mismatch (-want +got):\n%s", diff)
			}
		})
	}
}

func TestAppValidateSession(t *testing.T) {
	t.Parallel()

	type fields struct {
		sessionTimeout time.Duration
	}
	type args struct {
		r *http.Request
	}
	tests := []struct {
		name       string
		fields     fields
		args       args
		prepare    func(storageManager *mock_session.MockstorageManager)
		wantStatus int
	}{
		{
			name: "success GET",
			fields: fields{
				sessionTimeout: time.Minute,
			},
			args: args{
				r: mockRequestWithSession(context.Background(), t, http.MethodGet, nil, "de6e1a12-2d4d-4c4d-aaf1-d82cb9a9eff5"),
			},
			prepare: func(storageManager *mock_session.MockstorageManager) {
				storageManager.EXPECT().Session(gomock.Any(), ccc.Must(ccc.UUIDFromString("de6e1a12-2d4d-4c4d-aaf1-d82cb9a9eff5"))).Return(&sessioninfo.SessionInfo{ID: ccc.Must(ccc.UUIDFromString("de6e1a12-2d4d-4c4d-aaf1-d82cb9a9eff5")), Username: "specialUser", UpdatedAt: time.Now()}, nil)
				storageManager.EXPECT().UpdateSessionActivity(gomock.Any(), ccc.Must(ccc.UUIDFromString("de6e1a12-2d4d-4c4d-aaf1-d82cb9a9eff5"))).Return(nil)
			},
			wantStatus: http.StatusOK,
		},
		{
			name: "success POST",
			fields: fields{
				sessionTimeout: time.Minute,
			},
			args: args{
				r: mockRequestWithSession(context.Background(), t, http.MethodPost, nil, "de6e1a12-2d4d-4c4d-aaf1-d82cb9a9eff5"),
			},
			prepare: func(storageManager *mock_session.MockstorageManager) {
				storageManager.EXPECT().Session(gomock.Any(), ccc.Must(ccc.UUIDFromString("de6e1a12-2d4d-4c4d-aaf1-d82cb9a9eff5"))).Return(&sessioninfo.SessionInfo{ID: ccc.Must(ccc.UUIDFromString("de6e1a12-2d4d-4c4d-aaf1-d82cb9a9eff5")), Username: "specialUser", UpdatedAt: time.Now()}, nil)
				storageManager.EXPECT().UpdateSessionActivity(gomock.Any(), ccc.Must(ccc.UUIDFromString("de6e1a12-2d4d-4c4d-aaf1-d82cb9a9eff5"))).Return(nil)
			},
			wantStatus: http.StatusOK,
		},
		{
			name: "checkSession() returns forbidden error",
			fields: fields{
				sessionTimeout: time.Minute,
			},
			args: args{
				r: mockRequestWithSession(context.Background(), t, http.MethodGet, nil, "de6e1a12-2d4d-4c4d-aaf1-d82cb9a9eff5"),
			},
			prepare: func(storageManager *mock_session.MockstorageManager) {
				storageManager.EXPECT().Session(gomock.Any(), ccc.Must(ccc.UUIDFromString("de6e1a12-2d4d-4c4d-aaf1-d82cb9a9eff5"))).Return(nil, errors.New("big fat error"))
			},
			wantStatus: http.StatusUnauthorized,
		},
		{
			name: "checkSession() returns general error",
			fields: fields{
				sessionTimeout: time.Minute,
			},
			args: args{
				r: mockRequestWithSession(context.Background(), t, http.MethodGet, nil, "de6e1a12-2d4d-4c4d-aaf1-d82cb9a9eff5"),
			},
			prepare: func(storageManager *mock_session.MockstorageManager) {
				storageManager.EXPECT().Session(gomock.Any(), ccc.Must(ccc.UUIDFromString("de6e1a12-2d4d-4c4d-aaf1-d82cb9a9eff5"))).Return(&sessioninfo.SessionInfo{ID: ccc.Must(ccc.UUIDFromString("de6e1a12-2d4d-4c4d-aaf1-d82cb9a9eff5")), Username: "specialUser", UpdatedAt: time.Now()}, nil)
				storageManager.EXPECT().UpdateSessionActivity(gomock.Any(), ccc.Must(ccc.UUIDFromString("de6e1a12-2d4d-4c4d-aaf1-d82cb9a9eff5"))).Return(errors.New("big fat error"))
			},
			wantStatus: http.StatusInternalServerError,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			ctrl := gomock.NewController(t)
			storageManager := mock_session.NewMockstorageManager(ctrl)

			tt.prepare(storageManager)

			a := &session{
				sessionTimeout: tt.fields.sessionTimeout,
				handle: func(handler func(w http.ResponseWriter, r *http.Request) error) http.HandlerFunc {
					return func(w http.ResponseWriter, r *http.Request) {
						if err := handler(w, r); err != nil {
							_ = err
						}
					}
				},
				storage: storageManager,
			}
			w := httptest.NewRecorder()
			a.ValidateSession(
				http.HandlerFunc(func(_ http.ResponseWriter, _ *http.Request) {}),
			).ServeHTTP(w, tt.args.r)
			if got := w.Code; got != tt.wantStatus {
				t.Errorf("App.ValidateSession() = %v, wantStatus %v", got, tt.wantStatus)
			}
		})
	}
}

func TestApp_checkSession(t *testing.T) {
	t.Parallel()

	type fields struct {
		sessionTimeout time.Duration
	}
	type args struct {
		r *http.Request
	}
	type test struct {
		name             string
		fields           fields
		args             args
		prepare          func(storageManager *mock_session.MockstorageManager, tt test)
		wantUnauthorized bool
		want             *sessioninfo.SessionInfo
		wantMsg          string
		wantErr          bool
	}
	tests := []test{
		{
			name: "success",
			fields: fields{
				sessionTimeout: time.Minute,
			},
			args: args{
				r: mockRequestWithSession(context.Background(), t, http.MethodGet, nil, "92922509-82d2-4bc7-853a-d73b8926a55f"),
			},
			want: &sessioninfo.SessionInfo{ID: ccc.Must(ccc.UUIDFromString("92922509-82d2-4bc7-853a-d73b8926a55f")), Username: "specialUser", UpdatedAt: time.Now()},
			prepare: func(storageManager *mock_session.MockstorageManager, tt test) {
				storageManager.EXPECT().Session(gomock.Any(), ccc.Must(ccc.UUIDFromString("92922509-82d2-4bc7-853a-d73b8926a55f"))).Return(tt.want, nil)
				storageManager.EXPECT().UpdateSessionActivity(gomock.Any(), ccc.Must(ccc.UUIDFromString("92922509-82d2-4bc7-853a-d73b8926a55f"))).Return(nil)
			},
		},
		{
			name: "fail on UpdateSessionActivity()",
			fields: fields{
				sessionTimeout: time.Minute,
			},
			args: args{
				r: mockRequestWithSession(context.Background(), t, http.MethodGet, nil, "92922509-82d2-4bc7-853a-d73b8926a55f"),
			},
			want: &sessioninfo.SessionInfo{ID: ccc.Must(ccc.UUIDFromString("92922509-82d2-4bc7-853a-d73b8926a55f")), Username: "specialUser", UpdatedAt: time.Now()},
			prepare: func(storageManager *mock_session.MockstorageManager, tt test) {
				storageManager.EXPECT().Session(gomock.Any(), ccc.Must(ccc.UUIDFromString("92922509-82d2-4bc7-853a-d73b8926a55f"))).Return(tt.want, nil)
				storageManager.EXPECT().UpdateSessionActivity(gomock.Any(), ccc.Must(ccc.UUIDFromString("92922509-82d2-4bc7-853a-d73b8926a55f"))).Return(errors.New("big fat error"))
			},
			wantErr: true,
		},
		{
			name: "fail on session expired in database",
			fields: fields{
				sessionTimeout: time.Minute,
			},
			args: args{
				r: mockRequestWithSession(context.Background(), t, http.MethodGet, nil, "92922509-82d2-4bc7-853a-d73b8926a55f"),
			},
			want: &sessioninfo.SessionInfo{ID: ccc.Must(ccc.UUIDFromString("92922509-82d2-4bc7-853a-d73b8926a55f")), Username: "specialUser", UpdatedAt: time.Now(), Expired: true},
			prepare: func(storageManager *mock_session.MockstorageManager, tt test) {
				storageManager.EXPECT().Session(gomock.Any(), ccc.Must(ccc.UUIDFromString("92922509-82d2-4bc7-853a-d73b8926a55f"))).Return(tt.want, nil)
			},
			wantUnauthorized: true,
			wantMsg:          "session expired",
			wantErr:          true,
		},
		{
			name: "fail on session expired from inactivity",
			fields: fields{
				sessionTimeout: time.Minute,
			},
			args: args{
				r: mockRequestWithSession(context.Background(), t, http.MethodGet, nil, "de6e1a12-2d4d-4c4d-aaf1-d82cb9a9eff5"),
			},
			want: &sessioninfo.SessionInfo{ID: ccc.Must(ccc.UUIDFromString("de6e1a12-2d4d-4c4d-aaf1-d82cb9a9eff5")), Username: "specialUser", UpdatedAt: time.Now().Add(-time.Hour)},
			prepare: func(storageManager *mock_session.MockstorageManager, tt test) {
				storageManager.EXPECT().Session(gomock.Any(), ccc.Must(ccc.UUIDFromString("de6e1a12-2d4d-4c4d-aaf1-d82cb9a9eff5"))).Return(tt.want, nil)
			},
			wantUnauthorized: true,
			wantMsg:          "session expired",
			wantErr:          true,
		},
		{
			name: "failed on session",
			args: args{
				r: mockRequestWithSession(context.Background(), t, http.MethodGet, nil, "de6e1a12-2d4d-4c4d-aaf1-d82cb9a9eff5"),
			},
			prepare: func(storageManager *mock_session.MockstorageManager, _ test) {
				storageManager.EXPECT().Session(gomock.Any(), ccc.Must(ccc.UUIDFromString("de6e1a12-2d4d-4c4d-aaf1-d82cb9a9eff5"))).Return(nil, errors.New("big fat error"))
			},
			wantUnauthorized: true,
			wantMsg:          "invalid session",
			wantErr:          true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			ctrl := gomock.NewController(t)
			storageManager := mock_session.NewMockstorageManager(ctrl)

			tt.prepare(storageManager, tt)

			a := &session{
				sessionTimeout: tt.fields.sessionTimeout,
				storage:        storageManager,
			}

			gotReq, err := a.checkSession(tt.args.r)
			if (err != nil) != tt.wantErr {
				t.Fatalf("App.checkSession() error = %v, wantErr %v", err, tt.wantErr)
			}
			if err != nil && tt.wantUnauthorized != httpio.HasUnauthorized(err) {
				t.Errorf("App.checkSession() error did not have the type 'unauthorized'")
			}

			if tt.wantErr {
				cerr := &httpio.ClientMessage{}
				errors.As(err, &cerr)
				if cerr.Message() != tt.wantMsg {
					t.Errorf("App.checkSession() error Message = %v, want %v", cerr.Message(), tt.wantMsg)
				}

				return
			}
			if got := sessioninfo.FromRequest(gotReq); !reflect.DeepEqual(got, tt.want) {
				t.Errorf("sessInfo = %v, wantSessInfo %v", got, tt.want)
			}
		})
	}
}

func Test_validSessionID(t *testing.T) {
	t.Parallel()

	type args struct {
		sessionID string
	}
	tests := []struct {
		name     string
		args     args
		wantUUID ccc.UUID
		want     bool
	}{
		{
			name: "success",
			args: args{
				sessionID: "ea4f6e96-1955-47a3-abb0-ea4f6e962bc6",
			},
			wantUUID: ccc.Must(ccc.UUIDFromString("ea4f6e96-1955-47a3-abb0-ea4f6e962bc6")),
			want:     true,
		},
		{
			name: "failure",
			args: args{
				sessionID: "invalid euid",
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			gotUUID, got := validSessionID(tt.args.sessionID)
			if got != tt.want {
				t.Errorf("validSessionID() = %v, want %v", got, tt.want)
			}
			if gotUUID != tt.wantUUID {
				t.Errorf("validSessionID() = %v, want %v", gotUUID, tt.wantUUID)
			}
		})
	}
}

func TestApp_Authenticated(t *testing.T) {
	t.Parallel()
	type response struct {
		Authenticated bool                                 `json:"authenticated"`
		Username      string                               `json:"username"`
		Permissions   accesstypes.UserPermissionCollection `json:"permissions"`
	}
	tests := []struct {
		name           string
		expectedStatus int
		prepare        func(*mock_session.MockstorageManager)
		cookieError    bool
		want           *response
	}{
		{
			name: "success but unauthorized",
			prepare: func(storage *mock_session.MockstorageManager) {
				storage.EXPECT().Session(gomock.Any(), gomock.Any()).Return(nil, errors.New("invalid session")).Times(1)
			},
			expectedStatus: http.StatusOK,
			want:           &response{},
		},
		{
			name: "fails to check the user's session",
			prepare: func(storage *mock_session.MockstorageManager) {
				storage.EXPECT().Session(gomock.Any(), gomock.Any()).Return(&sessioninfo.SessionInfo{UpdatedAt: time.Now()}, nil).Times(1)
				storage.EXPECT().UpdateSessionActivity(gomock.Any(), gomock.Any()).Return(errors.New("failed to update session activity")).Times(1)
			},
			expectedStatus: http.StatusInternalServerError,
		},
		{
			name: "successful authentication",
			prepare: func(storage *mock_session.MockstorageManager) {
				storage.EXPECT().Session(gomock.Any(), gomock.Any()).Return(&sessioninfo.SessionInfo{
					Username:  "test Username",
					UpdatedAt: time.Now(),
				}, nil).Times(1)
				storage.EXPECT().UpdateSessionActivity(gomock.Any(), gomock.Any()).Return(nil).Times(1)
			},
			expectedStatus: http.StatusOK,
			want: &response{
				Authenticated: true,
				Username:      "test Username",
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			ctrl := gomock.NewController(t)
			storage := mock_session.NewMockstorageManager(ctrl)

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
		prepare        func(*mock_session.MockstorageManager)
		expectedStatus int
		wantSessionID  ccc.UUID
	}{
		{
			name: "success logging out, fails to destroy session in db",
			prepare: func(u *mock_session.MockstorageManager) {
				u.EXPECT().DestroySession(gomock.Any(), ccc.Must(ccc.UUIDFromString("bbee630a-0255-4dee-9283-8b7277bad0b0"))).Return(httpio.NewNotFoundMessagef("session not found")).Times(1)
			},
			expectedStatus: http.StatusNotFound,
			wantSessionID:  ccc.Must(ccc.UUIDFromString("bbee630a-0255-4dee-9283-8b7277bad0b0")),
		},
		{
			name: "success logging out",
			prepare: func(u *mock_session.MockstorageManager) {
				u.EXPECT().DestroySession(gomock.Any(), gomock.Any()).Return(nil).Times(1)
			},
			expectedStatus: http.StatusOK,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			storage := mock_session.NewMockstorageManager(gomock.NewController(t))
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
