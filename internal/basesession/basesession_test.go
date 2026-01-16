package basesession

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
	"github.com/cccteam/session/internal/cookie"
	"github.com/cccteam/session/mock/mock_cookie"
	"github.com/cccteam/session/sessioninfo"
	"github.com/cccteam/session/sessionstorage/mock/mock_sessionstorage"
	"github.com/go-chi/chi/v5"
	"github.com/go-playground/errors/v5"
	"github.com/google/go-cmp/cmp"
	"go.uber.org/mock/gomock"
)

const cookieKey = "Rsgb6WsDvBsMQ5IJr2WJjVLCPO+o9WW6SdVktdaaq9O0WFA0Hc/EmJeOwCGV6LIqG8ue3iSZ/lycpv8ZNKvWjWU42hZnlO15vYANZG89R1ncjmu4KStldFuP/r0RFhZa"

// mockRequestWithSession Mocks Request with Session Cookie
func mockRequestWithSession(ctx context.Context, t *testing.T, method, masterKeyBase64, sessionID string) *http.Request {
	// Create request using cookie set in Response Recorder
	r := &http.Request{
		Method: method,
		URL:    &url.URL{},
	}

	r = r.WithContext(ctx)

	switch {
	case masterKeyBase64 != "":
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

		cookieClient, err := cookie.NewCookieClient(masterKeyBase64)
		if err != nil {
			t.Fatalf("NewCookieClient() = %v", err)
		}
		a := &BaseSession{CookieHandler: cookieClient}
		if _, err := a.CookieHandler.NewAuthCookie(w, false, id); err != nil {
			t.Fatalf("newAuthCookie() = %v", err)
		}

		r.Header = http.Header{
			"Cookie": w.Header().Values("Set-Cookie"),
		}
	default:
		// Store sessionID in context
		id, err := ccc.UUIDFromString(sessionID)
		if err != nil {
			t.Fatalf("uuid.FromString() = %v", err)
		}
		r = r.WithContext(context.WithValue(r.Context(), sessioninfo.CTXSessionID, id))
	}

	return r
}

func TestBaseSessionStartSession(t *testing.T) {
	t.Parallel()

	type test struct {
		name           string
		req            *http.Request
		prepare        func(*mock_cookie.MockHandler, *test)
		wantSessionID  ccc.UUID
		expectedStatus int
	}
	tests := []test{
		{
			name: "success starting new session (invalid session in pre-existing cookie)",
			req:  mockRequestWithSession(context.Background(), t, http.MethodGet, cookieKey, ""),
			prepare: func(c *mock_cookie.MockHandler, tt *test) {
				c.EXPECT().ReadAuthCookie(gomock.Any()).Return(
					cookie.NewValues().
						Set(cookie.SessionID, "92922509-bad-session-id").
						Set(cookie.SameSiteStrict, "true"),
					true, nil)
				c.EXPECT().NewAuthCookie(gomock.Any(), gomock.Any(), gomock.Any()).
					Do(func(_ http.ResponseWriter, _ bool, sessionID ccc.UUID) {
						tt.wantSessionID = sessionID
					}).
					Return(
						cookie.NewValues().
							Set(cookie.SessionID, "92922509-82d2-4ba1-853a-d73b8926a55f").
							Set(cookie.SameSiteStrict, "true"),
						nil)
			},
			expectedStatus: http.StatusOK,
		},
		{
			name: "success starting new session (no pre-existing cookie)",
			req:  mockRequestWithSession(context.Background(), t, http.MethodGet, cookieKey, ""),
			prepare: func(c *mock_cookie.MockHandler, tt *test) {
				c.EXPECT().ReadAuthCookie(gomock.Any()).Return(cookie.NewValues(), false, nil)
				c.EXPECT().NewAuthCookie(gomock.Any(), gomock.Any(), gomock.Any()).
					Do(func(_ http.ResponseWriter, _ bool, sessionID ccc.UUID) {
						tt.wantSessionID = sessionID
					}).
					Return(cookie.NewValues().
						Set(cookie.SessionID, "92922509-82d2-4ba1-853a-d73b8926a55f").
						Set(cookie.SameSiteStrict, "true"),
						nil)
			},
			expectedStatus: http.StatusOK,
		},
		{
			name: "success with existing cookie upgraded",
			req:  mockRequestWithSession(context.Background(), t, http.MethodGet, cookieKey, "92922509-82d2-4bc7-853a-d73b8926a55f"),
			prepare: func(c *mock_cookie.MockHandler, _ *test) {
				c.EXPECT().ReadAuthCookie(gomock.Any()).Return(cookie.NewValues().Set(cookie.SessionID, "92922509-82d2-4bc7-853a-d73b8926a55f"), true, nil)
				c.EXPECT().WriteAuthCookie(gomock.Any(), true, cookie.NewValues().Set(cookie.SessionID, "92922509-82d2-4bc7-853a-d73b8926a55f")).Return(nil)
			},
			wantSessionID:  ccc.Must(ccc.UUIDFromString("92922509-82d2-4bc7-853a-d73b8926a55f")),
			expectedStatus: http.StatusOK,
		},
		{
			name: "success without upgrading existing cookie",
			req:  mockRequestWithSession(context.Background(), t, http.MethodGet, cookieKey, "92922509-82d2-4bc7-853a-d73b8926a55f"),
			prepare: func(c *mock_cookie.MockHandler, _ *test) {
				c.EXPECT().ReadAuthCookie(gomock.Any()).Return(cookie.NewValues().
					Set(cookie.SessionID, "92922509-82d2-4bc7-853a-d73b8926a55f").
					Set(cookie.SameSiteStrict, "true"),
					true, nil)
			},
			wantSessionID:  ccc.Must(ccc.UUIDFromString("92922509-82d2-4bc7-853a-d73b8926a55f")),
			expectedStatus: http.StatusOK,
		},
		{
			name: "fails to upgrade existing cookie",
			req:  mockRequestWithSession(context.Background(), t, http.MethodGet, cookieKey, "92922509-82d2-4bc7-853a-d73b8926a55f"),
			prepare: func(c *mock_cookie.MockHandler, _ *test) {
				c.EXPECT().ReadAuthCookie(gomock.Any()).Return(cookie.NewValues().
					Set(cookie.SessionID, "92922509-82d2-4bc7-853a-d73b8926a55f").
					Set(cookie.SameSiteStrict, "false"),
					true, nil)
				c.EXPECT().WriteAuthCookie(gomock.Any(), true, cookie.NewValues().
					Set(cookie.SessionID, "92922509-82d2-4bc7-853a-d73b8926a55f").
					Set(cookie.SameSiteStrict, "false"),
				).Return(errors.New("error writing cookie"))
			},
			expectedStatus: http.StatusInternalServerError,
		},
		{
			name: "fail at ReadAuthCookie()",
			req:  &http.Request{URL: &url.URL{}},
			prepare: func(c *mock_cookie.MockHandler, _ *test) {
				c.EXPECT().ReadAuthCookie(gomock.Any()).Return(cookie.NewValues(), false, errors.New("error reading cookie"))
			},
			expectedStatus: http.StatusInternalServerError,
		},
		{
			name: "fail at NewAuthCookie()",
			req:  &http.Request{URL: &url.URL{}},
			prepare: func(c *mock_cookie.MockHandler, _ *test) {
				c.EXPECT().ReadAuthCookie(gomock.Any()).Return(cookie.NewValues(), false, nil)
				c.EXPECT().NewAuthCookie(gomock.Any(), gomock.Any(), gomock.Any()).Return(cookie.NewValues(), errors.New("error creating cookie"))
			},
			expectedStatus: http.StatusInternalServerError,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			c := mock_cookie.NewMockHandler(gomock.NewController(t))
			a := &BaseSession{
				SessionTimeout: time.Second * 5,
				CookieHandler:  c,
				Handle: func(handler func(w http.ResponseWriter, r *http.Request) error) http.HandlerFunc {
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

			got := sessioninfo.IDFromRequest(req)
			if diff := cmp.Diff(tt.wantSessionID, got); diff != "" {
				t.Errorf("sessionIDFromRequest mismatch (-want +got):\n%s", diff)
			}
		})
	}
}

func TestBaseSessionValidateSession(t *testing.T) {
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
		prepare    func(storageManager *mock_sessionstorage.MockBaseStore)
		wantStatus int
	}{
		{
			name: "success GET",
			fields: fields{
				sessionTimeout: time.Minute,
			},
			args: args{
				r: mockRequestWithSession(context.Background(), t, http.MethodGet, "", "de6e1a12-2d4d-4c4d-aaf1-d82cb9a9eff5"),
			},
			prepare: func(storageManager *mock_sessionstorage.MockBaseStore) {
				storageManager.EXPECT().Session(gomock.Any(), ccc.Must(ccc.UUIDFromString("de6e1a12-2d4d-4c4d-aaf1-d82cb9a9eff5"))).
					Return(&sessioninfo.SessionInfo{
						ID:        ccc.Must(ccc.UUIDFromString("de6e1a12-2d4d-4c4d-aaf1-d82cb9a9eff5")),
						Username:  "specialUser",
						UpdatedAt: time.Now().Add(-10 * time.Second),
					}, nil)
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
				r: mockRequestWithSession(context.Background(), t, http.MethodPost, "", "de6e1a12-2d4d-4c4d-aaf1-d82cb9a9eff5"),
			},
			prepare: func(storageManager *mock_sessionstorage.MockBaseStore) {
				storageManager.EXPECT().Session(gomock.Any(), ccc.Must(ccc.UUIDFromString("de6e1a12-2d4d-4c4d-aaf1-d82cb9a9eff5"))).
					Return(&sessioninfo.SessionInfo{
						ID:        ccc.Must(ccc.UUIDFromString("de6e1a12-2d4d-4c4d-aaf1-d82cb9a9eff5")),
						Username:  "specialUser",
						UpdatedAt: time.Now().Add(-10 * time.Second),
					}, nil)
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
				r: mockRequestWithSession(context.Background(), t, http.MethodGet, "", "de6e1a12-2d4d-4c4d-aaf1-d82cb9a9eff5"),
			},
			prepare: func(storageManager *mock_sessionstorage.MockBaseStore) {
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
				r: mockRequestWithSession(context.Background(), t, http.MethodGet, "", "de6e1a12-2d4d-4c4d-aaf1-d82cb9a9eff5"),
			},
			prepare: func(storageManager *mock_sessionstorage.MockBaseStore) {
				storageManager.EXPECT().Session(gomock.Any(), ccc.Must(ccc.UUIDFromString("de6e1a12-2d4d-4c4d-aaf1-d82cb9a9eff5"))).
					Return(&sessioninfo.SessionInfo{
						ID:        ccc.Must(ccc.UUIDFromString("de6e1a12-2d4d-4c4d-aaf1-d82cb9a9eff5")),
						Username:  "specialUser",
						UpdatedAt: time.Now().Add(-10 * time.Second),
					}, nil)
				storageManager.EXPECT().UpdateSessionActivity(gomock.Any(), ccc.Must(ccc.UUIDFromString("de6e1a12-2d4d-4c4d-aaf1-d82cb9a9eff5"))).Return(errors.New("big fat error"))
			},
			wantStatus: http.StatusInternalServerError,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			ctrl := gomock.NewController(t)
			storageManager := mock_sessionstorage.NewMockBaseStore(ctrl)

			tt.prepare(storageManager)

			a := &BaseSession{
				SessionTimeout: tt.fields.sessionTimeout,
				Handle: func(handler func(w http.ResponseWriter, r *http.Request) error) http.HandlerFunc {
					return func(w http.ResponseWriter, r *http.Request) {
						if err := handler(w, r); err != nil {
							_ = err
						}
					}
				},
				Storage: storageManager,
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

func TestBaseSessionCheckSession(t *testing.T) {
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
		prepare          func(storageManager *mock_sessionstorage.MockBaseStore, tt test)
		wantUnauthorized bool
		want             *sessioninfo.SessionInfo
		wantMsg          string
		wantErr          bool
	}
	tests := []test{
		{
			name: "success, with update session activity",
			fields: fields{
				sessionTimeout: time.Minute,
			},
			args: args{
				r: mockRequestWithSession(context.Background(), t, http.MethodGet, "", "92922509-82d2-4bc7-853a-d73b8926a55f"),
			},
			want: &sessioninfo.SessionInfo{
				ID:        ccc.Must(ccc.UUIDFromString("92922509-82d2-4bc7-853a-d73b8926a55f")),
				Username:  "specialUser",
				UpdatedAt: time.Now().Add(-10 * time.Second),
			},
			prepare: func(storageManager *mock_sessionstorage.MockBaseStore, tt test) {
				storageManager.EXPECT().Session(gomock.Any(), ccc.Must(ccc.UUIDFromString("92922509-82d2-4bc7-853a-d73b8926a55f"))).Return(tt.want, nil)
				storageManager.EXPECT().UpdateSessionActivity(gomock.Any(), ccc.Must(ccc.UUIDFromString("92922509-82d2-4bc7-853a-d73b8926a55f"))).Return(nil)
			},
		},
		{
			name: "success, skip update session activity",
			fields: fields{
				sessionTimeout: time.Minute,
			},
			args: args{
				r: mockRequestWithSession(context.Background(), t, http.MethodGet, "", "92922509-82d2-4bc7-853a-d73b8926a55f"),
			},
			want: &sessioninfo.SessionInfo{
				ID:        ccc.Must(ccc.UUIDFromString("92922509-82d2-4bc7-853a-d73b8926a55f")),
				Username:  "specialUser",
				UpdatedAt: time.Now(),
			},
			prepare: func(storageManager *mock_sessionstorage.MockBaseStore, tt test) {
				storageManager.EXPECT().Session(gomock.Any(), ccc.Must(ccc.UUIDFromString("92922509-82d2-4bc7-853a-d73b8926a55f"))).Return(tt.want, nil)
			},
		},
		{
			name: "fail on UpdateSessionActivity()",
			fields: fields{
				sessionTimeout: time.Minute,
			},
			args: args{
				r: mockRequestWithSession(context.Background(), t, http.MethodGet, "", "92922509-82d2-4bc7-853a-d73b8926a55f"),
			},
			want: &sessioninfo.SessionInfo{ID: ccc.Must(ccc.UUIDFromString("92922509-82d2-4bc7-853a-d73b8926a55f")), Username: "specialUser", UpdatedAt: time.Now().Add(-10 * time.Second)},
			prepare: func(storageManager *mock_sessionstorage.MockBaseStore, tt test) {
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
				r: mockRequestWithSession(context.Background(), t, http.MethodGet, "", "92922509-82d2-4bc7-853a-d73b8926a55f"),
			},
			want: &sessioninfo.SessionInfo{ID: ccc.Must(ccc.UUIDFromString("92922509-82d2-4bc7-853a-d73b8926a55f")), Username: "specialUser", UpdatedAt: time.Now().Add(-10 * time.Second), Expired: true},
			prepare: func(storageManager *mock_sessionstorage.MockBaseStore, tt test) {
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
				r: mockRequestWithSession(context.Background(), t, http.MethodGet, "", "de6e1a12-2d4d-4c4d-aaf1-d82cb9a9eff5"),
			},
			want: &sessioninfo.SessionInfo{ID: ccc.Must(ccc.UUIDFromString("de6e1a12-2d4d-4c4d-aaf1-d82cb9a9eff5")), Username: "specialUser", UpdatedAt: time.Now().Add(-time.Hour)},
			prepare: func(storageManager *mock_sessionstorage.MockBaseStore, tt test) {
				storageManager.EXPECT().Session(gomock.Any(), ccc.Must(ccc.UUIDFromString("de6e1a12-2d4d-4c4d-aaf1-d82cb9a9eff5"))).Return(tt.want, nil)
			},
			wantUnauthorized: true,
			wantMsg:          "session expired",
			wantErr:          true,
		},
		{
			name: "failed on session",
			args: args{
				r: mockRequestWithSession(context.Background(), t, http.MethodGet, "", "de6e1a12-2d4d-4c4d-aaf1-d82cb9a9eff5"),
			},
			prepare: func(storageManager *mock_sessionstorage.MockBaseStore, _ test) {
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
			storageManager := mock_sessionstorage.NewMockBaseStore(ctrl)

			tt.prepare(storageManager, tt)

			a := &BaseSession{
				SessionTimeout: tt.fields.sessionTimeout,
				Storage:        storageManager,
			}

			gotReq, err := a.ValidateSessionAPI(tt.args.r.Context())
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
			if got := sessioninfo.FromCtx(gotReq); !reflect.DeepEqual(got, tt.want) {
				t.Errorf("sessInfo = %v, wantSessInfo %v", got, tt.want)
			}
		})
	}
}

func TestBaseSession_validSessionID(t *testing.T) {
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
			gotUUID, got := cookie.ValidSessionID(tt.args.sessionID)
			if got != tt.want {
				t.Errorf("validSessionID() = %v, want %v", got, tt.want)
			}
			if gotUUID != tt.wantUUID {
				t.Errorf("validSessionID() = %v, want %v", gotUUID, tt.wantUUID)
			}
		})
	}
}

func TestBaseSession_Authenticated(t *testing.T) {
	t.Parallel()
	type response struct {
		Authenticated bool                                 `json:"authenticated"`
		Username      string                               `json:"username"`
		Permissions   accesstypes.UserPermissionCollection `json:"permissions"`
	}
	tests := []struct {
		name           string
		expectedStatus int
		prepare        func(*mock_sessionstorage.MockBaseStore)
		cookieError    bool
		want           *response
	}{
		{
			name: "success but unauthorized",
			prepare: func(storage *mock_sessionstorage.MockBaseStore) {
				storage.EXPECT().Session(gomock.Any(), gomock.Any()).Return(nil, errors.New("invalid session")).Times(1)
			},
			expectedStatus: http.StatusOK,
			want:           &response{},
		},
		{
			name: "fails to check the user's session",
			prepare: func(storage *mock_sessionstorage.MockBaseStore) {
				storage.EXPECT().Session(gomock.Any(), gomock.Any()).Return(&sessioninfo.SessionInfo{UpdatedAt: time.Now().Add(-10 * time.Second)}, nil).Times(1)
				storage.EXPECT().UpdateSessionActivity(gomock.Any(), gomock.Any()).Return(errors.New("failed to update session activity")).Times(1)
			},
			expectedStatus: http.StatusInternalServerError,
		},
		{
			name: "successful authentication",
			prepare: func(storage *mock_sessionstorage.MockBaseStore) {
				storage.EXPECT().Session(gomock.Any(), gomock.Any()).Return(&sessioninfo.SessionInfo{
					Username:  "test Username",
					UpdatedAt: time.Now().Add(-10 * time.Second),
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
			storage := mock_sessionstorage.NewMockBaseStore(ctrl)

			session := &BaseSession{
				SessionTimeout: 15 * time.Minute,
				Storage:        storage,
				Handle: func(handler func(w http.ResponseWriter, r *http.Request) error) http.HandlerFunc {
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

func TestBaseSession_Logout(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name           string
		prepare        func(*mock_sessionstorage.MockBaseStore)
		expectedStatus int
		wantSessionID  ccc.UUID
	}{
		{
			name: "success logging out, fails to destroy session in db",
			prepare: func(u *mock_sessionstorage.MockBaseStore) {
				u.EXPECT().DestroySession(gomock.Any(), ccc.Must(ccc.UUIDFromString("bbee630a-0255-4dee-9283-8b7277bad0b0"))).Return(httpio.NewNotFoundMessagef("session not found")).Times(1)
			},
			expectedStatus: http.StatusNotFound,
			wantSessionID:  ccc.Must(ccc.UUIDFromString("bbee630a-0255-4dee-9283-8b7277bad0b0")),
		},
		{
			name: "success logging out",
			prepare: func(u *mock_sessionstorage.MockBaseStore) {
				u.EXPECT().DestroySession(gomock.Any(), gomock.Any()).Return(nil).Times(1)
			},
			expectedStatus: http.StatusOK,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			storage := mock_sessionstorage.NewMockBaseStore(gomock.NewController(t))
			tt.prepare(storage)
			a := &BaseSession{
				SessionTimeout: 15 * time.Minute,
				Storage:        storage,
				Handle: func(handler func(w http.ResponseWriter, r *http.Request) error) http.HandlerFunc {
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
			req = req.WithContext(context.WithValue(req.Context(), sessioninfo.CTXSessionID, tt.wantSessionID))

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

// mockRequestWithXSRFToken Mocks Request with XSRF Token
func mockRequestWithXSRFToken(t *testing.T, method string, setHeader bool, cookieSessionID, requestSessionID ccc.UUID) *http.Request {
	// Use setXSRFTokenCookie() to generate a valid cookie
	w := httptest.NewRecorder()
	c, err := cookie.NewCookieClient(cookieKey)
	if err != nil {
		t.Fatalf("NewCookieClient() = %v", err)
	}
	if set, _ := c.RefreshXSRFTokenCookie(w, &http.Request{}, cookieSessionID); !set {
		t.Fatalf("setXSRFTokenCookie() = false, should have set cookie in request recorder")
	}

	// Create request using cookie set in Response Recorder
	r := &http.Request{
		Method: method,
		Header: http.Header{
			"Cookie": w.Header().Values("Set-Cookie"),
		},
	}

	if setHeader {
		// Get XSRF cookie
		c, err := r.Cookie(cookie.XSRFCookieName)
		if err != nil {
			return r
		}

		// Set XSRF Token header to XSRF cookie value
		r.Header.Set(cookie.XSRFHeaderName, c.Value)
	}

	// Store sessionID in context
	r = r.WithContext(context.WithValue(context.Background(), sessioninfo.CTXSessionID, requestSessionID))

	return r
}

func TestBaseSessionSetXSRFToken(t *testing.T) {
	t.Parallel()

	type args struct {
		next http.Handler
		r    *http.Request
	}
	tests := []struct {
		name string
		args args
		want int
	}{
		{
			name: "success",
			args: args{
				next: http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusAccepted) }),
				r:    &http.Request{Method: http.MethodGet},
			},
			want: http.StatusAccepted,
		},
		{
			name: "redirect",
			args: args{
				r: &http.Request{Method: http.MethodPost, URL: &url.URL{}},
			},
			want: http.StatusTemporaryRedirect,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			cookieClient, err := cookie.NewCookieClient(cookieKey)
			if err != nil {
				t.Fatalf("NewCookieClient() = %v", err)
			}
			a := &BaseSession{
				CookieHandler: cookieClient,
				Handle: func(handler func(w http.ResponseWriter, r *http.Request) error) http.HandlerFunc {
					return func(w http.ResponseWriter, r *http.Request) {
						if err := handler(w, r); err != nil {
							_ = err
						}
					}
				},
			}
			w := httptest.NewRecorder()
			a.SetXSRFToken(tt.args.next).ServeHTTP(w, tt.args.r)
			if got := w.Code; !reflect.DeepEqual(got, tt.want) {
				t.Errorf("App.SetXSRFToken() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestBaseSessionValidateXSRFToken(t *testing.T) {
	t.Parallel()

	type args struct {
		next http.Handler
		r    *http.Request
	}
	tests := []struct {
		name string
		args args
		want int
	}{
		{
			name: "success safe method no cookie",
			args: args{
				next: http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusAccepted) }),
				r:    &http.Request{Method: http.MethodGet},
			},
			want: http.StatusAccepted,
		},
		{
			name: "success safe method with cookie",
			args: args{
				next: http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusAccepted) }),
				r:    mockRequestWithXSRFToken(t, http.MethodGet, true, ccc.Must(ccc.UUIDFromString("de6e1a12-2d4d-4c4d-aaf1-d82cb9a9eff5")), ccc.Must(ccc.UUIDFromString("de6e1a12-2d4d-4c4d-aaf1-d82cb9a9eff5"))),
			},
			want: http.StatusAccepted,
		},
		{
			name: "success non-safe method",
			args: args{
				next: http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusAccepted) }),
				r:    mockRequestWithXSRFToken(t, http.MethodPost, true, ccc.Must(ccc.UUIDFromString("de6e1a12-2d4d-4c4d-aaf1-d82cb9a9eff5")), ccc.Must(ccc.UUIDFromString("de6e1a12-2d4d-4c4d-aaf1-d82cb9a9eff5"))),
			},
			want: http.StatusAccepted,
		},
		{
			name: "failure non-safe method",
			args: args{
				r: &http.Request{Method: http.MethodPost},
			},
			want: http.StatusForbidden,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			cookieClient, err := cookie.NewCookieClient(cookieKey)
			if err != nil {
				t.Fatalf("NewCookieClient() = %v", err)
			}
			a := &BaseSession{
				CookieHandler: cookieClient,
				Handle: func(handler func(w http.ResponseWriter, r *http.Request) error) http.HandlerFunc {
					return func(w http.ResponseWriter, r *http.Request) {
						if err := handler(w, r); err != nil {
							_ = err
						}
					}
				},
			}
			w := httptest.NewRecorder()
			a.ValidateXSRFToken(tt.args.next).ServeHTTP(w, tt.args.r)
			if got := w.Code; !reflect.DeepEqual(got, tt.want) {
				t.Errorf("App.ValidateXSRFToken() = %v, want %v", got, tt.want)
			}
		})
	}
}
