package session

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/cccteam/ccc"
	"github.com/cccteam/session/mock/mock_session"
	gomock "go.uber.org/mock/gomock"
)

func TestPreauthSession_NewSession(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name       string
		username   string
		prepare    func(*mock_session.MockPreauthSessionStorage, *MockcookieManager, *httptest.ResponseRecorder)
		wantErr    bool
		expectedID ccc.UUID
	}{
		{
			name:     "successful session creation and cookie set",
			username: "test_user",
			prepare: func(mockStorage *mock_session.MockPreauthSessionStorage, mockCookies *MockcookieManager, w *httptest.ResponseRecorder) {
				mockStorage.EXPECT().
					NewSession(gomock.Any(), "test_user").
					Return(ccc.Must(ccc.UUIDFromString("123e4567-e89b-12d3-a456-426614174000")), nil).
					Times(1)

				mockCookies.EXPECT().
					newAuthCookie(w, false, gomock.Any()).
					DoAndReturn(func(w http.ResponseWriter, sameSiteStrict bool, sessionID ccc.UUID) (map[scKey]string, error) {
						http.SetCookie(w, &http.Cookie{
							Name:  "auth",
							Value: sessionID.String(),
							Path:  "/",
						})
						return map[scKey]string{scSessionID: sessionID.String()}, nil
					}).
					Times(1)

				mockCookies.EXPECT().
					setXSRFTokenCookie(w, gomock.Any(), gomock.Any(), xsrfCookieLife).
					Return(true).
					Times(1)
			},
			expectedID: ccc.Must(ccc.UUIDFromString("123e4567-e89b-12d3-a456-426614174000")),
		},
		{
			name:     "failed session creation",
			username: "test_user",
			prepare: func(mockStorage *mock_session.MockPreauthSessionStorage, mockCookies *MockcookieManager, w *httptest.ResponseRecorder) {
				mockStorage.EXPECT().
					NewSession(gomock.Any(), "test_user").
					Return(ccc.NilUUID, errors.New("storage error")).
					Times(1)
			},
			wantErr: true,
		},
		{
			name:     "failed to set auth cookie",
			username: "test_user",
			prepare: func(mockStorage *mock_session.MockPreauthSessionStorage, mockCookies *MockcookieManager, w *httptest.ResponseRecorder) {
				mockStorage.EXPECT().
					NewSession(gomock.Any(), "test_user").
					Return(ccc.Must(ccc.UUIDFromString("123e4567-e89b-12d3-a456-426614174000")), nil).
					Times(1)

				// Simulate failure in newAuthCookie
				mockCookies.EXPECT().
					newAuthCookie(w, false, gomock.Any()).
					Return(nil, errors.New("failed to set auth cookie")).
					Times(1)
			},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			ctrl := gomock.NewController(t)
			defer ctrl.Finish()

			mockStorage := mock_session.NewMockPreauthSessionStorage(ctrl)
			mockCookies := NewMockcookieManager(ctrl)

			w := httptest.NewRecorder()
			r := httptest.NewRequest(http.MethodPost, "/", nil)

			if tt.prepare != nil {
				tt.prepare(mockStorage, mockCookies, w)
			}

			preauth := &PreauthSession{
				storage: mockStorage,
				session: session{
					cookieManager: mockCookies,
					storage:       mockStorage,
				},
			}

			id, err := preauth.NewSession(context.Background(), w, r, tt.username)

			if (err != nil) != tt.wantErr {
				t.Errorf("NewSession() error = %v, wantErr = %v", err, tt.wantErr)
			}
			if id != tt.expectedID && !tt.wantErr {
				t.Errorf("NewSession() id = %v, expectedID = %v", id, tt.expectedID)
			}

			if tt.wantErr {
				if len(w.Result().Cookies()) > 0 {
					t.Error("expected no cookies to be set on failure, but found some")
				}
			}
		})
	}
}
