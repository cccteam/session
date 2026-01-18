package session

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/cccteam/ccc"
	"github.com/cccteam/session/cookie"
	"github.com/cccteam/session/internal/basesession"
	internalcookie "github.com/cccteam/session/internal/cookie"
	"github.com/cccteam/session/mock/mock_cookie"
	"github.com/cccteam/session/sessionstorage/mock/mock_sessionstorage"
	gomock "go.uber.org/mock/gomock"
)

func TestPreauthAPI_Login(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name       string
		username   string
		prepare    func(*mock_sessionstorage.MockPreauthStore, *mock_cookie.MockHandler)
		wantErr    bool
		expectedID ccc.UUID
	}{
		{
			name:     "successful session creation and cookie set",
			username: "test_user",
			prepare: func(mockStorage *mock_sessionstorage.MockPreauthStore, mockCookies *mock_cookie.MockHandler) {
				// Mock the session creation
				mockStorage.EXPECT().
					NewSession(gomock.Any(), "test_user").
					Return(ccc.Must(ccc.UUIDFromString("123e4567-e89b-12d3-a456-426614174000")), nil).
					Times(1)

				// Simulate cookie setting
				mockCookies.EXPECT().
					NewAuthCookie(gomock.Any(), true, gomock.Any()).
					DoAndReturn(func(w http.ResponseWriter, _ bool, sessionID ccc.UUID) (cookie.Values, error) {
						http.SetCookie(w, &http.Cookie{
							Name:  "auth",
							Value: sessionID.String(),
							Path:  "/",
						})
						return cookie.NewValues().Set(internalcookie.SessionID, sessionID.String()), nil
					}).
					Times(1)

				mockCookies.EXPECT().
					CreateXSRFTokenCookie(gomock.Any(), gomock.Any()).
					Return().
					Times(1)
			},
			expectedID: ccc.Must(ccc.UUIDFromString("123e4567-e89b-12d3-a456-426614174000")),
		},
		{
			name:     "failed session creation",
			username: "test_user",
			prepare: func(mockStorage *mock_sessionstorage.MockPreauthStore, _ *mock_cookie.MockHandler) {
				// Simulate a failure in session creation
				mockStorage.EXPECT().
					NewSession(gomock.Any(), "test_user").
					Return(ccc.NilUUID, errors.New("storage error")).
					Times(1)
			},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			// Setup the mock controller
			ctrl := gomock.NewController(t)
			mockStorage := mock_sessionstorage.NewMockPreauthStore(ctrl)
			mockCookies := mock_cookie.NewMockHandler(ctrl)

			// Prepare the mock expectations
			if tt.prepare != nil {
				tt.prepare(mockStorage, mockCookies)
			}

			// Setup request and response recorder
			w := httptest.NewRecorder()

			// Create the PreauthSession instance with mocked dependencies
			preauth := &Preauth{
				storage: mockStorage,
				baseSession: &basesession.BaseSession{
					CookieHandler: mockCookies,
					Storage:       mockStorage,
				},
			}

			// Call Login and capture the result
			id, err := preauth.API().Login(context.Background(), w, tt.username)

			// Validate the results
			if (err != nil) != tt.wantErr {
				t.Errorf("Login() error = %v, wantErr = %v", err, tt.wantErr)
			}
			if id != tt.expectedID && !tt.wantErr {
				t.Errorf("Login() id = %v, expectedID = %v", id, tt.expectedID)
			}

			// Ensure cookies are only set on success
			if tt.wantErr {
				resp := w.Result()
				defer resp.Body.Close()
				if len(resp.Cookies()) > 0 {
					t.Error("expected no cookies to be set on failure, but found some")
				}
			}
		})
	}
}
