package session

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/cccteam/ccc"
	"github.com/cccteam/httpio"
	"github.com/cccteam/session/internal/dbtype"
	"github.com/cccteam/session/mock/mock_cookie"
	"github.com/cccteam/session/sessionstorage/mock/mock_sessionstorage"
	gomock "go.uber.org/mock/gomock"
)

// TestPasswordAuth_PasswordLessAccount proves that an account with no password hash (one
// provisioned for external sign-in only) fails every password check as invalid
// credentials: it never panics in the hasher and never yields a session. The strict
// mocks would fail a CreateSession, SetUserPasswordHash or DestroyAllUserSessions call.
func TestPasswordAuth_PasswordLessAccount(t *testing.T) {
	t.Parallel()

	userID := ccc.Must(ccc.NewUUID())
	passwordLess := &dbtype.SessionUser{ID: userID, Username: "sso-only@example.com"}

	tests := []struct {
		name string
		// check runs the password check under test and returns its error.
		check func(ctx context.Context, p *PasswordAuth[NoCustomData, NoCustomData], storage *mock_sessionstorage.MockPasswordAuthStore) error
		// wantClass is the client error class the refusal must carry.
		wantClass func(error) bool
	}{
		{
			name: "ValidateCredentials refuses it as invalid credentials",
			check: func(ctx context.Context, p *PasswordAuth[NoCustomData, NoCustomData], storage *mock_sessionstorage.MockPasswordAuthStore) error {
				storage.EXPECT().UserByUserName(gomock.Any(), passwordLess.Username).Return(passwordLess, nil)

				return p.API().ValidateCredentials(ctx, passwordLess.Username, "any password")
			},
			wantClass: httpio.HasUnauthorized,
		},
		{
			name: "Login refuses it as invalid credentials and starts no session",
			check: func(ctx context.Context, p *PasswordAuth[NoCustomData, NoCustomData], storage *mock_sessionstorage.MockPasswordAuthStore) error {
				storage.EXPECT().UserByUserName(gomock.Any(), passwordLess.Username).Return(passwordLess, nil)

				return p.API().Login(ctx, httptest.NewRecorder(), passwordLess.Username, "")
			},
			wantClass: httpio.HasUnauthorized,
		},
		{
			name: "changing its password refuses the old password and keeps its sessions",
			check: func(ctx context.Context, p *PasswordAuth[NoCustomData, NoCustomData], storage *mock_sessionstorage.MockPasswordAuthStore) error {
				storage.EXPECT().User(gomock.Any(), userID).Return(passwordLess, nil)

				return p.API().ChangeSessionUserPassword(ctx, httptest.NewRecorder(), userID, &ChangeSessionUserPasswordRequest{OldPassword: "", NewPassword: "new password"})
			},
			wantClass: httpio.HasBadRequest,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			ctrl := gomock.NewController(t)

			storage := newPasswordStoreMock(ctrl)
			p, err := NewPasswordAuth[NoCustomData, NoCustomData](storage, cookieKey)
			if err != nil {
				t.Fatalf("NewPasswordAuth() error = %v", err)
			}
			p.baseSession.CookieHandler = mock_cookie.NewMockHandler(ctrl)

			var got error
			func() {
				defer func() {
					if r := recover(); r != nil {
						t.Fatalf("password check panicked on a password-less account: %v", r)
					}
				}()
				got = tt.check(t.Context(), p, storage)
			}()

			if got == nil {
				t.Fatal("password check error = nil, want a refusal")
			}
			if !tt.wantClass(got) {
				t.Errorf("password check error = %v, want the refusal's client error class", got)
			}
		})
	}
}

// TestPasswordAuth_Login_PasswordLessAccount drives the Login handler for a
// password-less account: 401, no cookies.
func TestPasswordAuth_Login_PasswordLessAccount(t *testing.T) {
	t.Parallel()
	ctrl := gomock.NewController(t)

	storage := newPasswordStoreMock(ctrl)
	storage.EXPECT().UserByUserName(gomock.Any(), "sso-only@example.com").Return(&dbtype.SessionUser{ID: ccc.Must(ccc.NewUUID()), Username: "sso-only@example.com"}, nil)

	p, err := NewPasswordAuth[NoCustomData, NoCustomData](storage, cookieKey)
	if err != nil {
		t.Fatalf("NewPasswordAuth() error = %v", err)
	}

	body, err := json.Marshal(map[string]string{"username": "sso-only@example.com", "password": "guess"})
	if err != nil {
		t.Fatal(err)
	}
	req := httptest.NewRequestWithContext(t.Context(), http.MethodPost, "/login", bytes.NewReader(body))
	rr := httptest.NewRecorder()

	p.Login().ServeHTTP(rr, req)

	if rr.Code != http.StatusUnauthorized {
		t.Errorf("Login() status = %d, want %d", rr.Code, http.StatusUnauthorized)
	}
	if cookies := rr.Result().Cookies(); len(cookies) != 0 {
		t.Errorf("Login() wrote %d cookies, want none", len(cookies))
	}
}
