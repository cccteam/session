package session

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/cccteam/ccc"
	"github.com/cccteam/httpio"
	"github.com/cccteam/session/sessioninfo"
	"github.com/cccteam/session/sessionstorage"
	"github.com/go-playground/errors/v5"
	gomock "go.uber.org/mock/gomock"
)

// grant posts form-encoded fields to h, as a standard OAuth client does.
func grant(h http.Handler, fields url.Values) *httptest.ResponseRecorder {
	r := httptest.NewRequestWithContext(context.Background(), http.MethodPost, "/oauth/token", strings.NewReader(fields.Encode()))
	r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, r)

	return rr
}

// oauthBody decodes an answer of the two public endpoints into m.
func oauthBody(t *testing.T, rr *httptest.ResponseRecorder, m any) {
	t.Helper()

	if got := rr.Header().Get("Cache-Control"); got != "no-store" {
		t.Errorf("Cache-Control = %q, want no-store", got)
	}
	if err := json.Unmarshal(rr.Body.Bytes(), m); err != nil {
		t.Fatalf("json.Unmarshal(%s) error = %v", rr.Body, err)
	}
}

func TestDeviceHandlers_Authorize(t *testing.T) {
	t.Parallel()

	t.Run("a form-encoded request is answered the RFC's fields", func(t *testing.T) {
		t.Parallel()
		f := newTokenFixture(t, gomock.NewController(t), WithDeviceCodeLifetime(10*time.Minute, 5*time.Second))
		var stored *sessionstorage.DeviceCode
		f.store.EXPECT().InsertDeviceCode(gomock.Any(), gomock.Any()).DoAndReturn(func(_ context.Context, code *sessionstorage.DeviceCode) error {
			stored = code

			return nil
		})

		rr := grant(f.auth.Device().Authorize(), url.Values{"client_id": {"corral"}, "outlet": {droids}})
		if rr.Code != http.StatusOK {
			t.Fatalf("status = %d: %s", rr.Code, rr.Body)
		}
		var body deviceAuthorizationResponse
		oauthBody(t, rr, &body)
		if !bytes.Equal(hashToken(body.DeviceCode), stored.DeviceCodeHash) || body.UserCode != formatUserCode(stored.UserCode) {
			t.Errorf("answer = %+v does not name the stored code %+v", body, stored)
		}
		if body.VerificationURI != "/device" || body.VerificationURIComplete != "/device?userCode="+body.UserCode || body.ExpiresIn != 600 || body.Interval != 5 {
			t.Errorf("answer = %+v", body)
		}
	})

	t.Run("a JSON request is accepted too, and an unregistered outlet is invalid_request", func(t *testing.T) {
		t.Parallel()
		f := newTokenFixture(t, gomock.NewController(t))
		rr := f.serve(f.auth.Device().Authorize(), http.MethodPost, "/oauth/device/authorize", map[string]string{"client_id": "corral", "outlet": robots}, nil)
		if rr.Code != http.StatusBadRequest {
			t.Fatalf("status = %d: %s", rr.Code, rr.Body)
		}
		var body oauthError
		if err := json.Unmarshal(rr.Body.Bytes(), &body); err != nil || body.Error != oauthInvalidRequest || !strings.Contains(body.Description, "not a machine outlet") {
			t.Errorf("answer = %s, %v", rr.Body, err)
		}
	})
}

func TestDeviceHandlers_Token(t *testing.T) {
	t.Parallel()

	type testCase struct {
		name   string
		fields url.Values
		redeem sessionstorage.DeviceCodeStatus
		// redeemErr and refreshErr are what the store answers the grant.
		redeemErr, refreshErr error
		wantStatus            int
		wantError             string
	}
	device := func(code string) url.Values {
		return url.Values{"grant_type": {grantDeviceCode}, "device_code": {code}}
	}
	refresh := func(token string) url.Values {
		return url.Values{"grant_type": {grantRefreshToken}, "refresh_token": {token}}
	}
	tests := []testCase{
		{name: "an unsupported grant type", fields: url.Values{"grant_type": {"password"}}, wantStatus: http.StatusBadRequest, wantError: oauthUnsupportedGrant},
		{name: "a device grant without a code", fields: device(""), wantStatus: http.StatusBadRequest, wantError: oauthInvalidRequest},
		{name: "a pending authorization", fields: device("d"), redeem: sessionstorage.DevicePending, wantStatus: http.StatusBadRequest, wantError: oauthAuthorizationPending},
		{name: "a poll before the interval", fields: device("d"), redeem: sessionstorage.DeviceSlowDown, wantStatus: http.StatusBadRequest, wantError: oauthSlowDown},
		{name: "a denied authorization", fields: device("d"), redeem: sessionstorage.DeviceDenied, wantStatus: http.StatusBadRequest, wantError: oauthAccessDenied},
		{name: "an expired authorization", fields: device("d"), redeem: sessionstorage.DeviceExpired, wantStatus: http.StatusBadRequest, wantError: oauthExpiredToken},
		{name: "an unknown or redeemed device code", fields: device("d"), redeemErr: httpio.NewNotFoundMessage("no code"), wantStatus: http.StatusBadRequest, wantError: oauthInvalidGrant},
		{name: "an approved authorization", fields: device("d"), redeem: sessionstorage.DeviceApproved, wantStatus: http.StatusOK},
		{name: "a refresh without a token", fields: refresh(""), wantStatus: http.StatusBadRequest, wantError: oauthInvalidRequest},
		{name: "a refresh of a token that is not a live refresh token", fields: refresh("r"), refreshErr: httpio.NewNotFoundMessage("no token"), wantStatus: http.StatusBadRequest, wantError: oauthInvalidGrant},
		{name: "a reused refresh token", fields: refresh("r"), refreshErr: errors.Wrap(sessionstorage.ErrTokenReuse, "family revoked"), wantStatus: http.StatusBadRequest, wantError: oauthInvalidGrant},
		{name: "a refresh", fields: refresh("r"), wantStatus: http.StatusOK},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			f := newTokenFixture(t, gomock.NewController(t), WithTokenLifetimes(2*time.Hour, 24*time.Hour, 48*time.Hour))
			var access, refreshed *sessionstorage.Token
			f.store.EXPECT().RedeemDeviceCode(gomock.Any(), hashToken("d"), gomock.Any(), gomock.Any(), gomock.Any()).
				DoAndReturn(func(_ context.Context, _ []byte, _ time.Duration, a, r *sessionstorage.Token) (*sessionstorage.DeviceCode, sessionstorage.DeviceCodeStatus, error) {
					access, refreshed = a, r

					return &sessionstorage.DeviceCode{}, tt.redeem, tt.redeemErr
				}).AnyTimes()
			f.store.EXPECT().ExchangeRefreshToken(gomock.Any(), hashToken("r"), gomock.Any(), gomock.Any()).
				DoAndReturn(func(_ context.Context, _ []byte, a, r *sessionstorage.Token) error {
					access, refreshed = a, r

					return tt.refreshErr
				}).AnyTimes()

			rr := grant(f.auth.Device().Token(), tt.fields)
			if rr.Code != tt.wantStatus {
				t.Fatalf("status = %d, want %d: %s", rr.Code, tt.wantStatus, rr.Body)
			}
			if tt.wantError != "" {
				var body oauthError
				oauthBody(t, rr, &body)
				if body.Error != tt.wantError || body.Description == "" {
					t.Errorf("answer = %+v, want error %q with a description", body, tt.wantError)
				}

				return
			}
			var body tokenResponse
			oauthBody(t, rr, &body)
			if body.TokenType != "Bearer" || body.ExpiresIn != 7200 {
				t.Errorf("answer = %+v, want a Bearer pair for two hours", body)
			}
			if !bytes.Equal(hashToken(body.AccessToken), access.TokenHash) || !bytes.Equal(hashToken(body.RefreshToken), refreshed.TokenHash) {
				t.Error("the pair's secrets are not the hashes the store took")
			}
		})
	}
}

func TestDeviceHandlers_ApprovalPage(t *testing.T) {
	t.Parallel()

	t.Run("the lookup names the client and the outlet of a pending code, and 404 for any other", func(t *testing.T) {
		t.Parallel()
		f := newTokenFixture(t, gomock.NewController(t))
		userID, sessionID := newIDs()
		f.user = pat(userID)
		f.expectSession(sessionID, f.user)
		expires := time.Now().Add(5 * time.Minute).Round(time.Second)
		f.store.EXPECT().DeviceCode(gomock.Any(), "BCDFGHJK").Return(&sessionstorage.DeviceCode{ID: ccc.Must(ccc.NewUUID()), ClientID: "corral", Outlet: droids, ExpiresAt: expires}, nil)
		f.store.EXPECT().DeviceCode(gomock.Any(), "XXXXXXXX").Return(nil, httpio.NewNotFoundMessage("no pending code"))

		lookup := func(code string) *httptest.ResponseRecorder {
			r := httptest.NewRequestWithContext(context.WithValue(context.Background(), sessioninfo.CTXSessionID, sessionID), http.MethodGet, "/device/lookup?userCode="+url.QueryEscape(code), http.NoBody)
			rr := httptest.NewRecorder()
			f.auth.Device().Lookup().ServeHTTP(rr, r)

			return rr
		}
		rr := lookup("bcdf-ghjk")
		if rr.Code != http.StatusOK {
			t.Fatalf("status = %d: %s", rr.Code, rr.Body)
		}
		var view deviceView
		if err := json.Unmarshal(rr.Body.Bytes(), &view); err != nil || view.ClientID != "corral" || view.Outlet != droids || !view.ExpiresAt.Equal(expires) {
			t.Errorf("lookup = %s, %v", rr.Body, err)
		}
		if rr := lookup("XXXX-XXXX"); rr.Code != http.StatusNotFound {
			t.Errorf("lookup of an unknown code = %d, want 404", rr.Code)
		}
	})

	t.Run("the signed-in person approves as themselves, or denies", func(t *testing.T) {
		t.Parallel()
		f := newTokenFixture(t, gomock.NewController(t))
		userID, sessionID := newIDs()
		f.user = pat(userID)
		f.expectSession(sessionID, f.user)
		code := &sessionstorage.DeviceCode{ID: ccc.Must(ccc.NewUUID()), ClientID: "corral", Outlet: droids}
		f.store.EXPECT().DeviceCode(gomock.Any(), "BCDFGHJK").Return(code, nil).Times(2)
		f.store.EXPECT().ApproveDeviceCode(gomock.Any(), code.ID, userID).Return(nil)
		f.store.EXPECT().DenyDeviceCode(gomock.Any(), code.ID).Return(httpio.NewNotFoundMessage("decided already"))

		if rr := f.asUser(f.auth.Device().Approve(), sessionID, map[string]string{"userCode": "bcdf-ghjk"}, nil); rr.Code != http.StatusOK {
			t.Errorf("approve = %d: %s", rr.Code, rr.Body)
		}
		if rr := f.asUser(f.auth.Device().Deny(), sessionID, map[string]string{"userCode": "BCDF GHJK"}, nil); rr.Code != http.StatusNotFound {
			t.Errorf("deny of a decided code = %d, want 404: %s", rr.Code, rr.Body)
		}
	})

	t.Run("without a session the page's handlers are refused", func(t *testing.T) {
		t.Parallel()
		f := newTokenFixture(t, gomock.NewController(t))
		_, sessionID := newIDs()
		f.store.EXPECT().Session(gomock.Any(), sessionID).Return(nil, httpio.NewNotFoundMessage("no session")).AnyTimes()
		if rr := f.asUser(f.auth.Device().Approve(), sessionID, map[string]string{"userCode": "BCDFGHJK"}, nil); rr.Code != http.StatusUnauthorized {
			t.Errorf("approve = %d, want 401", rr.Code)
		}
	})
}

func TestApplicationTokenHandlers(t *testing.T) {
	t.Parallel()

	f := newTokenFixture(t, gomock.NewController(t), WithTokenLifetimes(time.Hour, 24*time.Hour, 48*time.Hour))
	userID, sessionID := newIDs()
	f.user = pat(userID)
	f.expectSession(sessionID, f.user)
	var stored *sessionstorage.Token
	f.store.EXPECT().InsertToken(gomock.Any(), gomock.Any()).DoAndReturn(func(_ context.Context, tok *sessionstorage.Token) error {
		stored = tok

		return nil
	})
	f.store.EXPECT().Tokens(gomock.Any(), userID).DoAndReturn(func(context.Context, ccc.UUID) ([]*sessionstorage.Token, error) {
		return []*sessionstorage.Token{stored}, nil
	})
	f.store.EXPECT().RevokeUserToken(gomock.Any(), userID, gomock.Any(), sessionstorage.TokenRevokedByHand).DoAndReturn(func(_ context.Context, _, id ccc.UUID, _ sessionstorage.TokenRevocation) error {
		if id != stored.ID {
			return httpio.NewNotFoundMessage("no live token")
		}

		return nil
	}).Times(2)

	// Create: the secret, once.
	rr := f.asUser(f.auth.ApplicationTokens().Create(), sessionID, map[string]any{"name": "laptop", "outlet": droids, "expiresIn": 3600}, nil)
	if rr.Code != http.StatusOK {
		t.Fatalf("create = %d: %s", rr.Code, rr.Body)
	}
	var issued issuedTokenResponse
	if err := json.Unmarshal(rr.Body.Bytes(), &issued); err != nil {
		t.Fatalf("json.Unmarshal() error = %v", err)
	}
	if issued.ID != stored.ID || !bytes.Equal(hashToken(issued.Token), stored.TokenHash) || issued.Name != "laptop" || issued.Outlet != droids || time.Until(issued.ExpiresAt) > time.Hour {
		t.Errorf("create = %+v for the stored %+v", issued, stored)
	}
	if rr := f.asUser(f.auth.ApplicationTokens().Create(), sessionID, map[string]any{"name": "laptop", "outlet": robots}, nil); rr.Code != http.StatusBadRequest {
		t.Errorf("create for an unregistered outlet = %d, want 400", rr.Code)
	}

	// List: the row, never the secret or the hash.
	rr = f.asUser(f.auth.ApplicationTokens().List(), sessionID, nil, nil)
	if rr.Code != http.StatusOK {
		t.Fatalf("list = %d: %s", rr.Code, rr.Body)
	}
	var rows []map[string]any
	if err := json.Unmarshal(rr.Body.Bytes(), &rows); err != nil || len(rows) != 1 {
		t.Fatalf("list = %s, %v", rr.Body, err)
	}
	if rows[0]["id"] != stored.ID.String() || rows[0]["kind"] != "application" || rows[0]["name"] != "laptop" || rows[0]["outlet"] != droids {
		t.Errorf("list row = %v", rows[0])
	}
	for _, key := range []string{"token", "tokenHash", "TokenHash", "clientId", "lastUsedAt"} {
		if _, ok := rows[0][key]; ok {
			t.Errorf("list row carries %q", key)
		}
	}

	// Revoke: the person's token, and 404 for any other.
	if rr := f.asUser(f.auth.ApplicationTokens().Revoke(), sessionID, map[string]string{"id": stored.ID.String()}, nil); rr.Code != http.StatusOK {
		t.Errorf("revoke = %d: %s", rr.Code, rr.Body)
	}
	if rr := f.asUser(f.auth.ApplicationTokens().Revoke(), sessionID, map[string]string{"id": ccc.Must(ccc.NewUUID()).String()}, nil); rr.Code != http.StatusNotFound {
		t.Errorf("revoke of another token = %d, want 404: %s", rr.Code, rr.Body)
	}
}
