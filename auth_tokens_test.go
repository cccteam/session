package session

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/cccteam/ccc"
	"github.com/cccteam/httpio"
	"github.com/cccteam/session/sessioninfo"
	"github.com/cccteam/session/sessionstorage"
	"github.com/go-playground/errors/v5"
	"github.com/google/go-cmp/cmp"
	gomock "go.uber.org/mock/gomock"
)

const (
	droids = "droids"
	robots = "robots"
)

// tokenFixture is an authFixture with the droids outlet registered.
type tokenFixture struct {
	*authFixture
	outlet *MachineOutlet
	user   *sessionstorage.SessionUser
}

func newTokenFixture(t *testing.T, ctrl *gomock.Controller, options ...AuthOption) *tokenFixture {
	t.Helper()

	f := newAuthFixture(t, ctrl, options...)
	userID, _ := newIDs()

	return &tokenFixture{authFixture: f, outlet: RegisterMachineOutlet(f.auth, droids), user: pat(userID)}
}

// liveToken is a live application token of the fixture's user for outlet.
func (f *tokenFixture) liveToken(kind sessionstorage.TokenKind, outlet string) (secret string, tok *sessionstorage.Token) {
	secret = "secret-" + ccc.Must(ccc.NewUUID()).String()
	tok = &sessionstorage.Token{
		ID: ccc.Must(ccc.NewUUID()), TokenHash: hashToken(secret), Kind: kind, UserID: f.user.ID, Outlet: outlet, Name: "laptop",
		CreatedAt: time.Now().Add(-time.Hour), ExpiresAt: time.Now().Add(time.Hour),
	}

	return secret, tok
}

// bearer sends a request to h on the outlet, carrying authorization when set.
func (f *tokenFixture) bearer(h http.Handler, authorization string) *httptest.ResponseRecorder {
	r := httptest.NewRequestWithContext(context.Background(), http.MethodGet, "/droids/whoami", http.NoBody)
	if authorization != "" {
		r.Header.Set("Authorization", authorization)
	}
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, r)

	return rr
}

func TestRegisterMachineOutlet(t *testing.T) {
	t.Parallel()

	t.Run("a registered outlet carries its name, and a second outlet registers beside it", func(t *testing.T) {
		t.Parallel()
		f := newTokenFixture(t, gomock.NewController(t))
		if f.outlet.Name() != droids {
			t.Errorf("Name() = %q, want %q", f.outlet.Name(), droids)
		}
		if got := RegisterMachineOutlet(f.auth, robots).Name(); got != robots {
			t.Errorf("Name() = %q, want %q", got, robots)
		}
		if !f.auth.registered().outlets[droids] || !f.auth.registered().outlets[robots] {
			t.Errorf("outlets = %v, want both registered", f.auth.registered().outlets)
		}
	})

	for _, tt := range []struct {
		name string
		at   string
		want string
	}{
		{name: "an empty name panics", at: "", want: "is not an identifier"},
		{name: "a name with a slash panics", at: "api/droids", want: "is not an identifier"},
		{name: "a name registered twice panics", at: droids, want: "registered twice"},
	} {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			f := newTokenFixture(t, gomock.NewController(t))
			defer func() {
				msg, _ := recover().(string)
				if !strings.Contains(msg, tt.want) {
					t.Errorf("panic = %q, want it to contain %q", msg, tt.want)
				}
			}()
			RegisterMachineOutlet(f.auth, tt.at)
		})
	}

	t.Run("an outlet registered once the Auth is in use panics", func(t *testing.T) {
		t.Parallel()
		f := newTokenFixture(t, gomock.NewController(t))
		f.auth.registered()
		defer func() {
			msg, _ := recover().(string)
			if !strings.Contains(msg, "after the Auth is in use") {
				t.Errorf("panic = %q, want the in-use refusal", msg)
			}
		}()
		RegisterMachineOutlet(f.auth, robots)
	})
}

// tokenSeen is what the handler behind ValidateToken saw.
type tokenSeen struct {
	sessionID ccc.UUID
	user      *sessioninfo.UserInfo
	token     *sessioninfo.TokenInfo
	events    []sessioninfo.AuthEvent
}

func TestMachineOutlet_ValidateToken(t *testing.T) {
	t.Parallel()

	type testCase struct {
		name          string
		authorization func(secret string) string
		kind          sessionstorage.TokenKind
		outlet        string
		unknown       bool
		lastUsed      *time.Time
		user          func(u *sessionstorage.SessionUser)
		wantStatus    int
		wantChallenge string
		wantCode      string
		wantTouch     bool
	}
	recent := time.Now().Add(-10 * time.Second)
	stale := time.Now().Add(-2 * time.Minute)
	tests := []testCase{
		{
			name: "a request without a bearer token is refused with the challenge alone", authorization: func(string) string { return "" },
			kind: sessionstorage.TokenApplication, outlet: droids, wantStatus: http.StatusUnauthorized, wantChallenge: `Bearer realm="droids"`,
		},
		{
			name: "a basic credential is no bearer token", authorization: func(string) string { return "Basic cGF0OnB3" },
			kind: sessionstorage.TokenApplication, outlet: droids, wantStatus: http.StatusUnauthorized, wantChallenge: `Bearer realm="droids"`,
		},
		{
			name: "an unknown token is refused as invalid", authorization: func(string) string { return "Bearer nope" },
			kind: sessionstorage.TokenApplication, outlet: droids, unknown: true, wantStatus: http.StatusUnauthorized, wantChallenge: `Bearer realm="droids", error="invalid_token"`,
		},
		{
			name: "a token issued for another outlet is refused", authorization: func(s string) string { return "Bearer " + s },
			kind: sessionstorage.TokenApplication, outlet: robots, wantStatus: http.StatusUnauthorized, wantChallenge: `Bearer realm="droids", error="invalid_token"`,
		},
		{
			name: "a refresh token is refused on the outlet", authorization: func(s string) string { return "Bearer " + s },
			kind: sessionstorage.TokenRefresh, outlet: droids, wantStatus: http.StatusUnauthorized, wantChallenge: `Bearer realm="droids", error="invalid_token"`,
		},
		{
			name: "a disabled person's token is refused", authorization: func(s string) string { return "Bearer " + s },
			kind: sessionstorage.TokenApplication, outlet: droids, user: func(u *sessionstorage.SessionUser) { u.Disabled = true },
			wantStatus: http.StatusUnauthorized, wantChallenge: `Bearer realm="droids", error="invalid_token"`,
		},
		{
			name: "a person under the password change mark is refused with the mark's code", authorization: func(s string) string { return "Bearer " + s },
			kind: sessionstorage.TokenApplication, outlet: droids, user: func(u *sessionstorage.SessionUser) { u.PasswordChangeRequired = true },
			wantStatus: http.StatusForbidden, wantCode: "password_change_required",
		},
		{
			name: "an application token never used binds the request to its person and is touched", authorization: func(s string) string { return "bearer " + s },
			kind: sessionstorage.TokenApplication, outlet: droids, wantStatus: http.StatusOK, wantTouch: true,
		},
		{
			name: "an access token used a minute ago is touched again", authorization: func(s string) string { return "Bearer " + s },
			kind: sessionstorage.TokenAccess, outlet: droids, lastUsed: &stale, wantStatus: http.StatusOK, wantTouch: true,
		},
		{
			name: "a token used seconds ago is not touched", authorization: func(s string) string { return "Bearer  " + s + " " },
			kind: sessionstorage.TokenAccess, outlet: droids, lastUsed: &recent, wantStatus: http.StatusOK,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			f := newTokenFixture(t, gomock.NewController(t))
			secret, tok := f.liveToken(tt.kind, tt.outlet)
			tok.LastUsedAt = tt.lastUsed
			if tt.user != nil {
				tt.user(f.user)
			}
			if tt.unknown {
				f.store.EXPECT().Token(gomock.Any(), gomock.Any()).Return(nil, httpio.NewNotFoundMessage("no token")).AnyTimes()
			} else {
				f.store.EXPECT().Token(gomock.Any(), tok.TokenHash).Return(tok, nil).AnyTimes()
			}
			f.store.EXPECT().User(gomock.Any(), f.user.ID).Return(f.user, nil).AnyTimes()
			touched := 0
			f.store.EXPECT().TouchToken(gomock.Any(), tok.ID).DoAndReturn(func(context.Context, ccc.UUID) error {
				touched++

				return nil
			}).AnyTimes()

			var seen *tokenSeen
			h := f.outlet.ValidateToken(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				token, _ := sessioninfo.TokenFromRequest(r)
				seen = &tokenSeen{sessionID: sessioninfo.IDFromRequest(r), user: sessioninfo.UserFromRequest(r), token: token, events: sessioninfo.DataFromCtx(r.Context()).AuthEvents}
				w.WriteHeader(http.StatusOK)
			}))
			rr := f.bearer(h, tt.authorization(secret))
			if rr.Code != tt.wantStatus {
				t.Fatalf("status = %d, want %d: %s", rr.Code, tt.wantStatus, rr.Body)
			}
			if got := rr.Header().Get("WWW-Authenticate"); got != tt.wantChallenge {
				t.Errorf("WWW-Authenticate = %q, want %q", got, tt.wantChallenge)
			}
			if tt.wantCode != "" {
				var body struct {
					Code string `json:"code"`
				}
				_ = json.Unmarshal(rr.Body.Bytes(), &body)
				if body.Code != tt.wantCode {
					t.Errorf("code = %q, want %q: %s", body.Code, tt.wantCode, rr.Body)
				}
			}
			if (touched == 1) != tt.wantTouch {
				t.Errorf("TouchToken calls = %d, wantTouch %v", touched, tt.wantTouch)
			}
			if tt.wantStatus != http.StatusOK {
				if seen != nil {
					t.Error("the handler ran on a refused request")
				}

				return
			}
			want := &tokenSeen{
				sessionID: tok.ID, user: &sessioninfo.UserInfo{ID: f.user.ID, Username: "pat"},
				token:  &sessioninfo.TokenInfo{ID: tok.ID, Kind: string(tt.kind), Name: "laptop", Outlet: droids},
				events: []sessioninfo.AuthEvent{{Method: sessioninfo.MethodToken, Connection: string(tt.kind), At: tok.CreatedAt}},
			}
			if diff := cmp.Diff(want, seen, cmp.AllowUnexported(tokenSeen{})); diff != "" {
				t.Errorf("the handler saw (-want +got):\n%s", diff)
			}
		})
	}
}

func TestAuthAPI_CreateApplicationToken(t *testing.T) {
	t.Parallel()

	t.Run("the token is issued once as a secret, stored hashed for the outlet and the person, and handed back without its hash", func(t *testing.T) {
		t.Parallel()
		f := newTokenFixture(t, gomock.NewController(t), WithTokenLifetimes(time.Hour, 24*time.Hour, 48*time.Hour))
		f.store.EXPECT().User(gomock.Any(), f.user.ID).Return(f.user, nil)
		var stored *sessionstorage.Token
		f.store.EXPECT().InsertToken(gomock.Any(), gomock.Any()).DoAndReturn(func(_ context.Context, tok *sessionstorage.Token) error {
			stored = tok

			return nil
		})

		issued, err := f.auth.API().CreateApplicationToken(context.Background(), &ApplicationTokenRequest{UserID: f.user.ID, Outlet: droids, Name: "  laptop ", ExpiresIn: time.Hour})
		if err != nil {
			t.Fatalf("CreateApplicationToken() error = %v", err)
		}
		if sum := sha256.Sum256([]byte(issued.Secret)); !bytes.Equal(sum[:], stored.TokenHash) {
			t.Error("the stored hash is not the secret's")
		}
		if stored.Kind != sessionstorage.TokenApplication || stored.UserID != f.user.ID || stored.Outlet != droids || stored.Name != "laptop" || stored.Family.Valid {
			t.Errorf("stored = %+v", stored)
		}
		if until := time.Until(stored.ExpiresAt); until < 59*time.Minute || until > time.Hour {
			t.Errorf("ExpiresAt in %s, want about an hour", until)
		}
		if issued.Token.TokenHash != nil || issued.Token.ID != stored.ID {
			t.Errorf("issued.Token = %+v, want the row without its hash", issued.Token)
		}
	})

	t.Run("no lifetime takes the Auth's application token lifetime", func(t *testing.T) {
		t.Parallel()
		f := newTokenFixture(t, gomock.NewController(t), WithTokenLifetimes(time.Hour, 24*time.Hour, 48*time.Hour))
		f.store.EXPECT().User(gomock.Any(), f.user.ID).Return(f.user, nil)
		var stored *sessionstorage.Token
		f.store.EXPECT().InsertToken(gomock.Any(), gomock.Any()).DoAndReturn(func(_ context.Context, tok *sessionstorage.Token) error {
			stored = tok

			return nil
		})
		if _, err := f.auth.API().CreateApplicationToken(context.Background(), &ApplicationTokenRequest{UserID: f.user.ID, Outlet: droids, Name: "ci"}); err != nil {
			t.Fatalf("CreateApplicationToken() error = %v", err)
		}
		if until := time.Until(stored.ExpiresAt); until < 47*time.Hour || until > 48*time.Hour {
			t.Errorf("ExpiresAt in %s, want about two days", until)
		}
	})

	for _, tt := range []struct {
		name    string
		req     func(f *tokenFixture) *ApplicationTokenRequest
		disable bool
		want    string
	}{
		{name: "an outlet that is not registered is refused", req: func(f *tokenFixture) *ApplicationTokenRequest {
			return &ApplicationTokenRequest{UserID: f.user.ID, Outlet: robots, Name: "ci"}
		}, want: "not a machine outlet"},
		{name: "a token without a name is refused", req: func(f *tokenFixture) *ApplicationTokenRequest {
			return &ApplicationTokenRequest{UserID: f.user.ID, Outlet: droids, Name: "  "}
		}, want: "needs a name"},
		{name: "a lifetime past the Auth's is refused", req: func(f *tokenFixture) *ApplicationTokenRequest {
			return &ApplicationTokenRequest{UserID: f.user.ID, Outlet: droids, Name: "ci", ExpiresIn: 49 * time.Hour}
		}, want: "lives at most"},
		{name: "a disabled person is refused", req: func(f *tokenFixture) *ApplicationTokenRequest {
			return &ApplicationTokenRequest{UserID: f.user.ID, Outlet: droids, Name: "ci"}
		}, disable: true, want: "disabled"},
	} {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			f := newTokenFixture(t, gomock.NewController(t), WithTokenLifetimes(time.Hour, 24*time.Hour, 48*time.Hour))
			f.user.Disabled = tt.disable
			f.store.EXPECT().User(gomock.Any(), f.user.ID).Return(f.user, nil).AnyTimes()

			_, err := f.auth.API().CreateApplicationToken(context.Background(), tt.req(f))
			if !httpio.HasBadRequest(err) || !strings.Contains(httpio.Message(err), tt.want) {
				t.Errorf("CreateApplicationToken() error = %v, want a bad request about %q", err, tt.want)
			}
		})
	}
}

func TestAuthAPI_TokensAndRevocation(t *testing.T) {
	t.Parallel()

	t.Run("the listing hands rows out without their hashes", func(t *testing.T) {
		t.Parallel()
		f := newTokenFixture(t, gomock.NewController(t))
		_, tok := f.liveToken(sessionstorage.TokenApplication, droids)
		f.store.EXPECT().Tokens(gomock.Any(), f.user.ID).Return([]*sessionstorage.Token{tok}, nil)

		rows, err := f.auth.API().Tokens(context.Background(), f.user.ID)
		if err != nil {
			t.Fatalf("Tokens() error = %v", err)
		}
		if len(rows) != 1 || rows[0].TokenHash != nil || rows[0].ID != tok.ID || tok.TokenHash == nil {
			t.Errorf("Tokens() = %+v, want the row without its hash and the store's row intact", rows)
		}
	})

	t.Run("a revocation by hand and a person's revocation carry their reasons", func(t *testing.T) {
		t.Parallel()
		f := newTokenFixture(t, gomock.NewController(t))
		id := ccc.Must(ccc.NewUUID())
		f.store.EXPECT().RevokeUserToken(gomock.Any(), f.user.ID, id, sessionstorage.TokenRevokedByHand).Return(nil)
		f.store.EXPECT().RevokeUserTokens(gomock.Any(), f.user.ID, sessionstorage.TokenRevokedWithUser).Return(nil)
		if err := f.auth.API().RevokeToken(context.Background(), f.user.ID, id); err != nil {
			t.Errorf("RevokeToken() error = %v", err)
		}
		if err := f.auth.API().RevokeUserTokens(context.Background(), f.user.ID); err != nil {
			t.Errorf("RevokeUserTokens() error = %v", err)
		}
	})

	t.Run("a token that is not the person's is NotFound", func(t *testing.T) {
		t.Parallel()
		f := newTokenFixture(t, gomock.NewController(t))
		id := ccc.Must(ccc.NewUUID())
		f.store.EXPECT().RevokeUserToken(gomock.Any(), f.user.ID, id, sessionstorage.TokenRevokedByHand).Return(httpio.NewNotFoundMessage("no live token"))
		if err := f.auth.API().RevokeToken(context.Background(), f.user.ID, id); !httpio.HasNotFound(err) {
			t.Errorf("RevokeToken() error = %v, want NotFound", err)
		}
	})
}

func TestAuthAPI_DeviceFlow(t *testing.T) {
	t.Parallel()

	t.Run("a device authorization stores the hashed device code and a normalized user code, and tells the client the formatted code and the page", authAPIDeviceCase1)
	t.Run("an authorization without a client or for an unregistered outlet is refused", authAPIDeviceCase2)
	t.Run("a redeemed authorization hands the client the pair the store took, in one family, and any other status no pair", authAPIDeviceCase3)
	t.Run("a refresh hands the next pair, a token that is not a live refresh is NotFound, and a reuse is an unauthorized refusal carrying the store's error", authAPIDeviceCase4)
	t.Run("the person's code is normalized before the lookup, the approval and the denial", authAPIDeviceCase5)
}

func authAPIDeviceCase1(t *testing.T) {
	t.Parallel()
	f := newTokenFixture(t, gomock.NewController(t), WithDeviceCodeLifetime(5*time.Minute, 2*time.Second), WithDeviceVerificationURL("/settings/device"))
	var stored *sessionstorage.DeviceCode
	f.store.EXPECT().InsertDeviceCode(gomock.Any(), gomock.Any()).DoAndReturn(func(_ context.Context, code *sessionstorage.DeviceCode) error {
		stored = code

		return nil
	})

	auth, err := f.auth.API().StartDeviceAuthorization(context.Background(), &DeviceAuthorizationRequest{ClientID: "corral", Outlet: droids})
	if err != nil {
		t.Fatalf("StartDeviceAuthorization() error = %v", err)
	}
	if sum := sha256.Sum256([]byte(auth.DeviceCode)); !bytes.Equal(sum[:], stored.DeviceCodeHash) {
		t.Error("the stored hash is not the device code's")
	}
	if len(stored.UserCode) != userCodeLength || strings.Trim(stored.UserCode, userCodeAlphabet) != "" {
		t.Errorf("stored user code = %q, want eight letters of %q", stored.UserCode, userCodeAlphabet)
	}
	if stored.ClientID != "corral" || stored.Outlet != droids || stored.UserID.Valid {
		t.Errorf("stored = %+v", stored)
	}
	if until := time.Until(stored.ExpiresAt); until < 4*time.Minute || until > 5*time.Minute {
		t.Errorf("ExpiresAt in %s, want about five minutes", until)
	}
	want := &DeviceAuthorization{
		DeviceCode: auth.DeviceCode, UserCode: stored.UserCode[:4] + "-" + stored.UserCode[4:],
		VerificationURI: "/settings/device", VerificationURIComplete: "/settings/device?userCode=" + stored.UserCode[:4] + "-" + stored.UserCode[4:],
		ExpiresIn: 5 * time.Minute, Interval: 2 * time.Second,
	}
	if diff := cmp.Diff(want, auth); diff != "" {
		t.Errorf("StartDeviceAuthorization() mismatch (-want +got):\n%s", diff)
	}
}

func authAPIDeviceCase2(t *testing.T) {
	t.Parallel()
	f := newTokenFixture(t, gomock.NewController(t))
	for _, req := range []*DeviceAuthorizationRequest{{ClientID: " ", Outlet: droids}, {ClientID: "corral", Outlet: robots}} {
		if _, err := f.auth.API().StartDeviceAuthorization(context.Background(), req); !httpio.HasBadRequest(err) {
			t.Errorf("StartDeviceAuthorization(%+v) error = %v, want a bad request", req, err)
		}
	}
}

func authAPIDeviceCase3(t *testing.T) {
	t.Parallel()
	f := newTokenFixture(t, gomock.NewController(t), WithTokenLifetimes(time.Hour, 24*time.Hour, 48*time.Hour), WithDeviceCodeLifetime(5*time.Minute, 2*time.Second))
	var access, refresh *sessionstorage.Token
	status := sessionstorage.DevicePending
	f.store.EXPECT().RedeemDeviceCode(gomock.Any(), hashToken("device-1"), 2*time.Second, gomock.Any(), gomock.Any()).
		DoAndReturn(func(_ context.Context, _ []byte, _ time.Duration, a, r *sessionstorage.Token) (*sessionstorage.DeviceCode, sessionstorage.DeviceCodeStatus, error) {
			access, refresh = a, r

			return &sessionstorage.DeviceCode{}, status, nil
		}).Times(2)

	pair, got, err := f.auth.API().RedeemDeviceCode(context.Background(), "device-1")
	if err != nil || got != sessionstorage.DevicePending || pair != nil {
		t.Fatalf("RedeemDeviceCode() = %+v, %q, %v; want no pair, pending", pair, got, err)
	}
	status = sessionstorage.DeviceApproved
	pair, got, err = f.auth.API().RedeemDeviceCode(context.Background(), "device-1")
	if err != nil || got != sessionstorage.DeviceApproved || pair == nil {
		t.Fatalf("RedeemDeviceCode() = %+v, %q, %v; want the pair, approved", pair, got, err)
	}
	if !bytes.Equal(hashToken(pair.AccessToken), access.TokenHash) || !bytes.Equal(hashToken(pair.RefreshToken), refresh.TokenHash) {
		t.Error("the pair's secrets are not the hashes the store took")
	}
	if access.Kind != sessionstorage.TokenAccess || refresh.Kind != sessionstorage.TokenRefresh || !access.Family.Valid || access.Family != refresh.Family {
		t.Errorf("access = %+v, refresh = %+v; want one family", access, refresh)
	}
	if pair.ExpiresIn != time.Hour || time.Until(access.ExpiresAt) > time.Hour || time.Until(refresh.ExpiresAt) < 23*time.Hour {
		t.Errorf("lifetimes: ExpiresIn %s, access %s, refresh %s", pair.ExpiresIn, time.Until(access.ExpiresAt), time.Until(refresh.ExpiresAt))
	}
}

func authAPIDeviceCase4(t *testing.T) {
	t.Parallel()
	f := newTokenFixture(t, gomock.NewController(t))
	gomock.InOrder(
		f.store.EXPECT().ExchangeRefreshToken(gomock.Any(), hashToken("refresh-1"), gomock.Any(), gomock.Any()).Return(nil),
		f.store.EXPECT().ExchangeRefreshToken(gomock.Any(), hashToken("refresh-2"), gomock.Any(), gomock.Any()).Return(httpio.NewNotFoundMessage("no live refresh token")),
		f.store.EXPECT().ExchangeRefreshToken(gomock.Any(), hashToken("refresh-1"), gomock.Any(), gomock.Any()).Return(errors.Wrap(sessionstorage.ErrTokenReuse, "family revoked")),
	)
	pair, err := f.auth.API().RefreshTokens(context.Background(), "refresh-1")
	if err != nil || pair.AccessToken == "" || pair.RefreshToken == "" {
		t.Fatalf("RefreshTokens() = %+v, %v", pair, err)
	}
	if _, err := f.auth.API().RefreshTokens(context.Background(), "refresh-2"); !httpio.HasNotFound(err) {
		t.Errorf("RefreshTokens(unknown) error = %v, want NotFound", err)
	}
	_, err = f.auth.API().RefreshTokens(context.Background(), "refresh-1")
	if !httpio.HasUnauthorized(err) || !errors.Is(err, sessionstorage.ErrTokenReuse) {
		t.Errorf("RefreshTokens(reused) error = %v, want Unauthorized wrapping ErrTokenReuse", err)
	}
}

func authAPIDeviceCase5(t *testing.T) {
	t.Parallel()
	f := newTokenFixture(t, gomock.NewController(t))
	code := &sessionstorage.DeviceCode{ID: ccc.Must(ccc.NewUUID()), DeviceCodeHash: []byte("hash"), UserCode: "BCDFGHJK", ClientID: "corral", Outlet: droids}
	f.store.EXPECT().DeviceCode(gomock.Any(), "BCDFGHJK").Return(code, nil).Times(3)
	f.store.EXPECT().ApproveDeviceCode(gomock.Any(), code.ID, f.user.ID).Return(nil)
	f.store.EXPECT().DenyDeviceCode(gomock.Any(), code.ID).Return(nil)

	pending, err := f.auth.API().PendingDevice(context.Background(), " bcdf-ghjk ")
	if err != nil || pending.DeviceCodeHash != nil || pending.ClientID != "corral" {
		t.Errorf("PendingDevice() = %+v, %v; want the row without its hash", pending, err)
	}
	if err := f.auth.API().ApproveDevice(context.Background(), f.user.ID, "bcdf ghjk"); err != nil {
		t.Errorf("ApproveDevice() error = %v", err)
	}
	if err := f.auth.API().DenyDevice(context.Background(), "BCDF-GHJK"); err != nil {
		t.Errorf("DenyDevice() error = %v", err)
	}
}

func TestAuth_TokenOptions(t *testing.T) {
	t.Parallel()

	for _, tt := range []struct {
		name    string
		options []AuthOption
		want    string
	}{
		{name: "a zero access lifetime", options: []AuthOption{WithTokenLifetimes(0, time.Hour, time.Hour)}, want: "access token lifetime must be positive"},
		{name: "a refresh lifetime under the access lifetime", options: []AuthOption{WithTokenLifetimes(2*time.Hour, time.Hour, time.Hour)}, want: "at least the access token lifetime"},
		{name: "a negative poll interval", options: []AuthOption{WithDeviceCodeLifetime(time.Minute, -time.Second)}, want: "poll interval must be positive"},
		{name: "a verification URL that leaves the application", options: []AuthOption{WithDeviceVerificationURL("https://evil.example/device")}, want: "must be a path in the application"},
		{name: "a verification URL that is the root", options: []AuthOption{WithDeviceVerificationURL("/")}, want: "must be a path in the application"},
	} {
		t.Run(tt.name+" is refused by NewAuth", func(t *testing.T) {
			t.Parallel()
			_, err := NewAuth[NoCustomData, NoCustomData](newAuthStoreMock(gomock.NewController(t)), cookieKey, tt.options...)
			if err == nil || !strings.Contains(err.Error(), tt.want) {
				t.Errorf("NewAuth() error = %v, want it to mention %q", err, tt.want)
			}
		})
	}

	t.Run("the table names reach the store", func(t *testing.T) {
		t.Parallel()
		store := newAuthStoreMock(gomock.NewController(t))
		store.EXPECT().SetTokensTableName("AppTokens").Return(nil)
		store.EXPECT().SetDeviceCodesTableName("AppDeviceCodes").Return(nil)
		if _, err := NewAuth[NoCustomData, NoCustomData](store, cookieKey, WithTokensTableName("AppTokens"), WithDeviceCodesTableName("AppDeviceCodes")); err != nil {
			t.Errorf("NewAuth() error = %v", err)
		}
	})
}

func Test_userCodes(t *testing.T) {
	t.Parallel()

	codes := map[string]bool{}
	for range 50 {
		code, err := newUserCode()
		if err != nil {
			t.Fatalf("newUserCode() error = %v", err)
		}
		if len(code) != userCodeLength || strings.Trim(code, userCodeAlphabet) != "" {
			t.Fatalf("newUserCode() = %q, want eight letters of %q", code, userCodeAlphabet)
		}
		codes[code] = true
		if got := normalizeUserCode(strings.ToLower(formatUserCode(code))); got != code {
			t.Errorf("normalizeUserCode(formatUserCode(%q)) = %q", code, got)
		}
	}
	if len(codes) != 50 {
		t.Errorf("50 codes drew %d distinct", len(codes))
	}
	if got := formatUserCode("BCDFGHJK"); got != "BCDF-GHJK" {
		t.Errorf("formatUserCode() = %q", got)
	}
	if got := normalizeUserCode(" bc-df gh_jk! "); got != "BCDFGHJK" {
		t.Errorf("normalizeUserCode() = %q", got)
	}
}

func Test_bearerToken(t *testing.T) {
	t.Parallel()

	for header, want := range map[string]string{"Bearer abc": "abc", "bearer abc": "abc", " Bearer  abc ": "abc", "Bearer": "", "Bearer ": "", "Basic abc": "", "": "", "Bearerabc": ""} {
		r := httptest.NewRequestWithContext(context.Background(), http.MethodGet, "/", http.NoBody)
		r.Header.Set("Authorization", header)
		got, ok := bearerToken(r)
		if got != want || ok != (want != "") {
			t.Errorf("bearerToken(%q) = %q, %v; want %q", header, got, ok, want)
		}
	}
}
