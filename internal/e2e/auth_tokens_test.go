package e2e

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/cccteam/ccc"
	"github.com/cccteam/httpio"
	"github.com/cccteam/session"
	"github.com/cccteam/session/sessioninfo"
	"github.com/go-chi/chi/v5"
	"github.com/google/go-cmp/cmp"
)

// The machine outlet scenarios: a person signs in through the browser as always; a
// program of theirs, or the command-line client the device flow authorizes, then calls
// the application's machine outlet with a bearer token the Auth issued, and no cookie.

// tokenApp is an authApp with two machine outlets, the device flow and the
// application token page mounted, and a machine client beside the browser.
type tokenApp[Tx any] struct {
	*authApp[Tx]
	machine *http.Client
}

// outletView is what the outlets' /whoami reports: the validated session as the
// handler sees it, and the token that authenticated it.
type outletView struct {
	sessionView
	TokenID string `json:"tokenId"`
	Kind    string `json:"kind"`
	Name    string `json:"name"`
	Client  string `json:"client"`
	Outlet  string `json:"outlet"`
}

func outletWhoami(w http.ResponseWriter, r *http.Request) {
	data := sessioninfo.DataFromCtx(r.Context())
	view := outletView{sessionView: sessionView{SessionID: data.ID.String(), Username: data.Username, User: sessioninfo.UserFromRequest(r).ID.String()}}
	if data.UserID.Valid {
		view.UserID = data.UserID.String()
	}
	for _, e := range data.AuthEvents {
		view.Events = append(view.Events, string(e.Method)+":"+e.Connection)
	}
	if tok, ok := sessioninfo.TokenFromRequest(r); ok {
		view.TokenID, view.Kind, view.Name, view.Client, view.Outlet = tok.ID.String(), tok.Kind, tok.Name, tok.ClientID, tok.Outlet
	}
	_ = httpio.NewEncoder(w).Ok(view)
}

// newTokenApp is an application with password sign-in, the droids and robots outlets,
// the device flow at a one-second poll interval and the token page, over be.
func newTokenApp[Tx any](ctx context.Context, t *testing.T, be backend[Tx]) *tokenApp[Tx] {
	t.Helper()

	h := &hooks[Tx]{rows: be.rows}
	db, store := be.newStore(ctx, t)
	auth, err := session.NewAuth[appSessionData, appUserData](withCustomData(t, store, h), cookieKey,
		session.WithIdentityLinked(h.identityLinked), session.WithPendingHook(h.pendingHook),
		session.WithDeviceCodeLifetime(10*time.Minute, time.Second))
	if err != nil {
		t.Fatalf("session.NewAuth() error = %v", err)
	}
	auth.SetSignInPolicy(h.signInPolicy)
	auth.SetSignedInHook(h.signedIn)
	password := session.PasswordSignIn(auth)
	droids := session.RegisterMachineOutlet(auth, "droids")
	robots := session.RegisterMachineOutlet(auth, "robots")

	root := chi.NewRouter()
	// The machine outlets and the device flow's public endpoints sit outside
	// StartSession: no cookie is read or written there.
	root.Route("/droids", func(r chi.Router) {
		r.Use(droids.ValidateToken)
		r.Get("/whoami", outletWhoami)
	})
	root.Route("/robots", func(r chi.Router) {
		r.Use(robots.ValidateToken)
		r.Get("/whoami", outletWhoami)
	})
	root.Post("/oauth/device/authorize", auth.Device().Authorize())
	root.Post("/oauth/token", auth.Device().Token())

	app := chi.NewRouter()
	mountAuth(app, auth, func(r chi.Router) {
		r.With(auth.ValidateXSRFToken).Post("/login", password.Login())
		r.Group(func(r chi.Router) {
			r.Use(auth.ValidateXSRFToken, auth.ValidateSession)
			r.Get("/tokens", auth.ApplicationTokens().List())
			r.Post("/tokens", auth.ApplicationTokens().Create())
			r.Post("/tokens/revoke", auth.ApplicationTokens().Revoke())
			r.Get("/device/lookup", auth.Device().Lookup())
			r.Post("/device/approve", auth.Device().Approve())
			r.Post("/device/deny", auth.Device().Deny())
		})
	})
	root.Mount("/", app)

	server := httptest.NewTLSServer(root)
	t.Cleanup(server.Close)
	machine := *server.Client()
	machine.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }

	return &tokenApp[Tx]{authApp: &authApp[Tx]{db: db, rows: be.rows, server: server, api: auth.API(), hooks: h}, machine: &machine}
}

// call sends a request as a program does: no cookie jar, the bearer token when set,
// and form-encoded fields when given.
func (a *tokenApp[Tx]) call(ctx context.Context, t *testing.T, method, path, bearer string, form url.Values) (status int, header http.Header, body []byte) {
	t.Helper()

	var payload io.Reader = http.NoBody
	if form != nil {
		payload = strings.NewReader(form.Encode())
	}
	req, err := http.NewRequestWithContext(ctx, method, a.server.URL+path, payload)
	if err != nil {
		t.Fatalf("http.NewRequestWithContext() error = %v", err)
	}
	if form != nil {
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	}
	if bearer != "" {
		req.Header.Set("Authorization", "Bearer "+bearer)
	}
	resp, err := a.machine.Do(req)
	if err != nil {
		t.Fatalf("%s %s error = %v", method, path, err)
	}
	defer resp.Body.Close()
	body, err = io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("io.ReadAll() error = %v", err)
	}

	return resp.StatusCode, resp.Header, body
}

// whoami calls an outlet's /whoami with bearer and returns the status, the challenge
// and the view.
func (a *tokenApp[Tx]) whoami(ctx context.Context, t *testing.T, outlet, bearer string) (status int, challenge string, view *outletView) {
	t.Helper()

	status, header, body := a.call(ctx, t, http.MethodGet, "/"+outlet+"/whoami", bearer, nil)
	if status != http.StatusOK {
		return status, header.Get("WWW-Authenticate"), nil
	}
	view = &outletView{}
	if err := json.Unmarshal(body, view); err != nil {
		t.Fatalf("json.Unmarshal(%s) error = %v", body, err)
	}

	return status, "", view
}

// deviceAuthorization is the device authorization endpoint's answer.
type deviceAuthorization struct {
	DeviceCode              string `json:"device_code"`
	UserCode                string `json:"user_code"`
	VerificationURI         string `json:"verification_uri"`
	VerificationURIComplete string `json:"verification_uri_complete"`
	ExpiresIn               int    `json:"expires_in"`
	Interval                int    `json:"interval"`
}

// tokenAnswer is the token endpoint's answer, a pair or an error.
type tokenAnswer struct {
	AccessToken  string `json:"access_token"`
	TokenType    string `json:"token_type"`
	ExpiresIn    int    `json:"expires_in"`
	RefreshToken string `json:"refresh_token"`
	Error        string `json:"error"`
}

// authorizeDevice starts a device authorization for client on outlet.
func (a *tokenApp[Tx]) authorizeDevice(ctx context.Context, t *testing.T, client, outlet string) *deviceAuthorization {
	t.Helper()

	status, header, body := a.call(ctx, t, http.MethodPost, "/oauth/device/authorize", "", url.Values{"client_id": {client}, "outlet": {outlet}})
	if status != http.StatusOK {
		t.Fatalf("device authorization = %d: %s", status, body)
	}
	if header.Get("Cache-Control") != "no-store" {
		t.Errorf("Cache-Control = %q, want no-store", header.Get("Cache-Control"))
	}
	auth := &deviceAuthorization{}
	if err := json.Unmarshal(body, auth); err != nil {
		t.Fatalf("json.Unmarshal(%s) error = %v", body, err)
	}

	return auth
}

// token posts a grant to the token endpoint.
func (a *tokenApp[Tx]) token(ctx context.Context, t *testing.T, form url.Values) (status int, answer *tokenAnswer) {
	t.Helper()

	status, _, body := a.call(ctx, t, http.MethodPost, "/oauth/token", "", form)
	answer = &tokenAnswer{}
	if err := json.Unmarshal(body, answer); err != nil {
		t.Fatalf("json.Unmarshal(%s) error = %v", body, err)
	}

	return status, answer
}

// poll polls a device authorization once.
func (a *tokenApp[Tx]) poll(ctx context.Context, t *testing.T, deviceCode string) (status int, answer *tokenAnswer) {
	t.Helper()

	return a.token(ctx, t, url.Values{"grant_type": {"urn:ietf:params:oauth:grant-type:device_code"}, "device_code": {deviceCode}})
}

// refresh exchanges a refresh token.
func (a *tokenApp[Tx]) refresh(ctx context.Context, t *testing.T, refreshToken string) (status int, answer *tokenAnswer) {
	t.Helper()

	return a.token(ctx, t, url.Values{"grant_type": {"refresh_token"}, "refresh_token": {refreshToken}})
}

// expectGrantError expects the token endpoint's 400 with code.
func (a *tokenApp[Tx]) expectGrantError(t *testing.T, status int, answer *tokenAnswer, code string) {
	t.Helper()

	if status != http.StatusBadRequest || answer.Error != code {
		t.Errorf("token endpoint = %d %+v, want 400 %s", status, answer, code)
	}
}

// approvedPair runs a device authorization for corral on droids through the person's
// approval in b to the pair the client receives.
func (a *tokenApp[Tx]) approvedPair(ctx context.Context, t *testing.T, b *browser) *tokenAnswer {
	t.Helper()

	auth := a.authorizeDevice(ctx, t, "corral", "droids")
	b.expect(ctx, http.StatusOK, http.MethodPost, "/device/approve", map[string]string{"userCode": auth.UserCode})
	time.Sleep(1100 * time.Millisecond)
	status, pair := a.poll(ctx, t, auth.DeviceCode)
	if status != http.StatusOK || pair.AccessToken == "" || pair.RefreshToken == "" {
		t.Fatalf("poll after approval = %d %+v, want the pair", status, pair)
	}

	return pair
}

// issuedToken is the token page's answer to a creation.
type issuedToken struct {
	ID     string `json:"id"`
	Token  string `json:"token"`
	Name   string `json:"name"`
	Outlet string `json:"outlet"`
}

// tokenRow is one row of the token page's listing.
type tokenRow struct {
	ID         string     `json:"id"`
	Kind       string     `json:"kind"`
	Name       string     `json:"name"`
	Outlet     string     `json:"outlet"`
	ClientID   string     `json:"clientId"`
	LastUsedAt *time.Time `json:"lastUsedAt"`
}

func (b *browser) createToken(ctx context.Context, name, outlet string) *issuedToken {
	b.t.Helper()

	issued := &issuedToken{}
	if err := json.Unmarshal(b.expect(ctx, http.StatusOK, http.MethodPost, "/tokens", map[string]any{"name": name, "outlet": outlet}), issued); err != nil {
		b.t.Fatalf("json.Unmarshal() error = %v", err)
	}

	return issued
}

func (b *browser) tokens(ctx context.Context) []tokenRow {
	b.t.Helper()

	var rows []tokenRow
	if err := json.Unmarshal(b.expect(ctx, http.StatusOK, http.MethodGet, "/tokens", nil), &rows); err != nil {
		b.t.Fatalf("json.Unmarshal() error = %v", err)
	}

	return rows
}

func TestAuthSeams_MachineTokens(t *testing.T) {
	t.Parallel()

	t.Run(postgresBackend.name, func(t *testing.T) {
		t.Parallel()
		runTokenSeams(t, postgresBackend)
	})
	t.Run(spannerBackend.name, func(t *testing.T) {
		t.Parallel()
		runTokenSeams(t, spannerBackend)
	})
}

func runTokenSeams[Tx any](t *testing.T, be backend[Tx]) {
	tests := []struct {
		name string
		run  func(ctx context.Context, t *testing.T, a *tokenApp[Tx])
	}{
		{
			name: "an application token a signed-in person issues acts as them on its outlet alone, is listed as used, and dies with its revocation",
			run:  seamApplicationToken[Tx],
		},
		{
			name: "the device flow: the client's codes, the person's approval as typed, the pair once, and the access token that acts as the person",
			run:  seamDeviceFlow[Tx],
		},
		{
			name: "a refresh rotates the pair, a reuse of the rotated token revokes the family, and the token endpoint refuses what is not a grant",
			run:  seamDeviceRotation[Tx],
		},
		{
			name: "a denied authorization is told so, a revocation by hand takes the grant's family, and a disabled person's token is refused",
			run:  seamDeviceDeniedRevokedDisabled[Tx],
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			ctx := t.Context()
			tt.run(ctx, t, newTokenApp(ctx, t, be))
		})
	}
}

func seamApplicationToken[Tx any](ctx context.Context, t *testing.T, a *tokenApp[Tx]) {
	t.Helper()

	pat := a.seed(ctx, t, "pat@lakeside.edu")
	b := a.browser(t)
	b.prime(ctx)
	if status, _ := b.passwordLogin(ctx, seedPassword); status != http.StatusOK {
		t.Fatalf("password login = %d", status)
	}

	issued := b.createToken(ctx, "laptop", "droids")
	if issued.Token == "" || issued.Name != "laptop" || issued.Outlet != "droids" {
		t.Fatalf("created = %+v", issued)
	}
	b.expect(ctx, http.StatusBadRequest, http.MethodPost, "/tokens", map[string]any{"name": "ci", "outlet": "nope"})

	status, _, view := a.whoami(ctx, t, "droids", issued.Token)
	if status != http.StatusOK {
		t.Fatalf("bearer call = %d", status)
	}
	want := &outletView{
		sessionView: sessionView{SessionID: issued.ID, UserID: pat.String(), Username: "pat@lakeside.edu", User: pat.String(), Events: []string{"token:application"}},
		TokenID:     issued.ID, Kind: "application", Name: "laptop", Outlet: "droids",
	}
	if diff := cmp.Diff(want, view, cmp.AllowUnexported(outletView{})); diff != "" {
		t.Errorf("bearer view mismatch (-want +got):\n%s", diff)
	}

	if status, challenge, _ := a.whoami(ctx, t, "robots", issued.Token); status != http.StatusUnauthorized || challenge != `Bearer realm="robots", error="invalid_token"` {
		t.Errorf("the token on another outlet = %d %q, want 401 with the invalid_token challenge", status, challenge)
	}
	if status, challenge, _ := a.whoami(ctx, t, "droids", ""); status != http.StatusUnauthorized || challenge != `Bearer realm="droids"` {
		t.Errorf("no token = %d %q, want 401 with the bare challenge", status, challenge)
	}
	if status, _, _ := a.whoami(ctx, t, "droids", issued.Token+"x"); status != http.StatusUnauthorized {
		t.Errorf("a wrong token = %d, want 401", status)
	}

	rows := b.tokens(ctx)
	if len(rows) != 1 || rows[0].ID != issued.ID || rows[0].Kind != "application" || rows[0].Name != "laptop" || rows[0].LastUsedAt == nil {
		t.Errorf("listing = %+v, want the used token", rows)
	}

	b.expect(ctx, http.StatusOK, http.MethodPost, "/tokens/revoke", map[string]string{"id": issued.ID})
	if status, _, _ := a.whoami(ctx, t, "droids", issued.Token); status != http.StatusUnauthorized {
		t.Errorf("the revoked token = %d, want 401", status)
	}
	if rows := b.tokens(ctx); len(rows) != 0 {
		t.Errorf("listing after the revocation = %+v, want none", rows)
	}
	b.expect(ctx, http.StatusNotFound, http.MethodPost, "/tokens/revoke", map[string]string{"id": issued.ID})
	b.expect(ctx, http.StatusNotFound, http.MethodPost, "/tokens/revoke", map[string]string{"id": ccc.Must(ccc.NewUUID()).String()})
}

func seamDeviceFlow[Tx any](ctx context.Context, t *testing.T, a *tokenApp[Tx]) {
	t.Helper()

	pat := a.seed(ctx, t, "pat@lakeside.edu")
	b := a.browser(t)
	b.prime(ctx)
	if status, _ := b.passwordLogin(ctx, seedPassword); status != http.StatusOK {
		t.Fatalf("password login = %d", status)
	}

	// The client starts and is told the codes.
	auth := a.authorizeDevice(ctx, t, "corral", "droids")
	if len(auth.UserCode) != 9 || auth.UserCode[4] != '-' {
		t.Errorf("user code = %q, want XXXX-XXXX", auth.UserCode)
	}
	wantAuth := &deviceAuthorization{
		DeviceCode: auth.DeviceCode, UserCode: auth.UserCode, VerificationURI: "/device", VerificationURIComplete: "/device?userCode=" + auth.UserCode,
		ExpiresIn: 600, Interval: 1,
	}
	if diff := cmp.Diff(wantAuth, auth); diff != "" {
		t.Errorf("authorization mismatch (-want +got):\n%s", diff)
	}
	if status, _, body := a.call(ctx, t, http.MethodPost, "/oauth/device/authorize", "", url.Values{"client_id": {"corral"}, "outlet": {"nope"}}); status != http.StatusBadRequest || !strings.Contains(string(body), "invalid_request") {
		t.Errorf("authorization for an unregistered outlet = %d %s", status, body)
	}

	// It polls: pending, then too soon.
	status, answer := a.poll(ctx, t, auth.DeviceCode)
	a.expectGrantError(t, status, answer, "authorization_pending")
	status, answer = a.poll(ctx, t, auth.DeviceCode)
	a.expectGrantError(t, status, answer, "slow_down")

	// The person looks the code up as typed, approves once.
	var pending struct {
		ClientID string `json:"clientId"`
		Outlet   string `json:"outlet"`
	}
	if err := json.Unmarshal(b.expect(ctx, http.StatusOK, http.MethodGet, "/device/lookup?userCode="+url.QueryEscape(strings.ToLower(auth.UserCode)), nil), &pending); err != nil {
		t.Fatalf("json.Unmarshal() error = %v", err)
	}
	if pending.ClientID != "corral" || pending.Outlet != "droids" {
		t.Errorf("lookup = %+v, want corral on droids", pending)
	}
	b.expect(ctx, http.StatusNotFound, http.MethodGet, "/device/lookup?userCode=XXXX-XXXX", nil)
	b.expect(ctx, http.StatusOK, http.MethodPost, "/device/approve", map[string]string{"userCode": auth.UserCode})
	b.expect(ctx, http.StatusNotFound, http.MethodPost, "/device/approve", map[string]string{"userCode": auth.UserCode})
	b.expect(ctx, http.StatusNotFound, http.MethodGet, "/device/lookup?userCode="+auth.UserCode, nil)

	// The client receives the pair, once.
	time.Sleep(1100 * time.Millisecond)
	status, pair := a.poll(ctx, t, auth.DeviceCode)
	if status != http.StatusOK {
		t.Fatalf("poll after approval = %d %+v, want the pair", status, pair)
	}
	if diff := cmp.Diff(&tokenAnswer{AccessToken: pair.AccessToken, RefreshToken: pair.RefreshToken, TokenType: "Bearer", ExpiresIn: 3600}, pair); diff != "" {
		t.Errorf("pair mismatch (-want +got):\n%s", diff)
	}
	if pair.AccessToken == "" || pair.RefreshToken == "" {
		t.Fatalf("pair = %+v, want both tokens", pair)
	}
	status, answer = a.poll(ctx, t, auth.DeviceCode)
	a.expectGrantError(t, status, answer, "invalid_grant")

	// The access token acts as the person on the outlet.
	status, _, view := a.whoami(ctx, t, "droids", pair.AccessToken)
	if status != http.StatusOK {
		t.Fatalf("bearer call = %d", status)
	}
	wantView := &outletView{
		sessionView: sessionView{SessionID: view.SessionID, UserID: pat.String(), Username: "pat@lakeside.edu", User: pat.String(), Events: []string{"token:access"}},
		TokenID:     view.SessionID, Kind: "access", Client: "corral", Outlet: "droids",
	}
	if diff := cmp.Diff(wantView, view, cmp.AllowUnexported(outletView{})); diff != "" {
		t.Errorf("bearer view mismatch (-want +got):\n%s", diff)
	}
	if view.TokenID == "" {
		t.Error("bearer view names no token")
	}
	if rows := b.tokens(ctx); len(rows) != 2 || rows[0].ClientID != "corral" || rows[1].ClientID != "corral" {
		t.Errorf("listing = %+v, want the grant's two tokens for corral", rows)
	}
}

func seamDeviceRotation[Tx any](ctx context.Context, t *testing.T, a *tokenApp[Tx]) {
	t.Helper()

	a.seed(ctx, t, "pat@lakeside.edu")
	b := a.browser(t)
	b.prime(ctx)
	if status, _ := b.passwordLogin(ctx, seedPassword); status != http.StatusOK {
		t.Fatalf("password login = %d", status)
	}
	pair := a.approvedPair(ctx, t, b)
	if status, _, _ := a.whoami(ctx, t, "droids", pair.AccessToken); status != http.StatusOK {
		t.Fatalf("the access token = %d, want 200", status)
	}

	// The refresh rotates the pair.
	status, next := a.refresh(ctx, t, pair.RefreshToken)
	if status != http.StatusOK || next.AccessToken == "" || next.RefreshToken == "" {
		t.Fatalf("refresh = %d %+v", status, next)
	}
	if status, _, _ := a.whoami(ctx, t, "droids", pair.AccessToken); status != http.StatusUnauthorized {
		t.Errorf("the rotated access token = %d, want 401", status)
	}
	if status, _, _ := a.whoami(ctx, t, "droids", next.AccessToken); status != http.StatusOK {
		t.Errorf("the new access token = %d, want 200", status)
	}

	// A reuse of the old refresh token revokes the family: the new pair dies with it.
	status, answer := a.refresh(ctx, t, pair.RefreshToken)
	a.expectGrantError(t, status, answer, "invalid_grant")
	if status, _, _ := a.whoami(ctx, t, "droids", next.AccessToken); status != http.StatusUnauthorized {
		t.Errorf("the new access token after the reuse = %d, want 401", status)
	}
	status, answer = a.refresh(ctx, t, next.RefreshToken)
	a.expectGrantError(t, status, answer, "invalid_grant")
	if rows := b.tokens(ctx); len(rows) != 0 {
		t.Errorf("listing after the reuse = %+v, want none", rows)
	}

	// The grant's own refusals.
	status, answer = a.token(ctx, t, url.Values{"grant_type": {"password"}})
	a.expectGrantError(t, status, answer, "unsupported_grant_type")
	status, answer = a.token(ctx, t, url.Values{"grant_type": {"urn:ietf:params:oauth:grant-type:device_code"}})
	a.expectGrantError(t, status, answer, "invalid_request")
}

func seamDeviceDeniedRevokedDisabled[Tx any](ctx context.Context, t *testing.T, a *tokenApp[Tx]) {
	t.Helper()

	pat := a.seed(ctx, t, "pat@lakeside.edu")
	b := a.browser(t)
	b.prime(ctx)
	if status, _ := b.passwordLogin(ctx, seedPassword); status != http.StatusOK {
		t.Fatalf("password login = %d", status)
	}

	// Denied.
	auth := a.authorizeDevice(ctx, t, "corral", "droids")
	b.expect(ctx, http.StatusOK, http.MethodPost, "/device/deny", map[string]string{"userCode": auth.UserCode})
	status, answer := a.poll(ctx, t, auth.DeviceCode)
	a.expectGrantError(t, status, answer, "access_denied")
	b.expect(ctx, http.StatusNotFound, http.MethodPost, "/device/approve", map[string]string{"userCode": auth.UserCode})

	// Revoked by hand: the refresh token's row takes the access token with it.
	pair := a.approvedPair(ctx, t, b)
	rows := b.tokens(ctx)
	var refreshID string
	for _, row := range rows {
		if row.Kind == "refresh" {
			refreshID = row.ID
		}
	}
	if refreshID == "" {
		t.Fatalf("listing = %+v, want the grant's refresh token", rows)
	}
	b.expect(ctx, http.StatusOK, http.MethodPost, "/tokens/revoke", map[string]string{"id": refreshID})
	if status, _, _ := a.whoami(ctx, t, "droids", pair.AccessToken); status != http.StatusUnauthorized {
		t.Errorf("the access token of a revoked grant = %d, want 401", status)
	}
	status, answer = a.refresh(ctx, t, pair.RefreshToken)
	a.expectGrantError(t, status, answer, "invalid_grant")

	// Disabled.
	issued := b.createToken(ctx, "laptop", "droids")
	if status, _, _ := a.whoami(ctx, t, "droids", issued.Token); status != http.StatusOK {
		t.Fatalf("bearer call = %d, want 200", status)
	}
	a.db.disableUser(ctx, t, pat)
	if status, challenge, _ := a.whoami(ctx, t, "droids", issued.Token); status != http.StatusUnauthorized || !strings.Contains(challenge, "invalid_token") {
		t.Errorf("a disabled person's token = %d %q, want 401 invalid_token", status, challenge)
	}
}
