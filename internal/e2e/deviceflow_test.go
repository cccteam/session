package e2e

import (
	"context"
	"encoding/json"
	"net/http"
	"net/url"
	"testing"
	"time"

	"github.com/cccteam/session"
	"github.com/cccteam/session/deviceflow"
	"github.com/go-playground/errors/v5"
)

// The device-flow client scenario: the deviceflow package, as a command-line program
// uses it, signs in against the real handlers, calls the outlet as the person who
// approved it, refreshes the pair, and forgets it.

func TestAuthSeams_DeviceFlowClient(t *testing.T) {
	t.Parallel()

	t.Run(postgresBackend.name, func(t *testing.T) {
		t.Parallel()
		seamDeviceFlowClient(t, postgresBackend)
	})
	t.Run(spannerBackend.name, func(t *testing.T) {
		t.Parallel()
		seamDeviceFlowClient(t, spannerBackend)
	})
}

// outletCall calls the droids outlet's /whoami through client.
func outletCall(ctx context.Context, t *testing.T, client *http.Client, server string) (int, *outletView, error) {
	t.Helper()

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, server+"/droids/whoami", http.NoBody)
	if err != nil {
		t.Fatalf("http.NewRequestWithContext() error = %v", err)
	}
	resp, err := client.Do(req)
	if err != nil {
		return 0, nil, errors.Wrap(err, "http.Client.Do()")
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return resp.StatusCode, nil, nil
	}
	view := &outletView{}
	if err := json.NewDecoder(resp.Body).Decode(view); err != nil {
		t.Fatalf("json.Decoder.Decode() error = %v", err)
	}

	return resp.StatusCode, view, nil
}

// approveDevice is the person's side of the prompt: they open the application's
// page, which looks the code up and approves it as them.
func (b *browser) approveDevice(ctx context.Context, p deviceflow.Prompt) {
	b.t.Helper()

	var pending struct {
		ClientID string `json:"clientId"`
		Outlet   string `json:"outlet"`
	}
	if err := json.Unmarshal(b.expect(ctx, http.StatusOK, http.MethodGet, "/device/lookup?userCode="+url.QueryEscape(p.UserCode), nil), &pending); err != nil {
		b.t.Fatalf("json.Unmarshal() error = %v", err)
	}
	if pending.ClientID != "corral" || pending.Outlet != "droids" {
		b.t.Errorf("lookup = %+v, want corral on droids", pending)
	}
	b.expect(ctx, http.StatusOK, http.MethodPost, "/device/approve", map[string]string{"userCode": p.UserCode})
}

// assertGrant fails unless rows are the grant's two tokens for corral, and none of
// before's when before is given: a refresh replaced them.
func assertGrant(t *testing.T, rows, before []tokenRow) {
	t.Helper()

	if len(rows) != 2 || rows[0].ClientID != "corral" || rows[1].ClientID != "corral" {
		t.Fatalf("listing = %+v, want the grant's two tokens for corral", rows)
	}
	for _, row := range rows {
		for _, old := range before {
			if row.ID == old.ID {
				t.Errorf("the token %s survived the refresh", row.ID)
			}
		}
	}
}

func seamDeviceFlowClient[Tx any](t *testing.T, be backend[Tx]) {
	t.Helper()

	ctx := t.Context()
	// Access tokens live thirty seconds here, within the minute the client refreshes
	// ahead of, so its first call refreshes the pair Login stored before it sends.
	a := newTokenApp(ctx, t, be, session.WithTokenLifetimes(30*time.Second, 30*24*time.Hour, 365*24*time.Hour))
	pat := a.seed(ctx, t, "pat@lakeside.edu")
	b := a.browser(t)
	b.prime(ctx)
	if status, _ := b.passwordLogin(ctx, seedPassword); status != http.StatusOK {
		t.Fatalf("password login = %d", status)
	}

	// The program signs in; the person, told the code, opens the application's page,
	// which looks the code up and approves it as them.
	var prompt deviceflow.Prompt
	cfg := &deviceflow.Config{
		Server: a.server.URL, Outlet: "droids", Prefix: "/", Client: "corral", Dir: t.TempDir(), HTTPClient: a.machine,
		Prompt: func(p deviceflow.Prompt) error {
			prompt = p
			b.approveDevice(ctx, p)

			return nil
		},
	}
	if err := deviceflow.Login(ctx, cfg); err != nil {
		t.Fatalf("deviceflow.Login() error = %v", err)
	}
	if prompt.VerificationURL != a.server.URL+"/device" || prompt.VerificationURLComplete != a.server.URL+"/device?userCode="+prompt.UserCode {
		t.Errorf("prompt = %+v, want the application's page, absolute", prompt)
	}
	if time.Until(prompt.ExpiresAt) < 9*time.Minute {
		t.Errorf("prompt.ExpiresAt = %s, want ten minutes away", prompt.ExpiresAt)
	}
	first := b.tokens(ctx)
	assertGrant(t, first, nil)

	// The program calls the outlet as the person: the pair is refreshed first, so the
	// grant's rows are new ones in the same family.
	client, err := deviceflow.Client(cfg)
	if err != nil {
		t.Fatalf("deviceflow.Client() error = %v", err)
	}
	status, view, err := outletCall(ctx, t, client, a.server.URL)
	if err != nil || status != http.StatusOK {
		t.Fatalf("outlet call = %d, %v, want 200", status, err)
	}
	if view.UserID != pat.String() || view.Client != "corral" || view.Kind != "access" || view.Outlet != "droids" {
		t.Errorf("outlet view = %+v, want the access token of corral as pat", view)
	}
	assertGrant(t, b.tokens(ctx), first)
	if status, _, err := outletCall(ctx, t, client, a.server.URL); err != nil || status != http.StatusOK {
		t.Errorf("a second outlet call = %d, %v, want 200", status, err)
	}

	// Logout forgets the pair here; the grant stays on the application until the
	// person revokes it.
	if err := deviceflow.Logout(cfg); err != nil {
		t.Fatalf("deviceflow.Logout() error = %v", err)
	}
	if _, _, err := outletCall(ctx, t, client, a.server.URL); !errors.Is(err, deviceflow.ErrSignedOut) {
		t.Errorf("outlet call after Logout error = %v, want ErrSignedOut", err)
	}
	if rows := b.tokens(ctx); len(rows) != 2 {
		t.Errorf("listing after Logout = %+v, want the grant's two tokens still", rows)
	}
}
