package deviceflow

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/go-playground/errors/v5"
	"github.com/google/go-cmp/cmp"
)

// config is a Config for f, its pair kept in a directory of the test's.
func config(t *testing.T, f *fake) *Config {
	t.Helper()

	return &Config{
		Server: f.server.URL, Outlet: f.outlet, Prefix: f.prefix, Client: "corral", Dir: t.TempDir(), HTTPClient: f.server.Client(),
		Prompt: func(Prompt) error { return nil },
	}
}

// waits is a wait of the poll loop that moves the fake's clock instead of sleeping,
// records what was asked, and runs a step of the test at each call.
type waits struct {
	f    *fake
	mu   sync.Mutex
	seen []time.Duration
	// step runs at the nth wait, counted from one.
	step func(n int)
}

func (w *waits) wait(_ context.Context, d time.Duration) error {
	w.mu.Lock()
	defer w.mu.Unlock()
	w.seen = append(w.seen, d)
	w.f.advance(d)
	if w.step != nil {
		w.step(len(w.seen))
	}

	return nil
}

// stored is the pair the test's directory holds for cfg.
func stored(t *testing.T, cfg *Config) *record {
	t.Helper()

	c, err := cfg.resolve()
	if err != nil {
		t.Fatalf("Config.resolve() error = %v", err)
	}
	rec, ok, err := c.store.read()
	if err != nil {
		t.Fatalf("store.read() error = %v", err)
	}
	if !ok {
		return nil
	}

	return rec
}

// keep stores pair for cfg with the access token expiring in ttl.
func keep(t *testing.T, cfg *Config, pair *tokenAnswer, ttl time.Duration) *record {
	t.Helper()

	c, err := cfg.resolve()
	if err != nil {
		t.Fatalf("Config.resolve() error = %v", err)
	}
	rec := &record{AccessToken: pair.AccessToken, RefreshToken: pair.RefreshToken, AccessExpiresAt: time.Now().Add(ttl), ObtainedAt: time.Now()}
	if err := c.store.save(rec); err != nil {
		t.Fatalf("store.save() error = %v", err)
	}

	return rec
}

// call sends method path with body through client and returns the status and the body.
func call(t *testing.T, client *http.Client, method, url string, body io.Reader) (status int, answer string, err error) {
	t.Helper()

	req, err := http.NewRequestWithContext(t.Context(), method, url, body)
	if err != nil {
		t.Fatalf("http.NewRequestWithContext() error = %v", err)
	}
	resp, err := client.Do(req)
	if err != nil {
		return 0, "", errors.Wrap(err, "http.Client.Do()")
	}
	defer resp.Body.Close()
	raw, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("io.ReadAll() error = %v", err)
	}

	return resp.StatusCode, string(raw), nil
}

// get calls the outlet's whoami through client and expects 200.
func get(t *testing.T, client *http.Client, f *fake) {
	t.Helper()

	status, body, err := call(t, client, http.MethodGet, f.server.URL+f.prefix+"/whoami", nil)
	if err != nil {
		t.Fatalf("GET whoami error = %v", err)
	}
	if status != http.StatusOK {
		t.Fatalf("GET whoami = %d %s, want 200", status, body)
	}
}

func TestLogin(t *testing.T) {
	t.Parallel()

	t.Run("the person approves and the pair is stored, the prompt naming the application's page", func(t *testing.T) {
		t.Parallel()
		f := newFake(t, "/machines")
		f.interval = 1
		cfg := config(t, f)
		var prompt Prompt
		cfg.Prompt = func(p Prompt) error {
			prompt = p
			f.decide(p.UserCode, "approved")

			return nil
		}
		before := time.Now()
		if err := Login(t.Context(), cfg); err != nil {
			t.Fatalf("Login() error = %v", err)
		}
		if len(prompt.UserCode) != 9 || prompt.UserCode[4] != '-' {
			t.Errorf("prompt.UserCode = %q, want XXXX-XXXX", prompt.UserCode)
		}
		want := Prompt{UserCode: prompt.UserCode, VerificationURL: f.server.URL + "/device", VerificationURLComplete: f.server.URL + "/device?userCode=" + prompt.UserCode, ExpiresAt: prompt.ExpiresAt}
		if diff := cmp.Diff(want, prompt); diff != "" {
			t.Errorf("prompt mismatch (-want +got):\n%s", diff)
		}
		if expires := prompt.ExpiresAt.Sub(before); expires < 9*time.Minute || expires > 11*time.Minute {
			t.Errorf("prompt.ExpiresAt is %s away, want ten minutes", expires)
		}
		rec := stored(t, cfg)
		if rec == nil || rec.AccessToken == "" || rec.RefreshToken == "" {
			t.Fatalf("stored = %+v, want the pair", rec)
		}
		if ttl := time.Until(rec.AccessExpiresAt); ttl < 59*time.Minute || ttl > time.Hour {
			t.Errorf("stored access expiry is %s away, want an hour", ttl)
		}
		client, err := Client(cfg)
		if err != nil {
			t.Fatalf("Client() error = %v", err)
		}
		get(t, client, f)
	})

	t.Run("the loop waits the interval, polls while the person decides, and adds five seconds on slow_down", func(t *testing.T) {
		t.Parallel()
		f := newFake(t, "/machines")
		f.minimumGap = 8
		cfg := config(t, f)
		var userCode string
		cfg.Prompt = func(p Prompt) error {
			userCode = p.UserCode

			return nil
		}
		c, err := cfg.resolve()
		if err != nil {
			t.Fatalf("Config.resolve() error = %v", err)
		}
		w := &waits{f: f, step: func(n int) {
			if n == 3 {
				f.decide(userCode, "approved")
			}
		}}
		c.wait = w.wait
		if err := c.login(t.Context()); err != nil {
			t.Fatalf("login() error = %v", err)
		}
		// Five seconds: pending. Five more: a gap of five under the eight enforced, so
		// slow_down and the interval grows to ten. Ten more: the pair.
		if diff := cmp.Diff([]time.Duration{5 * time.Second, 5 * time.Second, 10 * time.Second}, w.seen); diff != "" {
			t.Errorf("waits mismatch (-want +got):\n%s", diff)
		}
		if _, _, polls := f.counts(); polls != 3 {
			t.Errorf("polls = %d, want 3", polls)
		}
		if stored(t, cfg) == nil {
			t.Error("nothing stored")
		}
	})
}

func TestLogin_Refusals(t *testing.T) {
	t.Parallel()

	t.Run("the person denies: ErrDenied and nothing stored", func(t *testing.T) {
		t.Parallel()
		f := newFake(t, "/machines")
		cfg := config(t, f)
		cfg.Prompt = func(p Prompt) error {
			f.decide(p.UserCode, "denied")

			return nil
		}
		c, err := cfg.resolve()
		if err != nil {
			t.Fatalf("Config.resolve() error = %v", err)
		}
		c.wait = (&waits{f: f}).wait
		err = c.login(t.Context())
		if !errors.Is(err, ErrDenied) {
			t.Errorf("login() error = %v, want ErrDenied", err)
		}
		var refusal *Error
		if !errors.As(err, &refusal) || refusal.Code != "access_denied" {
			t.Errorf("login() error = %v, want the access_denied answer", err)
		}
		if stored(t, cfg) != nil {
			t.Error("a pair is stored after a denial")
		}
	})

	t.Run("the code expires: ErrExpired", func(t *testing.T) {
		t.Parallel()
		f := newFake(t, "/machines")
		cfg := config(t, f)
		c, err := cfg.resolve()
		if err != nil {
			t.Fatalf("Config.resolve() error = %v", err)
		}
		c.wait = func(_ context.Context, _ time.Duration) error {
			f.advance(11 * time.Minute)

			return nil
		}
		if err := c.login(t.Context()); !errors.Is(err, ErrExpired) {
			t.Errorf("login() error = %v, want ErrExpired", err)
		}
	})

	t.Run("the application refuses the authorization: its error", func(t *testing.T) {
		t.Parallel()
		f := newFake(t, "/machines")
		cfg := config(t, f)
		cfg.Outlet = "nope"
		err := Login(t.Context(), cfg)
		var refusal *Error
		if !errors.As(err, &refusal) || refusal.Code != "invalid_request" || !strings.Contains(refusal.Description, `"nope"`) {
			t.Errorf("Login() error = %v, want invalid_request naming the outlet", err)
		}
		for _, sentinel := range []error{ErrDenied, ErrExpired, ErrSignedOut} {
			if errors.Is(err, sentinel) {
				t.Errorf("Login() error matches %v", sentinel)
			}
		}
	})

	t.Run("the context ends while the person decides", func(t *testing.T) {
		t.Parallel()
		f := newFake(t, "/machines")
		cfg := config(t, f)
		ctx, cancel := context.WithCancel(t.Context())
		cfg.Prompt = func(Prompt) error {
			cancel()

			return nil
		}
		if err := Login(ctx, cfg); !errors.Is(err, context.Canceled) {
			t.Errorf("Login() error = %v, want context.Canceled", err)
		}
	})

	t.Run("the prompt's error ends the sign-in", func(t *testing.T) {
		t.Parallel()
		f := newFake(t, "/machines")
		cfg := config(t, f)
		cfg.Prompt = func(Prompt) error { return errors.New("the terminal is gone") }
		if err := Login(t.Context(), cfg); err == nil || !strings.Contains(err.Error(), "the terminal is gone") {
			t.Errorf("Login() error = %v, want the prompt's", err)
		}
	})
}

func TestLogin_Prefix(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name, mounted, prefix string
	}{
		{name: "the default prefix is the outlet's name", mounted: "/machines", prefix: ""},
		{name: "a prefix of the application's own", mounted: "/api/m", prefix: "/api/m"},
		{name: "a trailing slash is ignored", mounted: "/api/m", prefix: "/api/m/"},
		{name: "the root", mounted: "", prefix: "/"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			f := newFake(t, tt.mounted)
			cfg := config(t, f)
			cfg.Prefix = tt.prefix
			cfg.Prompt = func(p Prompt) error {
				f.decide(p.UserCode, "approved")

				return nil
			}
			c, err := cfg.resolve()
			if err != nil {
				t.Fatalf("Config.resolve() error = %v", err)
			}
			c.wait = (&waits{f: f}).wait
			if err := c.login(t.Context()); err != nil {
				t.Fatalf("login() error = %v", err)
			}
		})
	}
}

func TestConfig(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name    string
		cfg     *Config
		wantErr string
	}{
		{name: "no Config", cfg: nil, wantErr: "a Config is required"},
		{name: "no server", cfg: &Config{Outlet: "machines", Client: "corral"}, wantErr: "Server must be the application's base URL"},
		{name: "a server without a scheme", cfg: &Config{Server: "app.example.com", Outlet: "machines", Client: "corral"}, wantErr: "Server must be the application's base URL"},
		{name: "no outlet", cfg: &Config{Server: "https://app.example.com", Client: "corral"}, wantErr: "Outlet must name the machine outlet"},
		{name: "no client", cfg: &Config{Server: "https://app.example.com", Outlet: "machines", Client: "  "}, wantErr: "Client must name the program"},
		{name: "a client name too long", cfg: &Config{Server: "https://app.example.com", Outlet: "machines", Client: strings.Repeat("x", 201)}, wantErr: "Client must name the program"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			_, err := tt.cfg.resolve()
			if err == nil || !strings.Contains(err.Error(), tt.wantErr) {
				t.Errorf("resolve() error = %v, want %q", err, tt.wantErr)
			}
			if _, err := Client(tt.cfg); err == nil {
				t.Error("Client() accepted the Config")
			}
			if err := Logout(tt.cfg); err == nil {
				t.Error("Logout() accepted the Config")
			}
		})
	}

	t.Run("the defaults", func(t *testing.T) {
		t.Parallel()
		c, err := (&Config{Server: "https://app.example.com/", Outlet: "machines", Client: " corral "}).resolve()
		if err != nil {
			t.Fatalf("resolve() error = %v", err)
		}
		base, err := os.UserConfigDir()
		if err != nil {
			t.Fatalf("os.UserConfigDir() error = %v", err)
		}
		if c.server != "https://app.example.com" || c.prefix != "/machines" || c.name != "corral" || c.store.dir != filepath.Join(base, "corral") || c.store.key != "https://app.example.com|machines" {
			t.Errorf("resolved = %+v, want the defaults", c)
		}
		if c.sender != http.DefaultClient || c.prompt == nil {
			t.Error("resolved without the default client or prompt")
		}
	})
}

func TestError(t *testing.T) {
	t.Parallel()

	tests := []struct {
		code, description, want string
		is                      error
	}{
		{code: "access_denied", description: "the person denied the request", want: "the application answered access_denied: the person denied the request", is: ErrDenied},
		{code: "expired_token", description: "the device code expired; start again", want: "the application answered expired_token: the device code expired; start again", is: ErrExpired},
		{code: "invalid_grant", description: "the refresh token is not valid; sign in again", want: "the application answered invalid_grant: the refresh token is not valid; sign in again", is: ErrSignedOut},
		{code: "unsupported_grant_type", want: "the application answered unsupported_grant_type"},
	}
	for _, tt := range tests {
		t.Run(tt.code, func(t *testing.T) {
			t.Parallel()
			err := errors.Wrap(&Error{Code: tt.code, Description: tt.description}, "the token endpoint")
			var refusal *Error
			if !errors.As(err, &refusal) || refusal.Error() != tt.want {
				t.Errorf("Error() = %q, want %q", refusal.Error(), tt.want)
			}
			for _, sentinel := range []error{ErrDenied, ErrExpired, ErrSignedOut} {
				if got, want := errors.Is(err, sentinel), errors.Is(sentinel, tt.is); got != want {
					t.Errorf("errors.Is(%s, %v) = %t", tt.code, sentinel, got)
				}
			}
		})
	}
}

func TestWritePrompt(t *testing.T) {
	t.Parallel()

	var buf bytes.Buffer
	at := time.Date(2026, time.October, 25, 15, 4, 0, 0, time.Local)
	if err := writePrompt(&buf, Prompt{UserCode: "BCDF-GHJK", VerificationURLComplete: "https://app.example.com/device?userCode=BCDF-GHJK", ExpiresAt: at}); err != nil {
		t.Fatalf("writePrompt() error = %v", err)
	}
	want := "Open https://app.example.com/device?userCode=BCDF-GHJK and approve the code BCDF-GHJK.\nThe code expires at 3:04 PM.\n"
	if buf.String() != want {
		t.Errorf("prompt = %q, want %q", buf.String(), want)
	}
}

func TestClient(t *testing.T) {
	t.Parallel()

	t.Run("a request carries the stored access token", func(t *testing.T) {
		t.Parallel()
		f := newFake(t, "/machines")
		cfg := config(t, f)
		keep(t, cfg, f.grant(), time.Hour)
		client, err := Client(cfg)
		if err != nil {
			t.Fatalf("Client() error = %v", err)
		}
		status, body, err := call(t, client, http.MethodGet, f.server.URL+"/machines/whoami", nil)
		if err != nil || status != http.StatusOK || !strings.Contains(body, `"client":"corral"`) {
			t.Errorf("GET whoami = %d %s %v, want 200 as corral", status, body, err)
		}
		if refreshes, _, _ := f.counts(); refreshes != 0 {
			t.Errorf("refreshes = %d, want none", refreshes)
		}
	})

	t.Run("a token that expires within a minute is refreshed before the request", func(t *testing.T) {
		t.Parallel()
		f := newFake(t, "/machines")
		cfg := config(t, f)
		first := keep(t, cfg, f.grant(), 30*time.Second)
		client, err := Client(cfg)
		if err != nil {
			t.Fatalf("Client() error = %v", err)
		}
		get(t, client, f)
		if refreshes, _, _ := f.counts(); refreshes != 1 {
			t.Errorf("refreshes = %d, want 1", refreshes)
		}
		next := stored(t, cfg)
		if next == nil || next.AccessToken == first.AccessToken || next.RefreshToken == first.RefreshToken {
			t.Fatalf("stored = %+v, want the next pair", next)
		}
		if ttl := time.Until(next.AccessExpiresAt); ttl < 59*time.Minute || ttl > time.Hour {
			t.Errorf("stored access expiry is %s away, want an hour", ttl)
		}
		if !next.ObtainedAt.After(first.ObtainedAt) {
			t.Errorf("obtainedAt = %s, want after %s", next.ObtainedAt, first.ObtainedAt)
		}
		get(t, client, f)
		if refreshes, _, _ := f.counts(); refreshes != 1 {
			t.Errorf("refreshes after the second request = %d, want 1 still", refreshes)
		}
	})
}

func TestClient_RefusedToken(t *testing.T) {
	t.Parallel()

	t.Run("a refused token is refreshed and the request sent again, with its body", func(t *testing.T) {
		t.Parallel()
		f := newFake(t, "/machines")
		cfg := config(t, f)
		pair := f.grant()
		keep(t, cfg, pair, time.Hour)
		f.killAccess(pair.AccessToken)
		client, err := Client(cfg)
		if err != nil {
			t.Fatalf("Client() error = %v", err)
		}
		status, body, err := call(t, client, http.MethodPost, f.server.URL+"/machines/echo", strings.NewReader("hello"))
		if err != nil || status != http.StatusOK || body != "hello" {
			t.Errorf("POST echo = %d %q %v, want 200 hello", status, body, err)
		}
		if refreshes, outletCalls, _ := f.counts(); refreshes != 1 || outletCalls != 1 {
			t.Errorf("refreshes, outlet calls = %d, %d, want 1, 1", refreshes, outletCalls)
		}
		get(t, client, f)
		if refreshes, _, _ := f.counts(); refreshes != 1 {
			t.Errorf("refreshes after the next request = %d, want 1 still", refreshes)
		}
	})

	t.Run("a refused request whose body cannot be sent again is answered the refusal, the pair refreshed for the next", func(t *testing.T) {
		t.Parallel()
		f := newFake(t, "/machines")
		cfg := config(t, f)
		pair := f.grant()
		keep(t, cfg, pair, time.Hour)
		f.killAccess(pair.AccessToken)
		client, err := Client(cfg)
		if err != nil {
			t.Fatalf("Client() error = %v", err)
		}
		status, _, err := call(t, client, http.MethodPost, f.server.URL+"/machines/echo", struct{ io.Reader }{strings.NewReader("once")})
		if err != nil || status != http.StatusUnauthorized {
			t.Errorf("POST echo = %d %v, want 401", status, err)
		}
		if refreshes, outletCalls, _ := f.counts(); refreshes != 1 || outletCalls != 0 {
			t.Errorf("refreshes, outlet calls = %d, %d, want 1, 0", refreshes, outletCalls)
		}
		if next := stored(t, cfg); next == nil || next.AccessToken == pair.AccessToken {
			t.Errorf("stored = %+v, want the next pair", next)
		}
		get(t, client, f)
	})
}

func TestClient_SignedOut(t *testing.T) {
	t.Parallel()

	t.Run("no stored pair: ErrSignedOut", func(t *testing.T) {
		t.Parallel()
		f := newFake(t, "/machines")
		client, err := Client(config(t, f))
		if err != nil {
			t.Fatalf("Client() error = %v", err)
		}
		_, _, err = call(t, client, http.MethodGet, f.server.URL+"/machines/whoami", nil)
		if !errors.Is(err, ErrSignedOut) {
			t.Errorf("GET whoami error = %v, want ErrSignedOut", err)
		}
	})

	t.Run("a refused refresh: ErrSignedOut and the pair forgotten", func(t *testing.T) {
		t.Parallel()
		f := newFake(t, "/machines")
		cfg := config(t, f)
		pair := f.grant()
		keep(t, cfg, pair, 30*time.Second)
		f.revokeFamily(pair.RefreshToken)
		client, err := Client(cfg)
		if err != nil {
			t.Fatalf("Client() error = %v", err)
		}
		_, _, err = call(t, client, http.MethodGet, f.server.URL+"/machines/whoami", nil)
		if !errors.Is(err, ErrSignedOut) {
			t.Errorf("GET whoami error = %v, want ErrSignedOut", err)
		}
		var refusal *Error
		if !errors.As(err, &refusal) || refusal.Code != "invalid_grant" {
			t.Errorf("GET whoami error = %v, want the invalid_grant answer", err)
		}
		if stored(t, cfg) != nil {
			t.Error("the refused pair is still stored")
		}
	})
}

func TestClient_SharedDirectory(t *testing.T) {
	t.Parallel()

	t.Run("two clients over one directory: the second finds the first's rotation and does not refresh", func(t *testing.T) {
		t.Parallel()
		f := newFake(t, "/machines")
		cfg := config(t, f)
		keep(t, cfg, f.grant(), 30*time.Second)
		first, err := Client(cfg)
		if err != nil {
			t.Fatalf("Client() error = %v", err)
		}
		second, err := Client(cfg)
		if err != nil {
			t.Fatalf("Client() error = %v", err)
		}
		get(t, first, f)
		get(t, second, f)
		if refreshes, outletCalls, _ := f.counts(); refreshes != 1 || outletCalls != 2 {
			t.Errorf("refreshes, outlet calls = %d, %d, want 1, 2", refreshes, outletCalls)
		}
	})

	t.Run("a refresh that finds the pair rotated by another process uses it", func(t *testing.T) {
		t.Parallel()
		f := newFake(t, "/machines")
		cfg := config(t, f)
		earlier := keep(t, cfg, f.grant(), 30*time.Second)
		c, err := cfg.resolve()
		if err != nil {
			t.Fatalf("Config.resolve() error = %v", err)
		}
		// Another process rotated the pair after this one read it.
		rotated := keep(t, cfg, f.grant(), time.Hour)
		next, err := c.refresh(t.Context(), earlier)
		if err != nil {
			t.Fatalf("refresh() error = %v", err)
		}
		if diff := cmp.Diff(rotated, next); diff != "" {
			t.Errorf("refresh() mismatch (-want +got):\n%s", diff)
		}
		if refreshes, _, _ := f.counts(); refreshes != 0 {
			t.Errorf("refreshes = %d, want none", refreshes)
		}
	})

	t.Run("requests from several goroutines refresh once", func(t *testing.T) {
		t.Parallel()
		f := newFake(t, "/machines")
		cfg := config(t, f)
		keep(t, cfg, f.grant(), 30*time.Second)
		client, err := Client(cfg)
		if err != nil {
			t.Fatalf("Client() error = %v", err)
		}
		var wg sync.WaitGroup
		for range 8 {
			wg.Go(func() { get(t, client, f) })
		}
		wg.Wait()
		if refreshes, outletCalls, _ := f.counts(); refreshes != 1 || outletCalls != 8 {
			t.Errorf("refreshes, outlet calls = %d, %d, want 1, 8", refreshes, outletCalls)
		}
	})
}

func TestClient_Configured(t *testing.T) {
	t.Parallel()

	t.Run("the transport, redirect policy and timeout of the configured client are kept", func(t *testing.T) {
		t.Parallel()
		f := newFake(t, "/machines")
		cfg := config(t, f)
		redirect := func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
		cfg.HTTPClient = &http.Client{Transport: f.server.Client().Transport, CheckRedirect: redirect, Timeout: 7 * time.Second}
		client, err := Client(cfg)
		if err != nil {
			t.Fatalf("Client() error = %v", err)
		}
		tr, ok := client.Transport.(*transport)
		if !ok || tr.next != f.server.Client().Transport || client.CheckRedirect == nil || client.Timeout != 7*time.Second {
			t.Errorf("Client() = %+v, want the configured client's pieces under the bearer transport", client)
		}
	})
}

func TestStore(t *testing.T) {
	t.Parallel()

	t.Run("the directory and the files are the person's alone", func(t *testing.T) {
		t.Parallel()
		if runtime.GOOS == "windows" {
			t.Skip("file modes are not Windows permissions")
		}
		f := newFake(t, "/machines")
		cfg := config(t, f)
		cfg.Dir = filepath.Join(t.TempDir(), "corral")
		keep(t, cfg, f.grant(), time.Hour)
		for name, want := range map[string]os.FileMode{"": dirMode | os.ModeDir, tokensFileName: fileMode, lockFileName: fileMode} {
			info, err := os.Stat(filepath.Join(cfg.Dir, name))
			if err != nil {
				t.Fatalf("os.Stat(%q) error = %v", name, err)
			}
			if info.Mode() != want {
				t.Errorf("%q mode = %s, want %s", name, info.Mode(), want)
			}
		}
		entries, err := os.ReadDir(cfg.Dir)
		if err != nil {
			t.Fatalf("os.ReadDir() error = %v", err)
		}
		if len(entries) != 2 {
			t.Errorf("the directory holds %d entries, want the two files", len(entries))
		}
	})

	t.Run("one file keeps the pairs of several applications", func(t *testing.T) {
		t.Parallel()
		f := newFake(t, "/machines")
		cfg := config(t, f)
		other := *cfg
		other.Outlet = "robots"
		mine := keep(t, cfg, f.grant(), time.Hour)
		theirs := keep(t, &other, f.grant(), time.Hour)
		if diff := cmp.Diff(mine, stored(t, cfg)); diff != "" {
			t.Errorf("stored mismatch (-want +got):\n%s", diff)
		}
		if diff := cmp.Diff(theirs, stored(t, &other)); diff != "" {
			t.Errorf("stored for the other outlet mismatch (-want +got):\n%s", diff)
		}
		if err := Logout(cfg); err != nil {
			t.Fatalf("Logout() error = %v", err)
		}
		if stored(t, cfg) != nil {
			t.Error("the pair is still stored after Logout")
		}
		if diff := cmp.Diff(theirs, stored(t, &other)); diff != "" {
			t.Errorf("Logout touched the other outlet's pair (-want +got):\n%s", diff)
		}
		if err := Logout(cfg); err != nil {
			t.Errorf("a second Logout() error = %v", err)
		}
		client, err := Client(cfg)
		if err != nil {
			t.Fatalf("Client() error = %v", err)
		}
		if _, _, err := call(t, client, http.MethodGet, f.server.URL+"/machines/whoami", nil); !errors.Is(err, ErrSignedOut) {
			t.Errorf("GET whoami after Logout error = %v, want ErrSignedOut", err)
		}
	})

	t.Run("Logout with nothing stored", func(t *testing.T) {
		t.Parallel()
		f := newFake(t, "/machines")
		cfg := config(t, f)
		cfg.Dir = filepath.Join(t.TempDir(), "never-made")
		if err := Logout(cfg); err != nil {
			t.Errorf("Logout() error = %v", err)
		}
		if _, err := os.Stat(filepath.Join(cfg.Dir, tokensFileName)); !errors.Is(err, os.ErrNotExist) {
			t.Errorf("Logout wrote a tokens file: %v", err)
		}
	})

	t.Run("a file that is not the store is reported", func(t *testing.T) {
		t.Parallel()
		f := newFake(t, "/machines")
		cfg := config(t, f)
		if err := os.WriteFile(filepath.Join(cfg.Dir, tokensFileName), []byte("not json"), fileMode); err != nil {
			t.Fatalf("os.WriteFile() error = %v", err)
		}
		if _, err := Client(cfg); err != nil {
			t.Fatalf("Client() error = %v", err)
		}
		if err := Logout(cfg); err == nil || !strings.Contains(err.Error(), "does not hold the stored sign-ins") {
			t.Errorf("Logout() error = %v, want the file named", err)
		}
	})
}

func TestStore_Lock(t *testing.T) {
	t.Parallel()

	t.Run("the lock waits for its holder", func(t *testing.T) {
		t.Parallel()
		if runtime.GOOS != "linux" && runtime.GOOS != "darwin" && runtime.GOOS != "windows" {
			t.Skip("no file lock on this platform")
		}
		s := &store{dir: t.TempDir(), key: "k"}
		unlock, err := s.lock()
		if err != nil {
			t.Fatalf("lock() error = %v", err)
		}
		taken := make(chan struct{})
		go func() {
			defer close(taken)
			again, err := s.lock()
			if err != nil {
				t.Errorf("second lock() error = %v", err)

				return
			}
			again()
		}()
		select {
		case <-taken:
			t.Fatal("the second lock was taken while the first is held")
		case <-time.After(100 * time.Millisecond):
		}
		unlock()
		select {
		case <-taken:
		case <-time.After(5 * time.Second):
			t.Fatal("the second lock was not taken once the first let go")
		}
	})
}

// A stored file as a person might read it: the tokens, when the access token
// expires, and when the pair was obtained.
func TestStore_Shape(t *testing.T) {
	t.Parallel()

	f := newFake(t, "/machines")
	cfg := config(t, f)
	rec := keep(t, cfg, &tokenAnswer{AccessToken: "a", RefreshToken: "r"}, time.Hour)
	raw, err := os.ReadFile(filepath.Join(cfg.Dir, tokensFileName))
	if err != nil {
		t.Fatalf("os.ReadFile() error = %v", err)
	}
	var all map[string]map[string]any
	if err := json.Unmarshal(raw, &all); err != nil {
		t.Fatalf("json.Unmarshal(%s) error = %v", raw, err)
	}
	entry := all[f.server.URL+"|machines"]
	if entry["accessToken"] != "a" || entry["refreshToken"] != "r" || entry["accessExpiresAt"] != rec.AccessExpiresAt.Format(time.RFC3339Nano) || entry["obtainedAt"] == nil {
		t.Errorf("file = %s, want the pair under the server and outlet", raw)
	}
}
