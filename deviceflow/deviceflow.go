// Package deviceflow signs a command-line program in to an impulse application's
// machine outlet through the device flow (RFC 8628) the session library serves, keeps
// the token pair in the person's configuration directory, and hands the program an
// http.Client that carries the access token and refreshes it.
//
// A program describes the application and itself in a Config. Login runs the flow
// once: it asks the application for a device authorization, tells the person which
// address to open and which code to approve, and polls until they decide. Client then
// calls the outlet as that person: every request carries the stored access token, a
// token about to expire is refreshed first, and a request the outlet refuses with
// invalid_token is sent once more with a refreshed token. Logout forgets the stored
// pair. The pair lives in one file under the program's directory in the person's
// configuration directory, so every invocation of the program finds it.
//
// A refresh rotates the pair on the server, and a rotated refresh token presented
// again revokes the whole grant. Every refresh therefore runs under a file lock shared
// with every other process that keeps the same pair, and a process that finds the pair
// rotated while it waited for the lock uses what it finds instead of refreshing again.
package deviceflow

import (
	"bytes"
	"context"
	"encoding/json"
	stderrors "errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/go-playground/errors/v5"
)

// The flow's grant types, error codes and timing (RFC 8628, RFC 6749).
const (
	grantDeviceCode   = "urn:ietf:params:oauth:grant-type:device_code"
	grantRefreshToken = "refresh_token"

	codeAuthorizationPending = "authorization_pending"
	codeSlowDown             = "slow_down"
	codeAccessDenied         = "access_denied"
	codeExpiredToken         = "expired_token"
	codeInvalidGrant         = "invalid_grant"

	authorizePath = "/oauth/device/authorize"
	tokenPath     = "/oauth/token"

	// defaultInterval is the poll interval when the application names none.
	defaultInterval = 5 * time.Second
	// slowDownStep is what a slow_down answer adds to the interval (RFC 8628, 3.5).
	slowDownStep = 5 * time.Second
	// clientNameMaxLength is the longest name the application records for a client.
	clientNameMaxLength = 200
	// answerLimit bounds what is read of an answer.
	answerLimit = 1 << 20
)

// Config describes the application a program signs in to and how the program keeps
// its tokens.
type Config struct {
	// Server is the application's base URL as a browser reaches it, such as
	// https://app.example.com; a trailing slash is ignored. Required.
	Server string
	// Outlet is the machine outlet's name, such as "machines". Required.
	Outlet string
	// Prefix is the path the outlet's public endpoints sit under, such as "/machines":
	// the device authorization endpoint is Prefix + "/oauth/device/authorize" and the
	// token endpoint Prefix + "/oauth/token". Default "/" + Outlet.
	Prefix string
	// Client is the program's name, shown to the person who approves it and recorded
	// on the grant (client_id). Required, at most 200 bytes.
	Client string
	// Dir is the directory the pair is kept in. Default the program's own directory
	// under the person's configuration directory: os.UserConfigDir joined with Client.
	Dir string
	// Prompt tells the person what to do. Default: two sentences on standard error,
	// "Open <address> and approve the code XXXX-XXXX." and "The code expires at
	// <time>."
	Prompt func(Prompt) error
	// HTTPClient sends the flow's requests and the refreshes; Client keeps its
	// transport, cookie jar, redirect policy and timeout. Default http.DefaultClient.
	HTTPClient *http.Client
}

// Prompt is what the person must do: open the address and approve the code.
type Prompt struct {
	// UserCode is the code the person approves, as XXXX-XXXX.
	UserCode string
	// VerificationURL is the application's page where the person types the code,
	// absolute.
	VerificationURL string
	// VerificationURLComplete is that page with the code filled in, absolute.
	VerificationURLComplete string
	// ExpiresAt is when the code stops working.
	ExpiresAt time.Time
}

// The errors a program tests for with errors.Is. They are plain values of the
// standard library, so each reads as its sentence and a wrapped one still matches.
var (
	// ErrDenied is Login's error when the person denied the request.
	ErrDenied = stderrors.New("the person denied the request")
	// ErrExpired is Login's error when the code expired before the person approved it.
	ErrExpired = stderrors.New("the code expired before the person approved it; sign in again")
	// ErrSignedOut is a Client request's error when the program holds no pair the
	// application accepts: none is stored, or the refresh was refused. The program
	// calls Login again.
	ErrSignedOut = stderrors.New("sign in again")
)

// Error is an error the application's device authorization or token endpoint
// answered (RFC 6749, 5.2): the code and the description as the application wrote
// them. errors.Is matches ErrDenied for access_denied, ErrExpired for expired_token
// and ErrSignedOut for invalid_grant.
type Error struct {
	// Code is the answer's error field, such as access_denied or invalid_request.
	Code string
	// Description is the answer's error_description field, as the application wrote it.
	Description string
}

// Error renders the code and the description.
func (e *Error) Error() string {
	if e.Description == "" {
		return "the application answered " + e.Code
	}

	return "the application answered " + e.Code + ": " + e.Description
}

// Is matches the package's sentinels to the codes they stand for.
func (e *Error) Is(target error) bool {
	switch target {
	case ErrDenied:
		return e.Code == codeAccessDenied
	case ErrExpired:
		return e.Code == codeExpiredToken
	case ErrSignedOut:
		return e.Code == codeInvalidGrant
	default:
		return false
	}
}

// Login signs the program in: it asks the application for a device authorization,
// tells the person through cfg.Prompt which address to open and which code to approve,
// polls the token endpoint at the interval the application names (longer when it
// answers slow_down) until the person decides, and stores the pair. It returns
// ErrDenied when the person denies the request, ErrExpired when the code expires
// first, an *Error for any other refusal, and ctx's error when ctx ends.
func Login(ctx context.Context, cfg *Config) error {
	c, err := cfg.resolve()
	if err != nil {
		return err
	}

	return c.login(ctx)
}

// Logout forgets the stored pair for cfg's server and outlet. Nothing is called on the
// application: the person revokes the grant from their token page when they want it
// gone there too.
func Logout(cfg *Config) error {
	c, err := cfg.resolve()
	if err != nil {
		return err
	}

	return c.store.forget()
}

// client is a Config resolved: every default filled in and the inputs checked.
type client struct {
	// server is the application's base URL without a trailing slash, and prefix the
	// outlet's path prefix without one ("" when the endpoints sit at the root).
	server, prefix string
	// outlet is the outlet's name and name the program's.
	outlet, name string
	sender       *http.Client
	prompt       func(Prompt) error
	store        *store
	// wait waits for d or until ctx ends, as the poll loop paces itself.
	wait func(ctx context.Context, d time.Duration) error
}

// resolve checks cfg and fills its defaults in.
func (cfg *Config) resolve() (*client, error) {
	if cfg == nil {
		return nil, errors.New("a Config is required")
	}
	server := strings.TrimRight(cfg.Server, "/")
	parsed, err := url.Parse(server)
	if err != nil || server == "" || (parsed.Scheme != "http" && parsed.Scheme != "https") || parsed.Host == "" {
		return nil, errors.Newf("Server must be the application's base URL, such as https://app.example.com, not %q", cfg.Server)
	}
	if cfg.Outlet == "" {
		return nil, errors.New("Outlet must name the machine outlet the program calls")
	}
	name := strings.TrimSpace(cfg.Client)
	if name == "" || len(name) > clientNameMaxLength {
		return nil, errors.New("Client must name the program, in at most 200 characters")
	}
	prefix := cfg.Prefix
	if prefix == "" {
		prefix = "/" + cfg.Outlet
	}
	if prefix = strings.Trim(prefix, "/"); prefix != "" {
		prefix = "/" + prefix
	}
	dir := cfg.Dir
	if dir == "" {
		base, err := os.UserConfigDir()
		if err != nil {
			return nil, errors.Wrap(err, "os.UserConfigDir()")
		}
		dir = filepath.Join(base, name)
	}
	prompt := cfg.Prompt
	if prompt == nil {
		prompt = defaultPrompt
	}
	sender := cfg.HTTPClient
	if sender == nil {
		sender = http.DefaultClient
	}

	return &client{
		server: server, prefix: prefix, outlet: cfg.Outlet, name: name, sender: sender, prompt: prompt,
		store: &store{dir: dir, key: server + "|" + cfg.Outlet}, wait: waitFor,
	}, nil
}

// defaultPrompt tells the person on standard error.
func defaultPrompt(p Prompt) error {
	return writePrompt(os.Stderr, p)
}

// writePrompt tells the person on w, in two sentences.
func writePrompt(w io.Writer, p Prompt) error {
	if _, err := fmt.Fprintf(w, "Open %s and approve the code %s.\nThe code expires at %s.\n",
		p.VerificationURLComplete, p.UserCode, p.ExpiresAt.Local().Format("3:04 PM")); err != nil {
		return errors.Wrap(err, "fmt.Fprintf()")
	}

	return nil
}

// waitFor waits for d or until ctx ends.
func waitFor(ctx context.Context, d time.Duration) error {
	timer := time.NewTimer(d)
	defer timer.Stop()

	select {
	case <-ctx.Done():
		return errors.Wrap(ctx.Err(), "context.Context.Err()")
	case <-timer.C:
		return nil
	}
}

// deviceAuthorization is the device authorization endpoint's answer (RFC 8628, 3.2).
type deviceAuthorization struct {
	DeviceCode              string `json:"device_code"`
	UserCode                string `json:"user_code"`
	VerificationURI         string `json:"verification_uri"`
	VerificationURIComplete string `json:"verification_uri_complete"`
	ExpiresIn               int    `json:"expires_in"`
	Interval                int    `json:"interval"`
}

// tokenAnswer is the token endpoint's answer (RFC 6749, 5.1).
type tokenAnswer struct {
	AccessToken  string `json:"access_token"`
	TokenType    string `json:"token_type"`
	ExpiresIn    int    `json:"expires_in"`
	RefreshToken string `json:"refresh_token"`
}

// oauthError is an endpoint's error answer (RFC 6749, 5.2).
type oauthError struct {
	Code        string `json:"error"`
	Description string `json:"error_description"`
}

// record is the pair as the file keeps it.
func (a *tokenAnswer) record(now time.Time) *record {
	return &record{
		AccessToken: a.AccessToken, RefreshToken: a.RefreshToken,
		AccessExpiresAt: now.Add(time.Duration(a.ExpiresIn) * time.Second), ObtainedAt: now,
	}
}

// login is Login over a resolved Config.
func (c *client) login(ctx context.Context) error {
	var auth deviceAuthorization
	if err := c.post(ctx, authorizePath, map[string]string{"client_id": c.name, "outlet": c.outlet}, &auth); err != nil {
		return err
	}
	if err := c.prompt(Prompt{
		UserCode: auth.UserCode, VerificationURL: c.absolute(auth.VerificationURI), VerificationURLComplete: c.absolute(auth.VerificationURIComplete),
		ExpiresAt: time.Now().Add(time.Duration(auth.ExpiresIn) * time.Second),
	}); err != nil {
		return errors.Wrap(err, "Config.Prompt()")
	}
	interval := time.Duration(auth.Interval) * time.Second
	if interval <= 0 {
		interval = defaultInterval
	}
	for {
		if err := c.wait(ctx, interval); err != nil {
			return err
		}
		var pair tokenAnswer
		err := c.post(ctx, tokenPath, map[string]string{"grant_type": grantDeviceCode, "device_code": auth.DeviceCode}, &pair)
		var refusal *Error
		switch {
		case err == nil:
			return c.store.save(pair.record(time.Now()))
		case errors.As(err, &refusal) && refusal.Code == codeAuthorizationPending:
		case errors.As(err, &refusal) && refusal.Code == codeSlowDown:
			interval += slowDownStep
		default:
			return err
		}
	}
}

// absolute resolves a path the application names, such as verification_uri, against
// the server; an absolute URL is kept.
func (c *client) absolute(ref string) string {
	parsed, err := url.Parse(ref)
	if err != nil || parsed.IsAbs() {
		return ref
	}

	return c.server + "/" + strings.TrimLeft(ref, "/")
}

// post sends fields as JSON to path under the outlet's prefix and decodes a 200 into
// answer. A 400 is the application's *Error; any other status is an error naming it.
func (c *client) post(ctx context.Context, path string, fields map[string]string, answer any) error {
	body, err := json.Marshal(fields)
	if err != nil {
		return errors.Wrap(err, "json.Marshal()")
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.server+c.prefix+path, bytes.NewReader(body))
	if err != nil {
		return errors.Wrap(err, "http.NewRequestWithContext()")
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json")
	resp, err := c.sender.Do(req)
	if err != nil {
		return errors.Wrap(err, "http.Client.Do()")
	}
	defer resp.Body.Close()

	raw, err := io.ReadAll(io.LimitReader(resp.Body, answerLimit))
	if err != nil {
		return errors.Wrap(err, "io.ReadAll()")
	}
	switch resp.StatusCode {
	case http.StatusOK:
		if err := json.Unmarshal(raw, answer); err != nil {
			return errors.Wrapf(err, "the application's answer to POST %s is not the JSON expected", path)
		}

		return nil
	case http.StatusBadRequest:
		var refusal oauthError
		if err := json.Unmarshal(raw, &refusal); err != nil || refusal.Code == "" {
			return errors.Newf("the application answered POST %s with 400 and no error code: %s", path, strings.TrimSpace(string(raw)))
		}

		return &Error{Code: refusal.Code, Description: refusal.Description}
	default:
		return errors.Newf("the application answered POST %s with %d: %s", path, resp.StatusCode, strings.TrimSpace(string(raw)))
	}
}
