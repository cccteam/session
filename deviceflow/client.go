package deviceflow

import (
	"context"
	"io"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/go-playground/errors/v5"
)

// refreshAhead is how long before the access token's expiry a request refreshes
// first, so a token does not expire in flight.
const refreshAhead = time.Minute

// refreshes serializes the refreshes of one process, across every Client over the
// same directory, before the file lock serializes them across processes.
var refreshes sync.Mutex

// Client returns an http.Client that calls the outlet as the signed-in person: every
// request carries the stored access token as a bearer token, a token that expires
// within a minute is refreshed first, and a request the outlet refuses with 401 and
// error="invalid_token" is sent once more with a refreshed token when its body can be
// sent again (no body, or GetBody set); otherwise the refusal is the answer. A request
// fails with ErrSignedOut when no pair is stored or the application refuses the
// refresh; the program calls Login again. The transport, cookie jar, redirect policy
// and timeout of cfg.HTTPClient are kept.
func Client(cfg *Config) (*http.Client, error) {
	c, err := cfg.resolve()
	if err != nil {
		return nil, err
	}
	next := c.sender.Transport
	if next == nil {
		next = http.DefaultTransport
	}

	return &http.Client{
		Transport: &transport{c: c, next: next}, CheckRedirect: c.sender.CheckRedirect, Jar: c.sender.Jar, Timeout: c.sender.Timeout,
	}, nil
}

// transport adds the bearer token to every request and refreshes it.
type transport struct {
	c    *client
	next http.RoundTripper
}

// RoundTrip sends req with the access token, refreshing it first when it is about to
// expire and once more when the outlet refuses it.
func (t *transport) RoundTrip(req *http.Request) (*http.Response, error) {
	ctx := req.Context()
	access, err := t.c.accessToken(ctx, "")
	if err != nil {
		closeBody(req)

		return nil, err
	}
	resp, err := t.next.RoundTrip(withBearer(req, req.Body, access))
	if err != nil {
		return nil, errors.Wrap(err, "http.RoundTripper.RoundTrip()")
	}
	if !refusedToken(resp) {
		return resp, nil
	}
	fresh, err := t.c.accessToken(ctx, access)
	if err != nil {
		discard(resp)

		return nil, err
	}
	body, ok := replayBody(req)
	if !ok {
		return resp, nil
	}
	discard(resp)
	resp, err = t.next.RoundTrip(withBearer(req, body, fresh))
	if err != nil {
		return nil, errors.Wrap(err, "http.RoundTripper.RoundTrip()")
	}

	return resp, nil
}

// withBearer is req with body and the bearer token, the request itself untouched as
// a RoundTripper leaves it.
func withBearer(req *http.Request, body io.ReadCloser, access string) *http.Request {
	r := req.Clone(req.Context())
	r.Body = body
	r.Header.Set("Authorization", "Bearer "+access)

	return r
}

// refusedToken reports whether resp refused the bearer token (RFC 6750, 3.1).
func refusedToken(resp *http.Response) bool {
	return resp.StatusCode == http.StatusUnauthorized && strings.Contains(resp.Header.Get("WWW-Authenticate"), `error="invalid_token"`)
}

// replayBody is req's body for a second send, and whether there is one: none when
// req carries none, a fresh one from GetBody, and nothing to replay otherwise.
func replayBody(req *http.Request) (io.ReadCloser, bool) {
	switch {
	case req.Body == nil || req.Body == http.NoBody:
		return req.Body, true
	case req.GetBody != nil:
		body, err := req.GetBody()
		if err != nil {
			return nil, false
		}

		return body, true
	default:
		return nil, false
	}
}

// closeBody closes req's body, as a RoundTripper that sends nothing must.
func closeBody(req *http.Request) {
	if req.Body != nil {
		_ = req.Body.Close()
	}
}

// discard reads resp's body out and closes it, so the connection is reused.
func discard(resp *http.Response) {
	_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, answerLimit))
	_ = resp.Body.Close()
}

// accessToken is the access token a request carries: the stored one while the
// outlet has not refused it and it is good for another minute, else the next pair's
// after a refresh. refused is the token the outlet just refused, "" before a send.
// ErrSignedOut when no pair is stored.
func (c *client) accessToken(ctx context.Context, refused string) (string, error) {
	rec, ok, err := c.store.read()
	if err != nil {
		return "", err
	}
	if !ok {
		return "", errors.Wrap(ErrSignedOut, "no sign-in is stored for "+c.server+" on the "+c.outlet+" outlet")
	}
	if rec.AccessToken != refused && time.Until(rec.AccessExpiresAt) >= refreshAhead {
		return rec.AccessToken, nil
	}
	next, err := c.refresh(ctx, rec)
	if err != nil {
		return "", err
	}

	return next.AccessToken, nil
}

// refresh exchanges earlier's refresh token for the next pair and stores it, unless
// another process did so while this one waited for the lock: a stored pair that
// differs from earlier is that rotation's result and is used as it is. The refresh
// token is presented once and never again, since a second presentation revokes the
// grant. A refresh the application refuses forgets the stored pair and is
// ErrSignedOut.
func (c *client) refresh(ctx context.Context, earlier *record) (*record, error) {
	refreshes.Lock()
	defer refreshes.Unlock()

	unlock, err := c.store.lock()
	if err != nil {
		return nil, err
	}
	defer unlock()

	current, ok, err := c.store.read()
	if err != nil {
		return nil, err
	}
	if !ok {
		return nil, errors.Wrap(ErrSignedOut, "the sign-in for "+c.server+" on the "+c.outlet+" outlet was forgotten")
	}
	if current.RefreshToken != earlier.RefreshToken {
		return current, nil
	}
	var pair tokenAnswer
	if err := c.post(ctx, tokenPath, map[string]string{"grant_type": grantRefreshToken, "refresh_token": current.RefreshToken}, &pair); err != nil {
		if errors.Is(err, ErrSignedOut) {
			if ferr := c.store.remove(); ferr != nil {
				return nil, ferr
			}
		}

		return nil, err
	}
	next := pair.record(time.Now())
	if err := c.store.write(next); err != nil {
		return nil, err
	}

	return next, nil
}
