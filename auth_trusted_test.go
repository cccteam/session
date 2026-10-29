package session

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/base64"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/cccteam/ccc"
	"github.com/cccteam/session/cookie"
	"go.uber.org/mock/gomock"
)

// The trusted device cookie's shapes: one entry per user, read for the signing-in user
// alone; the one-token shape of earlier releases; the cap; and what a held sign-in
// drops. The rows are not involved: these are the cookie's own rules.

// trustedCookieHarness is an Auth over a mock store with the helpers the trusted device
// cookie tests share.
type trustedCookieHarness struct {
	t *testing.T
	a *Auth[NoCustomData, NoCustomData, mockTx]
}

func newTrustedCookieHarness(t *testing.T) *trustedCookieHarness {
	t.Helper()

	a, err := NewAuth[NoCustomData, NoCustomData](newAuthStoreMock(gomock.NewController(t)), cookieKey)
	if err != nil {
		t.Fatalf("NewAuth() error = %v", err)
	}

	return &trustedCookieHarness{t: t, a: a}
}

func (h *trustedCookieHarness) newUser() ccc.UUID {
	h.t.Helper()

	id, err := ccc.NewUUID()
	if err != nil {
		h.t.Fatalf("ccc.NewUUID() error = %v", err)
	}

	return id
}

func (h *trustedCookieHarness) newToken() (hash []byte, token string) {
	h.t.Helper()

	raw := make([]byte, trustedTokenSize)
	if _, err := rand.Read(raw); err != nil {
		h.t.Fatalf("rand.Read() error = %v", err)
	}

	return hashPendingToken(raw), base64.RawURLEncoding.EncodeToString(raw)
}

// written writes cval as the trusted device cookie and returns the cookies set.
func (h *trustedCookieHarness) written(cval *cookie.Values) []*http.Cookie {
	rr := httptest.NewRecorder()
	h.a.trustedCookies.Cookie().WritePersistentCookie(rr, h.a.settings.factors.trustedCookie, h.a.trustedCookies.Domain, true, http.SameSiteLaxMode, time.Hour, cval)

	return rr.Result().Cookies()
}

// entriesWritten writes the entries as the trusted device cookie and returns the cookies set.
func (h *trustedCookieHarness) entriesWritten(entries map[string]trustedEntry) []*http.Cookie {
	h.t.Helper()

	cval := cookie.NewValues()
	if err := cval.Set(trustedDevicesKey, entries); err != nil {
		h.t.Fatalf("Set() error = %v", err)
	}

	return h.written(cval)
}

// ctxWith is the context StartSession gives a request carrying cookies.
func (h *trustedCookieHarness) ctxWith(cookies []*http.Cookie) context.Context {
	r := httptest.NewRequestWithContext(context.Background(), http.MethodGet, "/", http.NoBody)
	for _, c := range cookies {
		r.AddCookie(c)
	}

	return h.a.withTrustedDeviceCookie(context.Background(), r)
}

// entriesOf reads the entries from the cookies a response set: absent when none was
// set, deleted when the cookie was deleted.
func (h *trustedCookieHarness) entriesOf(cookies []*http.Cookie) (entries map[string]trustedEntry, deleted, absent bool) {
	h.t.Helper()

	if len(cookies) == 0 {
		return nil, false, true
	}
	if cookies[0].MaxAge < 0 || cookies[0].Value == "" {
		return nil, true, false
	}
	r := httptest.NewRequestWithContext(context.Background(), http.MethodGet, "/", http.NoBody)
	r.AddCookie(cookies[0])
	cval, found, err := h.a.trustedCookies.Cookie().Read(r, h.a.settings.factors.trustedCookie)
	if err != nil || !found {
		h.t.Fatalf("Read() = found %v, error %v", found, err)
	}
	entries = map[string]trustedEntry{}
	if err := cval.Get(trustedDevicesKey, &entries); err != nil {
		h.t.Fatalf("Get(devices) error = %v", err)
	}

	return entries, false, false
}

func TestTrustedDeviceCookie_Shapes(t *testing.T) {
	t.Parallel()

	h := newTrustedCookieHarness(t)
	newUser, newToken, written, ctxWith := h.newUser, h.newToken, h.written, h.ctxWith

	t.Run("the one-token shape of earlier releases stands for whichever user's device its row names", func(t *testing.T) {
		t.Parallel()

		hash, token := newToken()
		ctx := ctxWith(written(cookie.NewValues().SetString(trustedCookieKey, token)))
		for _, u := range []ccc.UUID{newUser(), newUser()} {
			if got, ok := trustedHashFor(ctx, u); !ok || !bytes.Equal(got, hash) {
				t.Errorf("trustedHashFor(%s) = %x, %v; want the bare token's hash", u, got, ok)
			}
		}
	})

	t.Run("one entry per user: a sign-in reads the signing-in user's token alone", func(t *testing.T) {
		t.Parallel()

		pat, sam, kim := newUser(), newUser(), newUser()
		patHash, patToken := newToken()
		samHash, samToken := newToken()
		cval := cookie.NewValues()
		if err := cval.Set(trustedDevicesKey, map[string]trustedEntry{pat.String(): {Token: patToken, At: 1}, sam.String(): {Token: samToken, At: 2}}); err != nil {
			t.Fatalf("Set() error = %v", err)
		}
		ctx := ctxWith(written(cval))
		if got, ok := trustedHashFor(ctx, pat); !ok || !bytes.Equal(got, patHash) {
			t.Errorf("trustedHashFor(pat) = %x, %v; want pat's token's hash", got, ok)
		}
		if got, ok := trustedHashFor(ctx, sam); !ok || !bytes.Equal(got, samHash) {
			t.Errorf("trustedHashFor(sam) = %x, %v; want sam's token's hash", got, ok)
		}
		if got, ok := trustedHashFor(ctx, kim); ok {
			t.Errorf("trustedHashFor(kim) = %x, %v; want none: kim was never remembered here", got, ok)
		}
		if _, ok := trustedHashFor(context.Background(), pat); ok {
			t.Error("trustedHashFor() without a cookie = ok; want none")
		}
	})

	t.Run("remembering one more person than the cap drops the oldest entry, never the one being written", func(t *testing.T) {
		t.Parallel()

		carried := map[string]trustedEntry{}
		users := make([]ccc.UUID, 0, trustedDevicesPerBrowser)
		for i := range trustedDevicesPerBrowser {
			u := newUser()
			users = append(users, u)
			_, token := newToken()
			carried[u.String()] = trustedEntry{Token: token, At: int64(10 + i)}
		}
		// The second person is the oldest by a later write of the others.
		carried[users[1].String()] = trustedEntry{Token: carried[users[1].String()].Token, At: 1}
		newcomer := newUser()
		_, token := newToken()
		got := trustedEntriesWith(carried, newcomer, trustedEntry{Token: token, At: 100})
		if len(got) != trustedDevicesPerBrowser {
			t.Fatalf("entries after the cap = %d, want %d", len(got), trustedDevicesPerBrowser)
		}
		if _, ok := got[users[1].String()]; ok {
			t.Error("the oldest entry survived the cap")
		}
		if e, ok := got[newcomer.String()]; !ok || e.Token != token {
			t.Error("the entry being written did not survive the cap")
		}
		if len(carried) != trustedDevicesPerBrowser || carried[users[1].String()].At != 1 {
			t.Error("the browser's own map was changed")
		}
		// A person remembered again replaces their own entry and drops nobody.
		again := trustedEntriesWith(got, newcomer, trustedEntry{Token: "replaced", At: 200})
		if len(again) != trustedDevicesPerBrowser || again[newcomer.String()].Token != "replaced" {
			t.Errorf("remembering again = %d entries, token %q; want the same %d with the entry replaced", len(again), again[newcomer.String()].Token, trustedDevicesPerBrowser)
		}
	})
}

func TestTrustedDeviceCookie_HeldSignIn(t *testing.T) {
	t.Parallel()

	h := newTrustedCookieHarness(t)
	a, newUser, newToken, written, ctxWith, entriesOf := h.a, h.newUser, h.newToken, h.written, h.ctxWith, h.entriesOf

	t.Run("a held sign-in drops the signing-in user's entry alone, deletes the cookie when nothing is left, and leaves a browser without their entry alone", func(t *testing.T) {
		t.Parallel()

		pat, sam, kim := newUser(), newUser(), newUser()
		_, patToken := newToken()
		_, samToken := newToken()
		both := cookie.NewValues()
		if err := both.Set(trustedDevicesKey, map[string]trustedEntry{pat.String(): {Token: patToken, At: 1}, sam.String(): {Token: samToken, At: 2}}); err != nil {
			t.Fatalf("Set() error = %v", err)
		}
		bothCookies := written(both)

		// kim is held: nothing of pat's or sam's goes, and the cookie is not rewritten.
		rr := httptest.NewRecorder()
		a.dropTrustedEntry(ctxWith(bothCookies), rr, ccc.NullUUID{UUID: kim, Valid: true})
		if _, _, absent := entriesOf(rr.Result().Cookies()); !absent {
			t.Error("a held sign-in of a person the browser never remembered rewrote the cookie")
		}

		// pat is held: pat's entry goes, sam's stays.
		rr = httptest.NewRecorder()
		a.dropTrustedEntry(ctxWith(bothCookies), rr, ccc.NullUUID{UUID: pat, Valid: true})
		entries, deleted, absent := entriesOf(rr.Result().Cookies())
		if deleted || absent || len(entries) != 1 || entries[sam.String()].Token != samToken {
			t.Errorf("after pat's held sign-in: entries %v, deleted %v, absent %v; want sam's entry alone", entries, deleted, absent)
		}

		// sam is held on that browser: nothing is left, so the cookie goes.
		rr2 := httptest.NewRecorder()
		a.dropTrustedEntry(ctxWith(rr.Result().Cookies()), rr2, ccc.NullUUID{UUID: sam, Valid: true})
		if _, deleted, _ := entriesOf(rr2.Result().Cookies()); !deleted {
			t.Error("the last entry's held sign-in left the cookie standing")
		}

		// The old shape: a held sign-in drops the bare token, as before.
		_, legacy := newToken()
		rr3 := httptest.NewRecorder()
		a.dropTrustedEntry(ctxWith(written(cookie.NewValues().SetString(trustedCookieKey, legacy))), rr3, ccc.NullUUID{UUID: pat, Valid: true})
		if _, deleted, _ := entriesOf(rr3.Result().Cookies()); !deleted {
			t.Error("a held sign-in left the one-token cookie standing")
		}
	})
}
