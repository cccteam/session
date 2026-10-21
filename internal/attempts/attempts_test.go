package attempts

import (
	"context"
	"fmt"
	"sync"
	"testing"
	"time"

	"github.com/cccteam/httpio"
	"github.com/cccteam/session/internal/dbtype"
	"github.com/go-playground/errors/v5"
)

// fakeStore is a Store over a map, applying the rule as the drivers do, that counts
// its calls.
type fakeStore struct {
	mu      sync.Mutex
	now     func() time.Time
	records map[string]*dbtype.SignInAttempts
	reads   int
	writes  int
	clears  int
	fail    error
}

func newFakeStore(now func() time.Time) *fakeStore {
	return &fakeStore{now: now, records: map[string]*dbtype.SignInAttempts{}}
}

func (s *fakeStore) SignInAttempts(_ context.Context, name string) (*dbtype.SignInAttempts, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	s.reads++
	if s.fail != nil {
		return nil, s.fail
	}
	r, found := s.records[name]
	if !found {
		return nil, httpio.NewNotFoundMessage("no sign-in attempts recorded")
	}
	copied := *r

	return &copied, nil
}

func (s *fakeStore) RecordSignInFailure(_ context.Context, name string, limit dbtype.SignInAttemptLimit) (*dbtype.SignInAttempts, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	s.writes++
	if s.fail != nil {
		return nil, s.fail
	}
	next := s.records[name].Failed(name, s.now(), limit)
	s.records[name] = next
	copied := *next

	return &copied, nil
}

func (s *fakeStore) ClearSignInAttempts(_ context.Context, name string) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	s.clears++
	delete(s.records, name)

	return nil
}

func (s *fakeStore) record(name string) *dbtype.SignInAttempts {
	s.mu.Lock()
	defer s.mu.Unlock()

	return s.records[name]
}

// clock is a settable test clock.
type clock struct {
	mu sync.Mutex
	t  time.Time
}

func (c *clock) now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()

	return c.t
}

func (c *clock) advance(d time.Duration) {
	c.mu.Lock()
	defer c.mu.Unlock()

	c.t = c.t.Add(d)
}

var testLimit = dbtype.SignInAttemptLimit{Failures: 3, Window: 15 * time.Minute, Lock: 10 * time.Minute}

func newLimiter(t *testing.T) (*Limiter, *fakeStore, *clock) {
	t.Helper()

	c := &clock{t: time.Date(2026, 10, 21, 12, 0, 0, 0, time.UTC)}
	store := newFakeStore(c.now)
	l := New(testLimit, store)
	l.SetClock(c.now)

	return l, store, c
}

// fail runs one failed attempt: the check lets it through, the failure is recorded.
func fail(ctx context.Context, t *testing.T, l *Limiter, name string, client Client) {
	t.Helper()

	if wait, err := l.Check(ctx, name, client); err != nil || wait != 0 {
		t.Fatalf("Check(%q) before the failure = %v, %v; want to go on", name, wait, err)
	}
	if _, err := l.Failed(ctx, name, client); err != nil {
		t.Fatalf("Failed(%q) error = %v", name, err)
	}
}

func TestNormalize(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		in   string
		want string
	}{
		{name: "a name is case-folded", in: "Pat@Lakeside.EDU", want: "pat@lakeside.edu"},
		{name: "a composed and a decomposed spelling are one name", in: "résumé", want: "résumé"},
		{name: "a folded name stays as it is", in: "pat", want: "pat"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			if got := Normalize(tt.in); got != tt.want {
				t.Errorf("Normalize(%q) = %q, want %q", tt.in, got, tt.want)
			}
		})
	}
}

func TestLimiter_NameLock(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		run  func(ctx context.Context, t *testing.T, l *Limiter, store *fakeStore, c *clock)
	}{
		{
			name: "the failure that reaches the limit locks the name, and the next attempt is refused from memory with the wait and no store read",
			run: func(ctx context.Context, t *testing.T, l *Limiter, store *fakeStore, _ *clock) {
				for range testLimit.Failures {
					fail(ctx, t, l, "Pat", Client{Address: "10.0.0.1"})
				}
				reads := store.reads
				wait, err := l.Check(ctx, "pat", Client{Address: "10.0.0.1"})
				if err != nil || wait != testLimit.Lock {
					t.Errorf("Check() after the limit = %v, %v; want the lock period %v", wait, err, testLimit.Lock)
				}
				if store.reads != reads {
					t.Errorf("store reads during the lock = %d, want none beyond %d", store.reads, reads)
				}
			},
		},
		{
			name: "a lock in the store is learned by the first check and then refused from memory",
			run: func(ctx context.Context, t *testing.T, l *Limiter, store *fakeStore, c *clock) {
				lockedUntil := c.now().Add(4 * time.Minute)
				store.records[Normalize("pat")] = &dbtype.SignInAttempts{Name: "pat", Failures: 3, WindowEndsAt: c.now().Add(time.Hour), LockedUntil: &lockedUntil}
				if wait, err := l.Check(ctx, "pat", Client{}); err != nil || wait != 4*time.Minute {
					t.Fatalf("Check() = %v, %v; want the store's wait of 4m", wait, err)
				}
				reads := store.reads
				c.advance(time.Minute)
				if wait, err := l.Check(ctx, "pat", Client{}); err != nil || wait != 3*time.Minute {
					t.Errorf("Check() a minute later = %v, %v; want 3m", wait, err)
				}
				if store.reads != reads {
					t.Errorf("store reads = %d, want %d: the lock answers from memory", store.reads, reads)
				}
			},
		},
		{
			name: "the lock passes with time and the name may try again",
			run: func(ctx context.Context, t *testing.T, l *Limiter, _ *fakeStore, c *clock) {
				for range testLimit.Failures {
					fail(ctx, t, l, "pat", Client{})
				}
				c.advance(testLimit.Lock + time.Second)
				if wait, err := l.Check(ctx, "pat", Client{}); err != nil || wait != 0 {
					t.Errorf("Check() after the lock = %v, %v; want to go on", wait, err)
				}
			},
		},
		{
			name: "failures outside the window do not add up",
			run: func(ctx context.Context, t *testing.T, l *Limiter, store *fakeStore, c *clock) {
				fail(ctx, t, l, "pat", Client{})
				fail(ctx, t, l, "pat", Client{})
				c.advance(testLimit.Window + time.Second)
				fail(ctx, t, l, "pat", Client{})
				if wait, err := l.Check(ctx, "pat", Client{}); err != nil || wait != 0 {
					t.Errorf("Check() = %v, %v; want to go on: the window ended", wait, err)
				}
				if r := store.record(Normalize("pat")); r == nil || r.Failures != 1 {
					t.Errorf("record = %+v, want one failure in a new window", r)
				}
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			l, store, c := newLimiter(t)
			tt.run(t.Context(), t, l, store, c)
		})
	}
}

// TestLimiter_NameResetAndCache covers what resets a name and how the store is read.
func TestLimiter_NameResetAndCache(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		run  func(ctx context.Context, t *testing.T, l *Limiter, store *fakeStore, c *clock)
	}{
		{
			name: "a success resets the name and deletes the record it saw; a name with no record is not written",
			run: func(ctx context.Context, t *testing.T, l *Limiter, store *fakeStore, _ *clock) {
				fail(ctx, t, l, "pat", Client{})
				fail(ctx, t, l, "pat", Client{})
				if _, err := l.Check(ctx, "pat", Client{}); err != nil {
					t.Fatal(err)
				}
				if err := l.Succeeded(ctx, "pat"); err != nil {
					t.Fatalf("Succeeded() error = %v", err)
				}
				if store.clears != 1 || store.record(Normalize("pat")) != nil {
					t.Errorf("clears = %d, record = %v; want the record deleted once", store.clears, store.record(Normalize("pat")))
				}
				if _, err := l.Check(ctx, "sam", Client{}); err != nil {
					t.Fatal(err)
				}
				if err := l.Succeeded(ctx, "sam"); err != nil {
					t.Fatalf("Succeeded() error = %v", err)
				}
				if store.clears != 1 {
					t.Errorf("clears after a success with no record = %d, want still 1", store.clears)
				}
			},
		},
		{
			name: "a clear resets the name whatever memory holds",
			run: func(ctx context.Context, t *testing.T, l *Limiter, store *fakeStore, _ *clock) {
				for range testLimit.Failures {
					fail(ctx, t, l, "pat", Client{})
				}
				if err := l.Clear(ctx, "pat"); err != nil {
					t.Fatalf("Clear() error = %v", err)
				}
				if wait, err := l.Check(ctx, "pat", Client{}); err != nil || wait != 0 {
					t.Errorf("Check() after the clear = %v, %v; want to go on", wait, err)
				}
				if store.clears != 1 {
					t.Errorf("clears = %d, want 1", store.clears)
				}
			},
		},
		{
			name: "a name spelled in another case is the same name",
			run: func(ctx context.Context, t *testing.T, l *Limiter, _ *fakeStore, _ *clock) {
				fail(ctx, t, l, "Pat@Lakeside.edu", Client{})
				fail(ctx, t, l, "pat@lakeside.EDU", Client{})
				fail(ctx, t, l, "PAT@LAKESIDE.EDU", Client{})
				if wait, _ := l.Check(ctx, "pat@lakeside.edu", Client{}); wait == 0 {
					t.Error("Check() = 0 after three failures under one name in three spellings, want the lock")
				}
			},
		},
		{
			name: "a store read within the TTL is not repeated; one after it is",
			run: func(ctx context.Context, t *testing.T, l *Limiter, store *fakeStore, c *clock) {
				if _, err := l.Check(ctx, "pat", Client{}); err != nil {
					t.Fatal(err)
				}
				if _, err := l.Check(ctx, "pat", Client{}); err != nil {
					t.Fatal(err)
				}
				if store.reads != 1 {
					t.Errorf("reads = %d, want 1 within the TTL", store.reads)
				}
				c.advance(readTTL + time.Second)
				if _, err := l.Check(ctx, "pat", Client{}); err != nil {
					t.Fatal(err)
				}
				if store.reads != 2 {
					t.Errorf("reads = %d, want 2 after the TTL", store.reads)
				}
			},
		},
		{
			name: "a store failure on the check is reported",
			run: func(ctx context.Context, t *testing.T, l *Limiter, store *fakeStore, _ *clock) {
				store.fail = errors.New("store down")
				if _, err := l.Check(ctx, "pat", Client{}); err == nil {
					t.Error("Check() error = nil, want the store's failure")
				}
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			l, store, c := newLimiter(t)
			tt.run(t.Context(), t, l, store, c)
		})
	}
}

func TestLimiter_ClientKeys(t *testing.T) {
	t.Parallel()

	clientLimit := ClientMultiple * testLimit.Failures

	tests := []struct {
		name string
		run  func(ctx context.Context, t *testing.T, l *Limiter, store *fakeStore, c *clock)
	}{
		{
			name: "early retries during a name's lock count against the client's address and cookie, not the name",
			run: func(ctx context.Context, t *testing.T, l *Limiter, store *fakeStore, _ *clock) {
				client := Client{Address: "10.0.0.1", Cookie: "tok"}
				for range testLimit.Failures {
					fail(ctx, t, l, "pat", client)
				}
				locked := *store.record(Normalize("pat"))
				for range clientLimit {
					if wait, err := l.Check(ctx, "pat", client); err != nil || wait == 0 {
						t.Fatalf("Check() during the lock = %v, %v; want a wait", wait, err)
					}
				}
				if r := store.record(Normalize("pat")); *r != locked {
					t.Errorf("the name's record changed during the retries: %+v, want %+v", r, locked)
				}
				// The client is now locked on its own: another name from it is refused
				// with no store read, and each retry extends the client's lock.
				reads := store.reads
				if wait, err := l.Check(ctx, "sam", client); err != nil || wait != testLimit.Lock {
					t.Errorf("Check() of another name from the locked client = %v, %v; want the lock period", wait, err)
				}
				if store.reads != reads {
					t.Errorf("store reads for a locked client = %d, want none beyond %d", store.reads, reads)
				}
			},
		},
		{
			name: "a client's failures across names lock the client at the client's limit, and a success for one name leaves the client's count",
			run: func(ctx context.Context, t *testing.T, l *Limiter, _ *fakeStore, _ *clock) {
				client := Client{Address: "10.0.0.1"}
				for i := range clientLimit - 1 {
					fail(ctx, t, l, fmt.Sprintf("name-%d", i), client)
				}
				if wait, _ := l.Check(ctx, "another", client); wait != 0 {
					t.Fatalf("Check() one short of the client's limit = %v, want to go on", wait)
				}
				if err := l.Succeeded(ctx, "name-0"); err != nil {
					t.Fatal(err)
				}
				fail(ctx, t, l, "last", client)
				if wait, _ := l.Check(ctx, "yet-another", client); wait != testLimit.Lock {
					t.Errorf("Check() at the client's limit = %v, want the lock period", wait)
				}
			},
		},
		{
			name: "a client's lock extends with every retry while the name's wait is reported when longer",
			run: func(ctx context.Context, t *testing.T, l *Limiter, _ *fakeStore, c *clock) {
				client := Client{Cookie: "tok"}
				for range clientLimit {
					fail(ctx, t, l, fmt.Sprintf("n%d", c.now().UnixNano()), client)
					c.advance(time.Millisecond)
				}
				c.advance(testLimit.Lock - time.Minute)
				if wait, _ := l.Check(ctx, "x", client); wait != testLimit.Lock {
					t.Errorf("Check() during the client's lock = %v, want it extended to the full lock period", wait)
				}
				c.advance(testLimit.Lock + time.Second)
				if wait, _ := l.Check(ctx, "x", client); wait != 0 {
					t.Errorf("Check() once the client's lock passed without retries = %v, want to go on", wait)
				}
			},
		},
		{
			name: "a client cycling cookies is held by its address; one with no keys is held by the name alone",
			run: func(ctx context.Context, t *testing.T, l *Limiter, _ *fakeStore, _ *clock) {
				for i := range clientLimit {
					fail(ctx, t, l, fmt.Sprintf("n%d", i), Client{Address: "10.0.0.1", Cookie: fmt.Sprintf("c%d", i)})
				}
				if wait, _ := l.Check(ctx, "x", Client{Address: "10.0.0.1", Cookie: "fresh"}); wait == 0 {
					t.Error("Check() from the address with a fresh cookie = 0, want the address's lock")
				}
				if wait, _ := l.Check(ctx, "x", Client{}); wait != 0 {
					t.Errorf("Check() with no client keys = %v, want to go on", wait)
				}
			},
		},
		{
			name: "the memory is bounded: a flood of names evicts the oldest entries and holds no more than the cap",
			run: func(ctx context.Context, t *testing.T, l *Limiter, store *fakeStore, _ *clock) {
				for i := range cacheSize + 100 {
					if _, err := l.Check(ctx, fmt.Sprintf("flood-%d", i), Client{Address: fmt.Sprintf("10.%d.%d.%d", i>>16&255, i>>8&255, i&255)}); err != nil {
						t.Fatal(err)
					}
				}
				l.mu.Lock()
				n := len(l.entries)
				l.mu.Unlock()
				if n > cacheSize {
					t.Errorf("entries = %d, want at most %d", n, cacheSize)
				}
				// The first name was evicted, so it is read from the store again.
				reads := store.reads
				if _, err := l.Check(ctx, "flood-0", Client{}); err != nil {
					t.Fatal(err)
				}
				if store.reads != reads+1 {
					t.Errorf("reads = %d, want %d: the evicted name is read again", store.reads, reads+1)
				}
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			l, store, c := newLimiter(t)
			tt.run(t.Context(), t, l, store, c)
		})
	}
}
