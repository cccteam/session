// Package attempts limits the failed password attempts of an Auth. It runs in memory,
// per instance, before any store access and before the password hash, over a durable
// record the store keeps by the submitted name. The memory holds three kinds of key: the
// name, the client's address and the login's XSRF cookie token. A name is held by its
// store record, cached here until its lock passes, so an attempt during the lock is
// refused the moment it arrives with nothing read, written or hashed. The client's keys
// are counted here alone: every failure and every refused attempt counts against them,
// and a client that keeps trying during a wait extends its own lock while the name's
// stays as it was. The memory is bounded; the store is the truth for the name.
package attempts

import (
	"container/list"
	"context"
	"crypto/sha256"
	"sync"
	"time"

	"github.com/cccteam/httpio"
	"github.com/cccteam/session/internal/dbtype"
	"github.com/go-playground/errors/v5"
	"golang.org/x/text/cases"
	"golang.org/x/text/unicode/norm"
)

// Store keeps the durable record of a name's attempts.
type Store interface {
	// SignInAttempts returns name's record, or NotFound when there is none.
	SignInAttempts(ctx context.Context, name string) (*dbtype.SignInAttempts, error)
	// RecordSignInFailure records a failure on name under limit and returns the record.
	RecordSignInFailure(ctx context.Context, name string, limit dbtype.SignInAttemptLimit) (*dbtype.SignInAttempts, error)
	// ClearSignInAttempts deletes name's record.
	ClearSignInAttempts(ctx context.Context, name string) error
}

// Client identifies the client of an attempt: its address and its login's XSRF cookie
// token. Either is empty when unknown, as both are for an attempt through the API.
type Client struct {
	Address string
	Cookie  string
}

const (
	// cacheSize bounds the entries the memory holds across every kind of key; the
	// least recently used entry goes when it is full, so a flood of names grows nothing
	// without limit. A name's lock evicted from memory is still the store's.
	cacheSize = 16384
	// readTTL is how long a name's store record is trusted before the next attempt
	// reads it again. A lock is trusted until it passes.
	readTTL = 5 * time.Second
	// ClientMultiple is how many times the name limit's failures a client's address or
	// cookie may fail, across names, within the window before the client is locked for
	// the lock period.
	ClientMultiple = 10
)

// Limiter is the in-memory layer over a Store.
type Limiter struct {
	limit dbtype.SignInAttemptLimit
	store Store
	now   func() time.Time

	mu      sync.Mutex
	entries map[string]*list.Element
	order   *list.List
}

// entry is one key's state. A name's entry caches the store's record, nil for none, and
// when it was read. A client's entry is its counter: failures in the window ending at
// windowEnds, and the lock they earned.
type entry struct {
	key         string
	record      *dbtype.SignInAttempts
	readAt      time.Time
	failures    int
	windowEnds  time.Time
	lockedUntil time.Time
}

// New returns a limiter under limit over store.
func New(limit dbtype.SignInAttemptLimit, store Store) *Limiter {
	return &Limiter{limit: limit, store: store, now: time.Now, entries: make(map[string]*list.Element), order: list.New()}
}

// Limit returns the limit the limiter counts under.
func (l *Limiter) Limit() dbtype.SignInAttemptLimit {
	return l.limit
}

// SetClock replaces the limiter's clock, for tests that move time.
func (l *Limiter) SetClock(now func() time.Time) {
	l.mu.Lock()
	defer l.mu.Unlock()

	l.now = now
}

// Normalize returns name as the key its attempts are counted under: Unicode NFC and
// case-folded, as the users table normalizes usernames, so a name spelled in another
// case is the same name.
func Normalize(name string) string {
	return cases.Fold().String(norm.NFC.String(name))
}

// Check decides whether an attempt on name by client goes on to the user lookup and the
// hash: wait is zero when it does, and otherwise how long the caller is to wait. The
// name's lock answers from memory when it is cached and from the store when it is not,
// the client's locks from memory alone, and a refused attempt counts against the
// client's keys and never against the name. err is a store failure.
func (l *Limiter) Check(ctx context.Context, name string, client Client) (wait time.Duration, err error) {
	key := Normalize(name)

	l.mu.Lock()
	now := l.now()
	nameWait, cached := l.nameHeld(key, now)
	clientWait := l.clientHeld(client, now)
	if nameWait > 0 || clientWait > 0 {
		defer l.mu.Unlock()

		return max(nameWait, l.countClient(client, now)), nil
	}
	if cached {
		l.mu.Unlock()

		return 0, nil
	}
	l.mu.Unlock()

	record, err := l.read(ctx, key)
	if err != nil {
		return 0, err
	}

	l.mu.Lock()
	defer l.mu.Unlock()

	now = l.now()
	e := l.entry(nameKey(key))
	e.record, e.readAt = record, now
	if nameWait, locked := record.Locked(now); locked {
		return max(nameWait, l.countClient(client, now)), nil
	}

	return 0, nil
}

// Failed records a failed attempt on name by client: in the store under the limit, and
// against the client's keys in memory. The record the store answers is kept in memory,
// and lock is how long it now holds the name, zero while it does not.
func (l *Limiter) Failed(ctx context.Context, name string, client Client) (lock time.Duration, err error) {
	key := Normalize(name)
	record, err := l.store.RecordSignInFailure(ctx, key, l.limit)

	l.mu.Lock()
	defer l.mu.Unlock()

	now := l.now()
	l.countClient(client, now)
	if err != nil {
		return 0, errors.Wrap(err, "sessionstorage.AuthStore.RecordSignInFailure()")
	}
	e := l.entry(nameKey(key))
	e.record, e.readAt = record, now
	lock, _ = record.Locked(now)

	return lock, nil
}

// Succeeded resets name after a successful password check: the store's record is
// deleted when the attempt saw one, and the name leaves memory.
func (l *Limiter) Succeeded(ctx context.Context, name string) error {
	key := Normalize(name)

	l.mu.Lock()
	el, found := l.entries[nameKey(key)]
	seen := found && valueOf(el).record != nil && valueOf(el).record.Failures > 0
	l.drop(nameKey(key))
	l.mu.Unlock()

	if !seen {
		return nil
	}

	return l.clear(ctx, key)
}

// Clear resets name whatever memory holds: an MFA completion or a password change.
func (l *Limiter) Clear(ctx context.Context, name string) error {
	key := Normalize(name)

	l.mu.Lock()
	l.drop(nameKey(key))
	l.mu.Unlock()

	return l.clear(ctx, key)
}

func (l *Limiter) clear(ctx context.Context, key string) error {
	if err := l.store.ClearSignInAttempts(ctx, key); err != nil {
		return errors.Wrap(err, "sessionstorage.AuthStore.ClearSignInAttempts()")
	}

	return nil
}

// read reads key's record from the store. A name with no record answers the zero
// record, which holds nothing, so the cache remembers that the store was asked.
func (l *Limiter) read(ctx context.Context, key string) (*dbtype.SignInAttempts, error) {
	record, err := l.store.SignInAttempts(ctx, key)
	if err != nil {
		if httpio.HasNotFound(err) {
			return &dbtype.SignInAttempts{Name: key}, nil
		}

		return nil, errors.Wrap(err, "sessionstorage.AuthStore.SignInAttempts()")
	}

	return record, nil
}

// nameHeld answers from memory: the wait while the cached record locks the name, and
// whether the cache answers at all (a lock until it passes, a record for readTTL).
func (l *Limiter) nameHeld(key string, now time.Time) (wait time.Duration, cached bool) {
	el, found := l.entries[nameKey(key)]
	if !found {
		return 0, false
	}
	e := valueOf(el)
	l.order.MoveToFront(el)
	if wait, locked := e.record.Locked(now); locked {
		return wait, true
	}

	return 0, now.Before(e.readAt.Add(readTTL))
}

// clientHeld is the longest wait the client's keys hold.
func (l *Limiter) clientHeld(client Client, now time.Time) time.Duration {
	var wait time.Duration
	for _, key := range clientKeys(client) {
		if el, found := l.entries[key]; found {
			e := valueOf(el)
			l.order.MoveToFront(el)
			wait = max(wait, e.lockedUntil.Sub(now))
		}
	}

	return max(wait, 0)
}

// countClient counts one failed or refused attempt against the client's keys and
// returns the longest wait they then hold: a key in its lock is extended by the lock
// period, one past its window starts a new one, and the failure that reaches the
// client's limit locks it.
func (l *Limiter) countClient(client Client, now time.Time) time.Duration {
	var wait time.Duration
	for _, key := range clientKeys(client) {
		e := l.entry(key)
		switch {
		case e.lockedUntil.After(now):
			e.lockedUntil = now.Add(l.limit.Lock)
		default:
			if !e.windowEnds.After(now) {
				e.failures, e.windowEnds = 0, now.Add(l.limit.Window)
			}
			e.failures++
			if e.failures >= ClientMultiple*l.limit.Failures {
				e.lockedUntil = now.Add(l.limit.Lock)
			}
		}
		wait = max(wait, e.lockedUntil.Sub(now))
	}

	return max(wait, 0)
}

// entry returns key's entry, making one when there is none and evicting the least
// recently used entry when the memory is full.
func (l *Limiter) entry(key string) *entry {
	if el, found := l.entries[key]; found {
		l.order.MoveToFront(el)

		return valueOf(el)
	}
	e := &entry{key: key}
	l.entries[key] = l.order.PushFront(e)
	for l.order.Len() > cacheSize {
		oldest := l.order.Back()
		l.order.Remove(oldest)
		delete(l.entries, valueOf(oldest).key)
	}

	return e
}

// valueOf is the entry an element of the order holds.
func valueOf(el *list.Element) *entry {
	e, _ := el.Value.(*entry)

	return e
}

func (l *Limiter) drop(key string) {
	if el, found := l.entries[key]; found {
		l.order.Remove(el)
		delete(l.entries, key)
	}
}

// Keys are a kind and the SHA-256 of the value, so an entry costs the same whatever
// the value's length.
const (
	kindName    = 'n'
	kindAddress = 'a'
	kindCookie  = 'c'
)

func keyOf(kind byte, value string) string {
	sum := sha256.Sum256([]byte(value))

	return string(append([]byte{kind}, sum[:]...))
}

func nameKey(normalized string) string {
	return keyOf(kindName, normalized)
}

func clientKeys(client Client) []string {
	keys := make([]string, 0, 2)
	if client.Address != "" {
		keys = append(keys, keyOf(kindAddress, client.Address))
	}
	if client.Cookie != "" {
		keys = append(keys, keyOf(kindCookie, client.Cookie))
	}

	return keys
}
