package dbtype

import "time"

// SignInAttempts is a row of the sign-in attempts table: the failed password attempts
// on one name, known or not, within a window, and the lock those failures earned. It
// is keyed by the submitted name as the users table normalizes usernames, never by
// the user row, so an unknown name is counted exactly as a known one. Failures is the
// count in the window that ends at WindowEndsAt; LockedUntil is set once Failures
// reached the limit and the name is refused until then. WindowEndsAt and LockedUntil
// are the caller's deadlines, written as given; UpdatedAt is the database's time at the
// write.
type SignInAttempts struct {
	Name         string
	Failures     int64
	WindowEndsAt time.Time
	LockedUntil  *time.Time
	UpdatedAt    time.Time
}

// SignInAttemptLimit is the rule a failure is recorded under: Failures within Window
// lock the name for Lock.
type SignInAttemptLimit struct {
	Failures int
	Window   time.Duration
	Lock     time.Duration
}

// Locked reports whether the record holds its name at now, and the wait until it
// no longer does.
func (r *SignInAttempts) Locked(now time.Time) (wait time.Duration, locked bool) {
	if r == nil || r.LockedUntil == nil || !r.LockedUntil.After(now) {
		return 0, false
	}

	return r.LockedUntil.Sub(now), true
}

// Failed returns the record after a failure at now under limit, the one rule both
// drivers apply inside their transaction. A record that holds its name is left as it
// is: a failure during the lock changes nothing. Otherwise the failure counts in the
// current window, or opens a new one when there is no record, the window has ended or
// a lock has passed; the failure that reaches the limit locks the name until now plus
// limit.Lock. UpdatedAt is the driver's to stamp.
func (r *SignInAttempts) Failed(name string, now time.Time, limit SignInAttemptLimit) *SignInAttempts {
	if _, locked := r.Locked(now); locked {
		next := *r

		return &next
	}

	next := &SignInAttempts{Name: name, Failures: 1, WindowEndsAt: now.Add(limit.Window)}
	if r != nil && r.LockedUntil == nil && r.WindowEndsAt.After(now) {
		next.Failures = r.Failures + 1
		next.WindowEndsAt = r.WindowEndsAt
	}
	if next.Failures >= int64(limit.Failures) {
		lockedUntil := now.Add(limit.Lock)
		next.LockedUntil = &lockedUntil
	}

	return next
}
