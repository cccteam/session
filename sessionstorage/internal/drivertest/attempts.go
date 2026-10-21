package drivertest

import (
	"context"
	"fmt"
	"sync"
	"testing"
	"time"

	"github.com/cccteam/httpio"
	"github.com/cccteam/session/internal/dbtype"
	"github.com/google/go-cmp/cmp"
	"github.com/google/go-cmp/cmp/cmpopts"
)

// The sign-in attempts table holds the failed password attempts on a name within a
// window and the lock they earned, keyed by the name and never by a user row. These
// cases check, on every backend, that a failure is recorded under the one rule
// (dbtype.SignInAttempts.Failed) at the time the caller names, with the database's
// time on the write; that an unknown name is recorded as a known one; that a clear
// deletes the record; and that concurrent failures each count.

// attemptsOpts compares records but for UpdatedAt, which the database writes and the
// cases check apart.
var attemptsOpts = cmp.Options{cmpopts.IgnoreFields(dbtype.SignInAttempts{}, "UpdatedAt")}

// attemptLimit is the limit these cases record under.
var attemptLimit = dbtype.SignInAttemptLimit{Failures: 3, Window: 15 * time.Minute, Lock: 10 * time.Minute}

func testSignInAttemptsRecorded(ctx context.Context, t *testing.T, h *AuthHarness) {
	in := h.New(ctx, t, Auth, AuthConfig{Auth: true})
	createUser(ctx, t, in.Driver, "pat@lakeside.edu")
	now := time.Now().Truncate(time.Microsecond)

	for _, name := range []string{"pat@lakeside.edu", "nobody@lakeside.edu"} {
		t.Run(name, func(t *testing.T) {
			if _, err := in.Driver.SignInAttempts(ctx, name); !httpio.HasNotFound(err) {
				t.Errorf("SignInAttempts() before any failure error = %v, want NotFound", err)
			}

			// The first failure opens the window; the second counts in it.
			w := startWindow(h.ClockLead)
			first, err := in.Driver.RecordSignInFailure(ctx, name, now, attemptLimit)
			w.done()
			if err != nil {
				t.Fatalf("RecordSignInFailure() error = %v", err)
			}
			want := &dbtype.SignInAttempts{Name: name, Failures: 1, WindowEndsAt: now.Add(attemptLimit.Window)}
			if diff := cmp.Diff(want, first, attemptsOpts); diff != "" {
				t.Errorf("RecordSignInFailure() mismatch (-want +got):\n%s", diff)
			}
			w.assertStamped(t, "RecordSignInFailure().UpdatedAt", first.UpdatedAt)
			second, err := in.Driver.RecordSignInFailure(ctx, name, now.Add(time.Minute), attemptLimit)
			if err != nil {
				t.Fatalf("RecordSignInFailure() error = %v", err)
			}
			want.Failures = 2
			if diff := cmp.Diff(want, second, attemptsOpts); diff != "" {
				t.Errorf("second RecordSignInFailure() mismatch (-want +got):\n%s", diff)
			}
			read, err := in.Driver.SignInAttempts(ctx, name)
			if err != nil {
				t.Fatalf("SignInAttempts() error = %v", err)
			}
			if diff := cmp.Diff(second, read); diff != "" {
				t.Errorf("SignInAttempts() mismatch (-want +got):\n%s", diff)
			}

			// The failure that reaches the limit locks the name; one during the lock
			// changes nothing but the write's time.
			at := now.Add(2 * time.Minute)
			locked, err := in.Driver.RecordSignInFailure(ctx, name, at, attemptLimit)
			if err != nil {
				t.Fatalf("RecordSignInFailure() error = %v", err)
			}
			lockedUntil := at.Add(attemptLimit.Lock)
			want.Failures, want.LockedUntil = 3, &lockedUntil
			if diff := cmp.Diff(want, locked, attemptsOpts); diff != "" {
				t.Errorf("locking RecordSignInFailure() mismatch (-want +got):\n%s", diff)
			}
			during, err := in.Driver.RecordSignInFailure(ctx, name, at.Add(time.Minute), attemptLimit)
			if err != nil {
				t.Fatalf("RecordSignInFailure() error = %v", err)
			}
			if diff := cmp.Diff(want, during, attemptsOpts); diff != "" {
				t.Errorf("RecordSignInFailure() during the lock mismatch (-want +got):\n%s", diff)
			}
			if !during.UpdatedAt.After(locked.UpdatedAt) {
				t.Errorf("UpdatedAt during the lock = %v, want it moved past %v", during.UpdatedAt, locked.UpdatedAt)
			}
		})
	}
}

func testSignInAttemptsWindowAndLockPass(ctx context.Context, t *testing.T, h *AuthHarness) {
	in := h.New(ctx, t, Auth, AuthConfig{Auth: true})
	now := time.Now().Truncate(time.Microsecond)

	tests := []struct {
		name string
		// before are the failures that set the record up, at their times.
		before []time.Duration
		// at is when the failure under test happens.
		at   time.Duration
		want func(name string, at time.Time) *dbtype.SignInAttempts
	}{
		{
			name:   "a failure after the window ended opens a new window",
			before: []time.Duration{0, time.Minute},
			at:     attemptLimit.Window + time.Second,
			want: func(name string, at time.Time) *dbtype.SignInAttempts {
				return &dbtype.SignInAttempts{Name: name, Failures: 1, WindowEndsAt: at.Add(attemptLimit.Window)}
			},
		},
		{
			name:   "a failure after the lock passed opens a new window",
			before: []time.Duration{0, time.Minute, 2 * time.Minute},
			at:     2*time.Minute + attemptLimit.Lock + time.Second,
			want: func(name string, at time.Time) *dbtype.SignInAttempts {
				return &dbtype.SignInAttempts{Name: name, Failures: 1, WindowEndsAt: at.Add(attemptLimit.Window)}
			},
		},
	}
	for i, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			name := fmt.Sprintf("pat%d@lakeside.edu", i)
			for _, d := range tt.before {
				if _, err := in.Driver.RecordSignInFailure(ctx, name, now.Add(d), attemptLimit); err != nil {
					t.Fatalf("RecordSignInFailure() error = %v", err)
				}
			}
			at := now.Add(tt.at)
			got, err := in.Driver.RecordSignInFailure(ctx, name, at, attemptLimit)
			if err != nil {
				t.Fatalf("RecordSignInFailure() error = %v", err)
			}
			if diff := cmp.Diff(tt.want(name, at), got, attemptsOpts); diff != "" {
				t.Errorf("RecordSignInFailure() mismatch (-want +got):\n%s", diff)
			}
		})
	}
}

func testSignInAttemptsCleared(ctx context.Context, t *testing.T, h *AuthHarness) {
	in := h.New(ctx, t, Auth, AuthConfig{Auth: true})
	now := time.Now()
	for range attemptLimit.Failures {
		if _, err := in.Driver.RecordSignInFailure(ctx, "pat@lakeside.edu", now, attemptLimit); err != nil {
			t.Fatalf("RecordSignInFailure() error = %v", err)
		}
	}
	if _, err := in.Driver.RecordSignInFailure(ctx, "sam@lakeside.edu", now, attemptLimit); err != nil {
		t.Fatalf("RecordSignInFailure() error = %v", err)
	}

	if err := in.Driver.ClearSignInAttempts(ctx, "pat@lakeside.edu"); err != nil {
		t.Fatalf("ClearSignInAttempts() error = %v", err)
	}
	if _, err := in.Driver.SignInAttempts(ctx, "pat@lakeside.edu"); !httpio.HasNotFound(err) {
		t.Errorf("SignInAttempts() after the clear error = %v, want NotFound", err)
	}
	if r, err := in.Driver.SignInAttempts(ctx, "sam@lakeside.edu"); err != nil || r.Failures != 1 {
		t.Errorf("SignInAttempts() of another name = %+v, %v; want it kept", r, err)
	}
	if err := in.Driver.ClearSignInAttempts(ctx, "unknown@lakeside.edu"); err != nil {
		t.Errorf("ClearSignInAttempts() of a name with no record error = %v, want none", err)
	}
	// The count starts over after a clear.
	if r, err := in.Driver.RecordSignInFailure(ctx, "pat@lakeside.edu", now.Add(time.Minute), attemptLimit); err != nil || r.Failures != 1 || r.LockedUntil != nil {
		t.Errorf("RecordSignInFailure() after the clear = %+v, %v; want one failure and no lock", r, err)
	}
}

func testSignInAttemptsConcurrent(ctx context.Context, t *testing.T, h *AuthHarness) {
	in := h.New(ctx, t, Auth, AuthConfig{Auth: true})
	limit := dbtype.SignInAttemptLimit{Failures: 100, Window: time.Hour, Lock: time.Hour}
	now := time.Now()

	const racers = 8
	var (
		wg     sync.WaitGroup
		mu     sync.Mutex
		failed []error
	)
	for range racers {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if _, err := in.Driver.RecordSignInFailure(ctx, "pat@lakeside.edu", now, limit); err != nil {
				mu.Lock()
				failed = append(failed, err)
				mu.Unlock()
			}
		}()
	}
	wg.Wait()

	if len(failed) != 0 {
		t.Fatalf("%d concurrent RecordSignInFailure() calls: errors %v", racers, failed)
	}
	if r, err := in.Driver.SignInAttempts(ctx, "pat@lakeside.edu"); err != nil || r.Failures != racers {
		t.Errorf("SignInAttempts() after %d concurrent failures = %+v, %v; want each counted", racers, r, err)
	}
}
