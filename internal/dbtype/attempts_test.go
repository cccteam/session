package dbtype

import (
	"testing"
	"time"

	"github.com/google/go-cmp/cmp"
)

func TestSignInAttempts_Failed(t *testing.T) {
	t.Parallel()

	now := time.Date(2026, 10, 21, 12, 0, 0, 0, time.UTC)
	limit := SignInAttemptLimit{Failures: 3, Window: 15 * time.Minute, Lock: 10 * time.Minute}
	at := func(d time.Duration) *time.Time {
		v := now.Add(d)

		return &v
	}

	tests := []struct {
		name   string
		record *SignInAttempts
		limit  SignInAttemptLimit
		want   *SignInAttempts
	}{
		{
			name: "the first failure opens a window",
			want: &SignInAttempts{Name: "pat", Failures: 1, WindowEndsAt: now.Add(15 * time.Minute)},
		},
		{
			name:   "a failure in the window counts, keeping the window's end",
			record: &SignInAttempts{Name: "pat", Failures: 1, WindowEndsAt: now.Add(5 * time.Minute)},
			want:   &SignInAttempts{Name: "pat", Failures: 2, WindowEndsAt: now.Add(5 * time.Minute)},
		},
		{
			name:   "the failure that reaches the limit locks the name",
			record: &SignInAttempts{Name: "pat", Failures: 2, WindowEndsAt: now.Add(5 * time.Minute)},
			want:   &SignInAttempts{Name: "pat", Failures: 3, WindowEndsAt: now.Add(5 * time.Minute), LockedUntil: at(10 * time.Minute)},
		},
		{
			name:   "a failure during the lock changes nothing",
			record: &SignInAttempts{Name: "pat", Failures: 3, WindowEndsAt: now.Add(5 * time.Minute), LockedUntil: at(time.Minute)},
			want:   &SignInAttempts{Name: "pat", Failures: 3, WindowEndsAt: now.Add(5 * time.Minute), LockedUntil: at(time.Minute)},
		},
		{
			name:   "a failure after the window ended opens a new window",
			record: &SignInAttempts{Name: "pat", Failures: 2, WindowEndsAt: now.Add(-time.Second)},
			want:   &SignInAttempts{Name: "pat", Failures: 1, WindowEndsAt: now.Add(15 * time.Minute)},
		},
		{
			name:   "a failure after the lock passed opens a new window",
			record: &SignInAttempts{Name: "pat", Failures: 3, WindowEndsAt: now.Add(5 * time.Minute), LockedUntil: at(-time.Second)},
			want:   &SignInAttempts{Name: "pat", Failures: 1, WindowEndsAt: now.Add(15 * time.Minute)},
		},
		{
			name:  "a limit of one failure locks at the first",
			limit: SignInAttemptLimit{Failures: 1, Window: 15 * time.Minute, Lock: 10 * time.Minute},
			want:  &SignInAttempts{Name: "pat", Failures: 1, WindowEndsAt: now.Add(15 * time.Minute), LockedUntil: at(10 * time.Minute)},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			l := tt.limit
			if l.Failures == 0 {
				l = limit
			}
			got := tt.record.Failed("pat", now, l)
			if diff := cmp.Diff(tt.want, got); diff != "" {
				t.Errorf("Failed() mismatch (-want +got):\n%s", diff)
			}
			if tt.record != nil && got == tt.record {
				t.Error("Failed() returned the record it was given, want a new one")
			}
		})
	}
}

func TestSignInAttempts_Locked(t *testing.T) {
	t.Parallel()

	now := time.Date(2026, 10, 21, 12, 0, 0, 0, time.UTC)
	later := now.Add(time.Minute)
	earlier := now.Add(-time.Minute)

	tests := []struct {
		name       string
		record     *SignInAttempts
		wantWait   time.Duration
		wantLocked bool
	}{
		{name: "no record holds nothing"},
		{name: "a record without a lock holds nothing", record: &SignInAttempts{Failures: 2, WindowEndsAt: later}},
		{name: "a lock in the future holds the name for the time left", record: &SignInAttempts{LockedUntil: &later}, wantWait: time.Minute, wantLocked: true},
		{name: "a lock that passed holds nothing", record: &SignInAttempts{LockedUntil: &earlier}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			wait, locked := tt.record.Locked(now)
			if wait != tt.wantWait || locked != tt.wantLocked {
				t.Errorf("Locked() = %v, %v; want %v, %v", wait, locked, tt.wantWait, tt.wantLocked)
			}
		})
	}
}
