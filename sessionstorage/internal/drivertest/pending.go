package drivertest

import (
	"context"
	"encoding/json"
	"sync"
	"testing"
	"time"

	"github.com/cccteam/ccc"
	"github.com/cccteam/httpio"
	"github.com/cccteam/session/internal/dbtype"
	"github.com/cccteam/session/sessioninfo"
	"github.com/google/go-cmp/cmp"
	"github.com/google/go-cmp/cmp/cmpopts"
)

// The pending sign-ins table holds a sign-in that waits for a confirmation or the
// application's MFA step. The browser's cookie carries an opaque token; the row keeps
// its hash. These cases check that a row is read back whole by that hash, that it is
// consumed once by a conditional update, and that an expired row is dead, on every
// backend.

// pendingOpts compares pending sign-ins with timestamps to the second (the backends
// store different precisions) and nil and empty slices alike.
var pendingOpts = cmp.Options{cmpopts.EquateApproxTime(time.Second), cmpopts.EquateEmpty()}

// tokenHash is a distinct 32-byte hash for the test's token n.
func tokenHash(n byte) []byte {
	hash := make([]byte, 32)
	hash[0] = n

	return hash
}

// newPendingSignIn is a pending sign-in for userID, with every field set, that expires in
// an hour.
func newPendingSignIn(userID ccc.NullUUID, hash []byte) *dbtype.PendingSignIn {
	now := time.Now().Truncate(time.Microsecond)

	return &dbtype.PendingSignIn{
		ID:           ccc.Must(ccc.NewUUID()),
		TokenHash:    hash,
		Step:         sessioninfo.PendingMFA,
		Registration: "workos",
		Identity: sessioninfo.Identity{
			Method: sessioninfo.MethodWorkOS, Connection: "conn_1", Subject: "idp_pat", Email: "pat@lakeside.edu", EmailVerified: true,
			Claims: json.RawMessage(`{"raw_attributes":{"department":"math"}}`), IDPAMR: []string{"pwd", "mfa"},
		},
		UserID:                userID,
		Username:              "pat@lakeside.edu",
		Tenant:                "lakeside",
		Events:                []sessioninfo.AuthEvent{{Method: sessioninfo.MethodWorkOS, Connection: "conn_1", IDPAMR: []string{"pwd", "mfa"}, At: now}},
		RoleNames:             []string{"Teacher", "Coach"},
		Factors:               []sessioninfo.AuthMethod{"email-otp", "totp"},
		ReturnURL:             "/reports?x=1",
		ProviderSessionID:     "sid-1",
		ProviderSessionIssuer: "https://login/lakeside",
		CreatedAt:             now,
		ExpiresAt:             now.Add(time.Hour),
	}
}

func testPendingSignInRoundTrip(ctx context.Context, t *testing.T, h *AuthHarness) {
	in := h.New(ctx, t, Auth, AuthConfig{Auth: true})
	user := createUser(ctx, t, in.Driver, "pat@lakeside.edu")

	tests := []struct {
		name string
		p    *dbtype.PendingSignIn
	}{
		{name: "an MFA wait on a known user, with claims, roles and factors", p: newPendingSignIn(ccc.NullUUIDFromUUID(user.ID), tokenHash(1))},
		{
			name: "a confirmation wait without a user, roles, factors or claims",
			p: func() *dbtype.PendingSignIn {
				p := newPendingSignIn(ccc.NullUUID{}, tokenHash(2))
				p.Step, p.Registration, p.Identity.Claims, p.RoleNames, p.Factors, p.ReturnURL = sessioninfo.PendingConfirmation, "", nil, nil, nil, ""
				p.ProviderSessionID, p.ProviderSessionIssuer = "", ""

				return p
			}(),
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if err := in.Driver.InsertPendingSignIn(ctx, tt.p); err != nil {
				t.Fatalf("InsertPendingSignIn() error = %v", err)
			}

			got, err := in.Driver.PendingSignInByToken(ctx, tt.p.TokenHash, time.Now())
			if err != nil {
				t.Fatalf("PendingSignInByToken() error = %v", err)
			}
			if diff := cmp.Diff(tt.p, got, pendingOpts); diff != "" {
				t.Errorf("PendingSignInByToken() mismatch (-want +got):\n%s", diff)
			}
			if got.ConsumedAt != nil {
				t.Errorf("PendingSignInByToken().ConsumedAt = %v, want nil", got.ConsumedAt)
			}
		})
	}

	// Another token finds nothing.
	if _, err := in.Driver.PendingSignInByToken(ctx, tokenHash(9), time.Now()); !httpio.HasNotFound(err) {
		t.Errorf("PendingSignInByToken() of an unknown token error = %v, want NotFound", err)
	}
}

func testPendingSignInConsumedOnce(ctx context.Context, t *testing.T, h *AuthHarness) {
	in := h.New(ctx, t, Auth, AuthConfig{Auth: true})
	p := newPendingSignIn(ccc.NullUUID{}, tokenHash(1))
	if err := in.Driver.InsertPendingSignIn(ctx, p); err != nil {
		t.Fatalf("InsertPendingSignIn() error = %v", err)
	}

	if err := in.Driver.ConsumePendingSignIn(ctx, p.TokenHash, time.Now()); err != nil {
		t.Fatalf("ConsumePendingSignIn() error = %v", err)
	}
	if err := in.Driver.ConsumePendingSignIn(ctx, p.TokenHash, time.Now()); !httpio.HasNotFound(err) {
		t.Errorf("second ConsumePendingSignIn() error = %v, want NotFound: a pending sign-in is consumed once", err)
	}
	if _, err := in.Driver.PendingSignInByToken(ctx, p.TokenHash, time.Now()); !httpio.HasNotFound(err) {
		t.Errorf("PendingSignInByToken() of a consumed pending sign-in error = %v, want NotFound", err)
	}
	if err := in.Driver.ConsumePendingSignIn(ctx, tokenHash(9), time.Now()); !httpio.HasNotFound(err) {
		t.Errorf("ConsumePendingSignIn() of an unknown token error = %v, want NotFound", err)
	}
}

func testPendingSignInExpired(ctx context.Context, t *testing.T, h *AuthHarness) {
	in := h.New(ctx, t, Auth, AuthConfig{Auth: true})
	p := newPendingSignIn(ccc.NullUUID{}, tokenHash(1))
	if err := in.Driver.InsertPendingSignIn(ctx, p); err != nil {
		t.Fatalf("InsertPendingSignIn() error = %v", err)
	}
	later := p.ExpiresAt.Add(time.Second)

	if _, err := in.Driver.PendingSignInByToken(ctx, p.TokenHash, later); !httpio.HasNotFound(err) {
		t.Errorf("PendingSignInByToken() after expiry error = %v, want NotFound", err)
	}
	if err := in.Driver.ConsumePendingSignIn(ctx, p.TokenHash, later); !httpio.HasNotFound(err) {
		t.Errorf("ConsumePendingSignIn() after expiry error = %v, want NotFound", err)
	}
	// The row is still live before its expiry.
	if _, err := in.Driver.PendingSignInByToken(ctx, p.TokenHash, time.Now()); err != nil {
		t.Errorf("PendingSignInByToken() before expiry error = %v", err)
	}
}

func testPendingSignInConcurrentConsume(ctx context.Context, t *testing.T, h *AuthHarness) {
	in := h.New(ctx, t, Auth, AuthConfig{Auth: true})
	p := newPendingSignIn(ccc.NullUUID{}, tokenHash(1))
	if err := in.Driver.InsertPendingSignIn(ctx, p); err != nil {
		t.Fatalf("InsertPendingSignIn() error = %v", err)
	}

	const racers = 8
	var (
		wg       sync.WaitGroup
		mu       sync.Mutex
		consumed int
		failed   []error
	)
	for range racers {
		wg.Add(1)
		go func() {
			defer wg.Done()
			err := in.Driver.ConsumePendingSignIn(ctx, p.TokenHash, time.Now())
			mu.Lock()
			defer mu.Unlock()
			switch {
			case err == nil:
				consumed++
			case httpio.HasNotFound(err):
			default:
				failed = append(failed, err)
			}
		}()
	}
	wg.Wait()

	if consumed != 1 || len(failed) != 0 {
		t.Errorf("%d concurrent ConsumePendingSignIn() calls: %d consumed, errors %v; want exactly 1 consumed and no errors", racers, consumed, failed)
	}
}
