package drivertest

import (
	"context"
	"testing"
	"time"

	"github.com/cccteam/ccc"
	"github.com/cccteam/httpio"
	"github.com/cccteam/session/internal/dbtype"
	"github.com/google/go-cmp/cmp"
	"github.com/google/go-cmp/cmp/cmpopts"
)

// The factor codes table holds the codes the library mails for a pending sign-in's
// second factor, and the trusted devices table the browsers a person asked to be
// remembered after one. These cases pin, on both backends, that a code is read back by
// its pending sign-in while it is live and one code stands at a time, that wrong codes
// are counted against it and it is consumed once, that a device is read back by its
// hash while it is live and revoked by its token or with every device of its user, and
// that both go with the row they belong to.

// factorCodeOpts compares factor codes leaving out the times the database writes.
var factorCodeOpts = cmp.Options{cmpopts.EquateEmpty(), cmpopts.IgnoreFields(dbtype.FactorCode{}, "CreatedAt", "ConsumedAt")}

// trustedDeviceOpts compares trusted devices leaving out the times the database writes.
var trustedDeviceOpts = cmp.Options{cmpopts.EquateEmpty(), cmpopts.IgnoreFields(dbtype.TrustedDevice{}, "CreatedAt", "LastUsedAt", "RevokedAt")}

// codeAddress is the address every code of the cases is mailed to.
const codeAddress = "pat@lakeside.edu"

// newFactorCode is a code for pendingID mailed to codeAddress, holding hash, that
// expires in ten minutes. Its Attempts, CreatedAt and ConsumedAt carry values the
// insert must ignore: the row is created at the database's time, with no attempt and
// not consumed.
func newFactorCode(pendingID ccc.UUID, hash []byte) *dbtype.FactorCode {
	ignored := time.Date(2000, 1, 1, 0, 0, 0, 0, time.UTC)

	return &dbtype.FactorCode{
		ID: ccc.Must(ccc.NewUUID()), PendingID: pendingID, Email: codeAddress, CodeHash: hash, Attempts: 7,
		CreatedAt: ignored, ExpiresAt: time.Now().Add(10 * time.Minute).Truncate(time.Microsecond), ConsumedAt: &ignored,
	}
}

// newTrustedDevice is a device of userID holding hash that expires in an hour. Its
// CreatedAt, LastUsedAt and RevokedAt carry values the insert must ignore.
func newTrustedDevice(userID ccc.UUID, hash []byte) *dbtype.TrustedDevice {
	ignored := time.Date(2000, 1, 1, 0, 0, 0, 0, time.UTC)

	return &dbtype.TrustedDevice{
		ID: ccc.Must(ccc.NewUUID()), UserID: userID, TokenHash: hash,
		CreatedAt: ignored, ExpiresAt: time.Now().Add(time.Hour).Truncate(time.Microsecond), LastUsedAt: &ignored, RevokedAt: &ignored,
	}
}

// insertPending inserts a pending MFA wait of userID holding hash and returns it.
func insertPending(ctx context.Context, t *testing.T, d AuthDriver, userID ccc.UUID, hash []byte) *dbtype.PendingSignIn {
	t.Helper()

	p := newPendingSignIn(ccc.NullUUIDFromUUID(userID), hash)
	if err := d.InsertPendingSignIn(ctx, p); err != nil {
		t.Fatalf("InsertPendingSignIn() error = %v", err)
	}

	return p
}

func factorCodeState(ctx context.Context, t *testing.T, d AuthDriver, id ccc.UUID) *dbtype.FactorCode {
	t.Helper()

	c, err := d.FactorCodeState(ctx, id)
	if err != nil {
		t.Fatalf("FactorCodeState() error = %v", err)
	}

	return c
}

func trustedDeviceState(ctx context.Context, t *testing.T, d AuthDriver, hash []byte) *dbtype.TrustedDevice {
	t.Helper()

	dev, err := d.TrustedDeviceState(ctx, hash)
	if err != nil {
		t.Fatalf("TrustedDeviceState() error = %v", err)
	}

	return dev
}

func testFactorCodeRoundTrip(ctx context.Context, t *testing.T, h *AuthHarness) {
	in := h.New(ctx, t, Auth, AuthConfig{Auth: true})
	user := createUser(ctx, t, in.Driver, "pat@lakeside.edu")
	pending := insertPending(ctx, t, in.Driver, user.ID, tokenHash(1))
	other := insertPending(ctx, t, in.Driver, user.ID, tokenHash(2))

	first := newFactorCode(pending.ID, tokenHash(3))
	w := startWindow(h.ClockLead)
	if err := in.Driver.InsertFactorCode(ctx, first, time.Now()); err != nil {
		t.Fatalf("InsertFactorCode() error = %v", err)
	}
	w.done()

	got, err := in.Driver.FactorCodeByPending(ctx, pending.ID, time.Now())
	if err != nil {
		t.Fatalf("FactorCodeByPending() error = %v", err)
	}
	want := *first
	want.Attempts = 0
	if diff := cmp.Diff(&want, got, factorCodeOpts); diff != "" {
		t.Errorf("FactorCodeByPending() mismatch (-want +got):\n%s", diff)
	}
	w.assertStamped(t, "FactorCodeByPending().CreatedAt", got.CreatedAt)
	if got.ConsumedAt != nil {
		t.Errorf("FactorCodeByPending().ConsumedAt = %v, want nil", got.ConsumedAt)
	}
	if _, err := in.Driver.FactorCodeByPending(ctx, other.ID, time.Now()); !httpio.HasNotFound(err) {
		t.Errorf("FactorCodeByPending() of a pending sign-in without a code error = %v, want NotFound", err)
	}

	// A new code for the same pending sign-in consumes the earlier one, in the same
	// write: one code stands at a time.
	second := newFactorCode(pending.ID, tokenHash(4))
	w = startWindow(h.ClockLead)
	if err := in.Driver.InsertFactorCode(ctx, second, time.Now()); err != nil {
		t.Fatalf("InsertFactorCode() of the second code error = %v", err)
	}
	w.done()
	got, err = in.Driver.FactorCodeByPending(ctx, pending.ID, time.Now())
	if err != nil {
		t.Fatalf("FactorCodeByPending() after the second code error = %v", err)
	}
	if got.ID != second.ID {
		t.Errorf("FactorCodeByPending() after the second code = %s, want the second, %s", got.ID, second.ID)
	}
	firstState := factorCodeState(ctx, t, in.Driver, first.ID)
	if firstState.ConsumedAt == nil {
		t.Fatal("the first code's ConsumedAt = nil after the second was inserted, want consumed")
	}
	w.assertStamped(t, "the first code's ConsumedAt", *firstState.ConsumedAt)
	assertSameTime(t, "the first code's ConsumedAt and the second's CreatedAt", *firstState.ConsumedAt, got.CreatedAt)
}

func testFactorCodeAttemptsAndConsume(ctx context.Context, t *testing.T, h *AuthHarness) {
	in := h.New(ctx, t, Auth, AuthConfig{Auth: true})
	user := createUser(ctx, t, in.Driver, "pat@lakeside.edu")
	pending := insertPending(ctx, t, in.Driver, user.ID, tokenHash(1))
	code := newFactorCode(pending.ID, tokenHash(2))
	if err := in.Driver.InsertFactorCode(ctx, code, time.Now()); err != nil {
		t.Fatalf("InsertFactorCode() error = %v", err)
	}

	for want := 1; want <= 3; want++ {
		got, err := in.Driver.RecordFactorCodeAttempt(ctx, code.ID, time.Now())
		if err != nil || got != want {
			t.Fatalf("RecordFactorCodeAttempt() #%d = %d, %v; want %d", want, got, err, want)
		}
	}
	if got, err := in.Driver.FactorCodeByPending(ctx, pending.ID, time.Now()); err != nil || got.Attempts != 3 {
		t.Errorf("FactorCodeByPending() after three attempts = %+v, %v; want Attempts 3", got, err)
	}

	w := startWindow(h.ClockLead)
	if err := in.Driver.ConsumeFactorCode(ctx, code.ID, time.Now()); err != nil {
		t.Fatalf("ConsumeFactorCode() error = %v", err)
	}
	w.done()
	if err := in.Driver.ConsumeFactorCode(ctx, code.ID, time.Now()); !httpio.HasNotFound(err) {
		t.Errorf("ConsumeFactorCode() a second time error = %v, want NotFound: a code is consumed once", err)
	}
	state := factorCodeState(ctx, t, in.Driver, code.ID)
	if state.ConsumedAt == nil {
		t.Fatal("ConsumedAt = nil after the consumption, want the database's time")
	}
	w.assertStamped(t, "ConsumedAt", *state.ConsumedAt)
	if _, err := in.Driver.FactorCodeByPending(ctx, pending.ID, time.Now()); !httpio.HasNotFound(err) {
		t.Errorf("FactorCodeByPending() of a consumed code error = %v, want NotFound", err)
	}
	if _, err := in.Driver.RecordFactorCodeAttempt(ctx, code.ID, time.Now()); !httpio.HasNotFound(err) {
		t.Errorf("RecordFactorCodeAttempt() on a consumed code error = %v, want NotFound", err)
	}

	expired := newFactorCode(pending.ID, tokenHash(3))
	expired.ExpiresAt = time.Now().Add(-time.Second)
	if err := in.Driver.InsertFactorCode(ctx, expired, time.Now()); err != nil {
		t.Fatalf("InsertFactorCode() of an expired code error = %v", err)
	}
	if _, err := in.Driver.FactorCodeByPending(ctx, pending.ID, time.Now()); !httpio.HasNotFound(err) {
		t.Errorf("FactorCodeByPending() of an expired code error = %v, want NotFound", err)
	}
	if _, err := in.Driver.RecordFactorCodeAttempt(ctx, expired.ID, time.Now()); !httpio.HasNotFound(err) {
		t.Errorf("RecordFactorCodeAttempt() on an expired code error = %v, want NotFound", err)
	}
	if err := in.Driver.ConsumeFactorCode(ctx, expired.ID, time.Now()); !httpio.HasNotFound(err) {
		t.Errorf("ConsumeFactorCode() of an expired code error = %v, want NotFound", err)
	}
}

func testTrustedDeviceLifecycle(ctx context.Context, t *testing.T, h *AuthHarness) {
	in := h.New(ctx, t, Auth, AuthConfig{Auth: true})
	user := createUser(ctx, t, in.Driver, "pat@lakeside.edu")
	laptop := newTrustedDevice(user.ID, tokenHash(1))
	phone := newTrustedDevice(user.ID, tokenHash(2))
	expired := newTrustedDevice(user.ID, tokenHash(3))
	expired.ExpiresAt = time.Now().Add(-time.Second)
	for _, d := range []*dbtype.TrustedDevice{laptop, phone, expired} {
		if err := in.Driver.InsertTrustedDevice(ctx, d); err != nil {
			t.Fatalf("InsertTrustedDevice() error = %v", err)
		}
	}

	got, err := in.Driver.TrustedDeviceByToken(ctx, laptop.TokenHash, time.Now())
	if err != nil {
		t.Fatalf("TrustedDeviceByToken() error = %v", err)
	}
	if diff := cmp.Diff(laptop, got, trustedDeviceOpts); diff != "" {
		t.Errorf("TrustedDeviceByToken() mismatch (-want +got):\n%s", diff)
	}
	if got.LastUsedAt != nil || got.RevokedAt != nil {
		t.Errorf("TrustedDeviceByToken() = LastUsedAt %v, RevokedAt %v; want both nil on a fresh device", got.LastUsedAt, got.RevokedAt)
	}
	if _, err := in.Driver.TrustedDeviceByToken(ctx, expired.TokenHash, time.Now()); !httpio.HasNotFound(err) {
		t.Errorf("TrustedDeviceByToken() of an expired device error = %v, want NotFound", err)
	}

	w := startWindow(h.ClockLead)
	if err := in.Driver.TouchTrustedDevice(ctx, laptop.ID, time.Now()); err != nil {
		t.Fatalf("TouchTrustedDevice() error = %v", err)
	}
	w.done()
	if got := trustedDeviceState(ctx, t, in.Driver, laptop.TokenHash); got.LastUsedAt == nil {
		t.Error("TouchTrustedDevice() left LastUsedAt nil, want the database's time")
	} else {
		w.assertStamped(t, "LastUsedAt", *got.LastUsedAt)
	}
	if err := in.Driver.TouchTrustedDevice(ctx, expired.ID, time.Now()); err != nil {
		t.Errorf("TouchTrustedDevice() of an expired device error = %v, want nothing", err)
	}
	if got := trustedDeviceState(ctx, t, in.Driver, expired.TokenHash); got.LastUsedAt != nil {
		t.Errorf("TouchTrustedDevice() of an expired device set LastUsedAt = %v, want nil", got.LastUsedAt)
	}

	w = startWindow(h.ClockLead)
	if err := in.Driver.RevokeTrustedDevice(ctx, laptop.TokenHash, time.Now()); err != nil {
		t.Fatalf("RevokeTrustedDevice() error = %v", err)
	}
	w.done()
	if err := in.Driver.RevokeTrustedDevice(ctx, laptop.TokenHash, time.Now()); !httpio.HasNotFound(err) {
		t.Errorf("RevokeTrustedDevice() a second time error = %v, want NotFound: a device is revoked once", err)
	}
	if err := in.Driver.RevokeTrustedDevice(ctx, expired.TokenHash, time.Now()); !httpio.HasNotFound(err) {
		t.Errorf("RevokeTrustedDevice() of an expired device error = %v, want NotFound", err)
	}
	if got := trustedDeviceState(ctx, t, in.Driver, laptop.TokenHash); got.RevokedAt == nil {
		t.Error("RevokeTrustedDevice() left RevokedAt nil, want the database's time")
	} else {
		w.assertStamped(t, "RevokedAt", *got.RevokedAt)
	}
	if _, err := in.Driver.TrustedDeviceByToken(ctx, laptop.TokenHash, time.Now()); !httpio.HasNotFound(err) {
		t.Errorf("TrustedDeviceByToken() of a revoked device error = %v, want NotFound", err)
	}
	if _, err := in.Driver.TrustedDeviceByToken(ctx, phone.TokenHash, time.Now()); err != nil {
		t.Errorf("TrustedDeviceByToken() of the other device error = %v, want it live: a revocation by token reaches one device", err)
	}

	// The reset: every device of the user at once, the expired one included, so the
	// person's next sign-in from any of them asks for the factor.
	w = startWindow(h.ClockLead)
	if err := in.Driver.RevokeTrustedDevices(ctx, user.ID); err != nil {
		t.Fatalf("RevokeTrustedDevices() error = %v", err)
	}
	w.done()
	for _, d := range []*dbtype.TrustedDevice{phone, expired} {
		got := trustedDeviceState(ctx, t, in.Driver, d.TokenHash)
		if got.RevokedAt == nil {
			t.Errorf("RevokeTrustedDevices() left device %s unrevoked", d.ID)

			continue
		}
		w.assertStamped(t, "RevokedAt after the reset", *got.RevokedAt)
	}
	if got := trustedDeviceState(ctx, t, in.Driver, laptop.TokenHash); got.RevokedAt == nil || !got.RevokedAt.Before(w.start) {
		t.Errorf("RevokeTrustedDevices() restamped the device revoked earlier: RevokedAt = %v, want the earlier time", got.RevokedAt)
	}
}

func testFactorsCascade(ctx context.Context, t *testing.T, h *AuthHarness) {
	in := h.New(ctx, t, Auth, AuthConfig{Auth: true})
	user := createUser(ctx, t, in.Driver, "pat@lakeside.edu")
	pending := insertPending(ctx, t, in.Driver, user.ID, tokenHash(1))
	code := newFactorCode(pending.ID, tokenHash(2))
	if err := in.Driver.InsertFactorCode(ctx, code, time.Now()); err != nil {
		t.Fatalf("InsertFactorCode() error = %v", err)
	}
	device := newTrustedDevice(user.ID, tokenHash(3))
	if err := in.Driver.InsertTrustedDevice(ctx, device); err != nil {
		t.Fatalf("InsertTrustedDevice() error = %v", err)
	}

	// The schema refuses a code for a pending sign-in that is not there.
	orphan := newFactorCode(ccc.Must(ccc.NewUUID()), tokenHash(4))
	if err := in.Driver.InsertFactorCode(ctx, orphan, time.Now()); err == nil {
		t.Error("InsertFactorCode() for an unknown pending sign-in error = nil, want the schema's refusal")
	}

	if err := in.Driver.DeleteUser(ctx, user.ID); err != nil {
		t.Fatalf("DeleteUser() error = %v", err)
	}
	if _, err := in.Driver.TrustedDeviceState(ctx, device.TokenHash); !httpio.HasNotFound(err) {
		t.Errorf("TrustedDeviceState() after the user was deleted error = %v, want NotFound: the device goes with the user", err)
	}
	// A pending sign-in stays when its user goes (it names the user without a
	// constraint, for audit), and its code stays with it.
	if _, err := in.Driver.FactorCodeState(ctx, code.ID); err != nil {
		t.Errorf("FactorCodeState() after the user was deleted error = %v, want the code, which goes with its pending sign-in", err)
	}
}
