package drivertest

import (
	"context"
	"testing"
	"time"

	"github.com/cccteam/ccc"
	"github.com/cccteam/httpio"
	"github.com/cccteam/session/internal/dbtype"
	"github.com/go-playground/errors/v5"
	"github.com/google/go-cmp/cmp"
	"github.com/google/go-cmp/cmp/cmpopts"
)

// The tokens table holds the bearer credentials of the machine outlets, each as the
// hash of a secret the client holds, and the device codes table the authorizations a
// command-line client starts. These cases pin, on both backends, that a row is read
// back whole by its hash while it is live and never after, that a revocation is
// conditional and reaches a family, that a refresh exchange rotates in one
// transaction and a reuse revokes the family, and that a device code is decided once
// and redeemed once.

// tokenOpts compares tokens leaving out the times the database writes.
var tokenOpts = cmp.Options{cmpopts.EquateEmpty(), cmpopts.IgnoreFields(dbtype.Token{}, "CreatedAt", "LastUsedAt", "RevokedAt")}

// deviceCodeOpts compares device codes leaving out the times the database writes.
var deviceCodeOpts = cmp.Options{cmpopts.EquateEmpty(), cmpopts.IgnoreFields(dbtype.DeviceCode{}, "CreatedAt", "ApprovedAt", "DeniedAt", "LastPolledAt", "ConsumedAt")}

// The outlet and client the cases issue tokens for.
const (
	droidsOutlet = "droids"
	corralClient = "corral"
)

// newToken is a token of kind for userID on the droids outlet, holding hash, that
// expires in an hour. Its CreatedAt, LastUsedAt and RevokedAt carry values the insert
// must ignore: the row is created at the database's time, unused and not revoked.
func newToken(kind dbtype.TokenKind, userID ccc.UUID, hash []byte) *dbtype.Token {
	ignored := time.Date(2000, 1, 1, 0, 0, 0, 0, time.UTC)

	return &dbtype.Token{
		ID: ccc.Must(ccc.NewUUID()), TokenHash: hash, Kind: kind, UserID: userID, Outlet: droidsOutlet,
		CreatedAt: ignored, ExpiresAt: time.Now().Add(time.Hour).Truncate(time.Microsecond), LastUsedAt: &ignored, RevokedAt: &ignored,
	}
}

// newFamily is a device grant's access and refresh tokens for userID, in one family,
// issued to the corral client.
func newFamily(userID ccc.UUID, accessHash, refreshHash []byte) (access, refresh *dbtype.Token) {
	family := ccc.NullUUIDFromUUID(ccc.Must(ccc.NewUUID()))
	access = newToken(dbtype.TokenAccess, userID, accessHash)
	refresh = newToken(dbtype.TokenRefresh, userID, refreshHash)
	for _, t := range []*dbtype.Token{access, refresh} {
		t.Family, t.ClientID = family, corralClient
	}

	return access, refresh
}

// insertTokens inserts each token and fails the test on a refusal.
func insertTokens(ctx context.Context, t *testing.T, d AuthDriver, tokens ...*dbtype.Token) {
	t.Helper()

	for _, tok := range tokens {
		if err := d.InsertToken(ctx, tok); err != nil {
			t.Fatalf("InsertToken(%s) error = %v", tok.Kind, err)
		}
	}
}

// newDeviceCode is a pending device authorization by the corral client for the droids
// outlet, holding hash, that expires in ten minutes.
func newDeviceCode(userCode string, hash []byte) *dbtype.DeviceCode {
	ignored := time.Date(2000, 1, 1, 0, 0, 0, 0, time.UTC)

	return &dbtype.DeviceCode{
		ID: ccc.Must(ccc.NewUUID()), DeviceCodeHash: hash, UserCode: userCode, ClientID: corralClient, Outlet: droidsOutlet,
		CreatedAt: ignored, ExpiresAt: time.Now().Add(10 * time.Minute).Truncate(time.Microsecond), ApprovedAt: &ignored, ConsumedAt: &ignored,
	}
}

// tokenState reads a token whatever its state and fails the test when it is not there.
func tokenState(ctx context.Context, t *testing.T, d AuthDriver, hash []byte) *dbtype.Token {
	t.Helper()

	tok, err := d.TokenState(ctx, hash)
	if err != nil {
		t.Fatalf("TokenState() error = %v", err)
	}

	return tok
}

func testTokenRoundTrip(ctx context.Context, t *testing.T, h *AuthHarness) {
	in := h.New(ctx, t, Auth, AuthConfig{Auth: true})
	user := createUser(ctx, t, in.Driver, "pat@lakeside.edu")
	other := createUser(ctx, t, in.Driver, "other@lakeside.edu")

	app := newToken(dbtype.TokenApplication, user.ID, tokenHash(1))
	app.Name = "deploy script"
	access, refresh := newFamily(user.ID, tokenHash(2), tokenHash(3))

	for _, tt := range []struct {
		name  string
		token *dbtype.Token
	}{
		{name: "an application token with its name", token: app},
		{name: "a device grant's access token with its family and client", token: access},
		{name: "a device grant's refresh token", token: refresh},
	} {
		t.Run(tt.name, func(t *testing.T) {
			w := startWindow(h.ClockLead)
			if err := in.Driver.InsertToken(ctx, tt.token); err != nil {
				t.Fatalf("InsertToken() error = %v", err)
			}
			w.done()

			got, err := in.Driver.TokenByHash(ctx, tt.token.TokenHash, time.Now())
			if err != nil {
				t.Fatalf("TokenByHash() error = %v", err)
			}
			if diff := cmp.Diff(tt.token, got, tokenOpts); diff != "" {
				t.Errorf("TokenByHash() mismatch (-want +got):\n%s", diff)
			}
			w.assertStamped(t, "TokenByHash().CreatedAt", got.CreatedAt)
			if got.LastUsedAt != nil || got.RevokedAt != nil || got.RevokedReason != "" {
				t.Errorf("TokenByHash() = used at %v, revoked at %v (%q), want unused and not revoked", got.LastUsedAt, got.RevokedAt, got.RevokedReason)
			}
		})
	}
	if _, err := in.Driver.TokenByHash(ctx, tokenHash(9), time.Now()); !httpio.HasNotFound(err) {
		t.Errorf("TokenByHash() of an unknown hash error = %v, want NotFound", err)
	}
	if err := in.Driver.InsertToken(ctx, newToken("magic", user.ID, tokenHash(4))); err == nil {
		t.Error("InsertToken() of an unknown kind error = nil, want a refusal")
	}

	// The user's live tokens, newest first; nobody else's.
	tokens, err := in.Driver.TokensByUser(ctx, user.ID, time.Now())
	if err != nil {
		t.Fatalf("TokensByUser() error = %v", err)
	}
	if diff := cmp.Diff([]*dbtype.Token{refresh, access, app}, tokens, tokenOpts); diff != "" {
		t.Errorf("TokensByUser() mismatch (-want +got):\n%s", diff)
	}
	if tokens, err := in.Driver.TokensByUser(ctx, other.ID, time.Now()); err != nil || len(tokens) != 0 {
		t.Errorf("TokensByUser() of a user without tokens = %v, %v, want none", tokens, err)
	}
}

func testTokenTouchAndRevoke(ctx context.Context, t *testing.T, h *AuthHarness) {
	in := h.New(ctx, t, Auth, AuthConfig{Auth: true})
	user := createUser(ctx, t, in.Driver, "pat@lakeside.edu")
	other := createUser(ctx, t, in.Driver, "other@lakeside.edu")
	app := newToken(dbtype.TokenApplication, user.ID, tokenHash(1))
	access, refresh := newFamily(user.ID, tokenHash(2), tokenHash(3))
	theirs := newToken(dbtype.TokenApplication, other.ID, tokenHash(4))
	insertTokens(ctx, t, in.Driver, app, access, refresh, theirs)

	// A touch stamps the database's time on a live token.
	w := startWindow(h.ClockLead)
	if err := in.Driver.TouchToken(ctx, app.ID, time.Now()); err != nil {
		t.Fatalf("TouchToken() error = %v", err)
	}
	w.done()
	if got := tokenState(ctx, t, in.Driver, app.TokenHash); got.LastUsedAt == nil {
		t.Error("TouchToken() left LastUsedAt nil")
	} else {
		w.assertStamped(t, "LastUsedAt", *got.LastUsedAt)
	}

	// Only the token's own user revokes it.
	if err := in.Driver.RevokeUserToken(ctx, other.ID, app.ID, time.Now(), dbtype.TokenRevokedByHand); !httpio.HasNotFound(err) {
		t.Errorf("RevokeUserToken() by another user error = %v, want NotFound", err)
	}
	if _, err := in.Driver.TokenByHash(ctx, app.TokenHash, time.Now()); err != nil {
		t.Errorf("TokenByHash() after another user's attempt error = %v, want the token live", err)
	}
	if err := in.Driver.RevokeUserToken(ctx, user.ID, app.ID, time.Now(), "gone"); err == nil {
		t.Error("RevokeUserToken() with an unknown reason error = nil, want a refusal")
	}

	// The user's revocation is stamped, once; the token is dead to the live reads.
	w = startWindow(h.ClockLead)
	if err := in.Driver.RevokeUserToken(ctx, user.ID, app.ID, time.Now(), dbtype.TokenRevokedByHand); err != nil {
		t.Fatalf("RevokeUserToken() error = %v", err)
	}
	w.done()
	revoked := tokenState(ctx, t, in.Driver, app.TokenHash)
	if revoked.RevokedAt == nil || revoked.RevokedReason != dbtype.TokenRevokedByHand {
		t.Fatalf("RevokeUserToken() left the token revoked at %v (%q), want stamped as revoked", revoked.RevokedAt, revoked.RevokedReason)
	}
	w.assertStamped(t, "RevokedAt", *revoked.RevokedAt)
	if _, err := in.Driver.TokenByHash(ctx, app.TokenHash, time.Now()); !httpio.HasNotFound(err) {
		t.Errorf("TokenByHash() of a revoked token error = %v, want NotFound", err)
	}
	if err := in.Driver.RevokeUserToken(ctx, user.ID, app.ID, time.Now(), dbtype.TokenRevokedByHand); !httpio.HasNotFound(err) {
		t.Errorf("second RevokeUserToken() error = %v, want NotFound", err)
	}
	if err := in.Driver.TouchToken(ctx, app.ID, time.Now()); err != nil {
		t.Errorf("TouchToken() of a revoked token error = %v, want nothing", err)
	}
	if got := tokenState(ctx, t, in.Driver, app.TokenHash); !got.LastUsedAt.Equal(*revoked.LastUsedAt) {
		t.Errorf("TouchToken() of a revoked token moved LastUsedAt to %v, want %v kept", got.LastUsedAt, revoked.LastUsedAt)
	}

	// Revoking one token of a family revokes the family, with one time.
	if err := in.Driver.RevokeUserToken(ctx, user.ID, access.ID, time.Now(), dbtype.TokenRevokedByHand); err != nil {
		t.Fatalf("RevokeUserToken() of a family member error = %v", err)
	}
	gotAccess, gotRefresh := tokenState(ctx, t, in.Driver, access.TokenHash), tokenState(ctx, t, in.Driver, refresh.TokenHash)
	if gotAccess.RevokedAt == nil || gotRefresh.RevokedAt == nil || gotRefresh.RevokedReason != dbtype.TokenRevokedByHand {
		t.Fatalf("RevokeUserToken() of a family member left access revoked at %v and refresh at %v (%q), want both revoked", gotAccess.RevokedAt, gotRefresh.RevokedAt, gotRefresh.RevokedReason)
	}
	assertSameTime(t, "the refresh token's RevokedAt", *gotRefresh.RevokedAt, *gotAccess.RevokedAt)

	// Every token of a user, at once; another user's stays.
	more, moreRefresh := newFamily(user.ID, tokenHash(5), tokenHash(6))
	insertTokens(ctx, t, in.Driver, more, moreRefresh)
	if err := in.Driver.RevokeUserTokens(ctx, user.ID, dbtype.TokenRevokedWithUser); err != nil {
		t.Fatalf("RevokeUserTokens() error = %v", err)
	}
	if tokens, err := in.Driver.TokensByUser(ctx, user.ID, time.Now()); err != nil || len(tokens) != 0 {
		t.Errorf("TokensByUser() after RevokeUserTokens() = %v, %v, want none", tokens, err)
	}
	if got := tokenState(ctx, t, in.Driver, moreRefresh.TokenHash); got.RevokedReason != dbtype.TokenRevokedWithUser {
		t.Errorf("RevokeUserTokens() reason = %q, want %q", got.RevokedReason, dbtype.TokenRevokedWithUser)
	}
	if _, err := in.Driver.TokenByHash(ctx, theirs.TokenHash, time.Now()); err != nil {
		t.Errorf("TokenByHash() of another user's token after RevokeUserTokens() error = %v, want it live", err)
	}
}

func testTokenExpired(ctx context.Context, t *testing.T, h *AuthHarness) {
	in := h.New(ctx, t, Auth, AuthConfig{Auth: true})
	user := createUser(ctx, t, in.Driver, "pat@lakeside.edu")
	expired := newToken(dbtype.TokenApplication, user.ID, tokenHash(1))
	expired.ExpiresAt = time.Now().Add(-time.Second)
	insertTokens(ctx, t, in.Driver, expired)

	if _, err := in.Driver.TokenByHash(ctx, expired.TokenHash, time.Now()); !httpio.HasNotFound(err) {
		t.Errorf("TokenByHash() of an expired token error = %v, want NotFound", err)
	}
	if tokens, err := in.Driver.TokensByUser(ctx, user.ID, time.Now()); err != nil || len(tokens) != 0 {
		t.Errorf("TokensByUser() with an expired token = %v, %v, want none", tokens, err)
	}
	if err := in.Driver.TouchToken(ctx, expired.ID, time.Now()); err != nil {
		t.Errorf("TouchToken() of an expired token error = %v, want nothing", err)
	}
	if got := tokenState(ctx, t, in.Driver, expired.TokenHash); got.LastUsedAt != nil {
		t.Errorf("TouchToken() of an expired token set LastUsedAt = %v, want nil", got.LastUsedAt)
	}
	if err := in.Driver.RevokeUserToken(ctx, user.ID, expired.ID, time.Now(), dbtype.TokenRevokedByHand); !httpio.HasNotFound(err) {
		t.Errorf("RevokeUserToken() of an expired token error = %v, want NotFound", err)
	}
}

func testRefreshExchange(ctx context.Context, t *testing.T, h *AuthHarness) {
	in := h.New(ctx, t, Auth, AuthConfig{Auth: true})
	user := createUser(ctx, t, in.Driver, "pat@lakeside.edu")
	app := newToken(dbtype.TokenApplication, user.ID, tokenHash(1))
	access1, refresh1 := newFamily(user.ID, tokenHash(2), tokenHash(3))
	insertTokens(ctx, t, in.Driver, app, access1, refresh1)

	// The exchange rotates in one transaction: the old pair, the refresh token and
	// the access token of its family, is revoked as rotated and the successors are
	// inserted in its family, as its user, for its outlet and client, which the driver
	// fills in.
	access2, refresh2 := newToken(dbtype.TokenAccess, ccc.NilUUID, tokenHash(12)), newToken(dbtype.TokenRefresh, ccc.NilUUID, tokenHash(13))
	access2.Outlet, refresh2.Outlet = "", ""
	w := startWindow(h.ClockLead)
	if err := in.Driver.ExchangeRefreshToken(ctx, refresh1.TokenHash, time.Now(), access2, refresh2); err != nil {
		t.Fatalf("ExchangeRefreshToken() error = %v", err)
	}
	w.done()
	for _, tok := range []*dbtype.Token{access2, refresh2} {
		if tok.UserID != user.ID || tok.Outlet != droidsOutlet || tok.ClientID != corralClient || tok.Family != refresh1.Family {
			t.Errorf("ExchangeRefreshToken() filled %s as user %s, outlet %q, client %q, family %v; want the old token's", tok.Kind, tok.UserID, tok.Outlet, tok.ClientID, tok.Family)
		}
		got, err := in.Driver.TokenByHash(ctx, tok.TokenHash, time.Now())
		if err != nil {
			t.Fatalf("TokenByHash(%s) after the exchange error = %v", tok.Kind, err)
		}
		if diff := cmp.Diff(tok, got, tokenOpts); diff != "" {
			t.Errorf("TokenByHash(%s) mismatch (-want +got):\n%s", tok.Kind, diff)
		}
		w.assertStamped(t, string(tok.Kind)+" CreatedAt", got.CreatedAt)
	}
	for _, tok := range []*dbtype.Token{refresh1, access1} {
		old := tokenState(ctx, t, in.Driver, tok.TokenHash)
		if old.RevokedAt == nil || old.RevokedReason != dbtype.TokenRevokedRotated {
			t.Fatalf("ExchangeRefreshToken() left the old %s token revoked at %v (%q), want rotated", tok.Kind, old.RevokedAt, old.RevokedReason)
		}
		w.assertStamped(t, "the old "+string(tok.Kind)+" token's RevokedAt", *old.RevokedAt)
	}
	if _, err := in.Driver.TokenByHash(ctx, app.TokenHash, time.Now()); err != nil {
		t.Errorf("TokenByHash() of the application token after the exchange error = %v, want it live", err)
	}

	// The rotated token presented again is a reuse: the family's live tokens are
	// revoked as reuse (the rotated ones keep their reason), the application token
	// stands, and nothing new is issued.
	access3, refresh3 := newToken(dbtype.TokenAccess, ccc.NilUUID, tokenHash(14)), newToken(dbtype.TokenRefresh, ccc.NilUUID, tokenHash(15))
	if err := in.Driver.ExchangeRefreshToken(ctx, refresh1.TokenHash, time.Now(), access3, refresh3); !errors.Is(err, dbtype.ErrTokenReuse) {
		t.Fatalf("ExchangeRefreshToken() of a rotated token error = %v, want ErrTokenReuse", err)
	}
	for _, hash := range [][]byte{access2.TokenHash, refresh2.TokenHash} {
		if got := tokenState(ctx, t, in.Driver, hash); got.RevokedAt == nil || got.RevokedReason != dbtype.TokenRevokedReuse {
			t.Errorf("after the reuse, family token %x is revoked at %v (%q), want revoked as reuse", hash[:1], got.RevokedAt, got.RevokedReason)
		}
	}
	if got := tokenState(ctx, t, in.Driver, access1.TokenHash); got.RevokedReason != dbtype.TokenRevokedRotated {
		t.Errorf("after the reuse, the rotated access token is revoked as %q, want its rotation kept", got.RevokedReason)
	}
	if _, err := in.Driver.TokenByHash(ctx, app.TokenHash, time.Now()); err != nil {
		t.Errorf("TokenByHash() of the application token after the reuse error = %v, want it live", err)
	}
	if _, err := in.Driver.TokenState(ctx, access3.TokenHash); !httpio.HasNotFound(err) {
		t.Errorf("TokenState() of a token the reuse must not issue error = %v, want NotFound", err)
	}

	// What is not a live refresh token is NotFound: an access token, an expired or
	// unknown refresh token, and a refresh token already revoked by its user.
	expired := newToken(dbtype.TokenRefresh, user.ID, tokenHash(20))
	expired.ExpiresAt = time.Now().Add(-time.Second)
	byHand := newToken(dbtype.TokenRefresh, user.ID, tokenHash(21))
	insertTokens(ctx, t, in.Driver, expired, byHand)
	if err := in.Driver.RevokeUserToken(ctx, user.ID, byHand.ID, time.Now(), dbtype.TokenRevokedByHand); err != nil {
		t.Fatalf("RevokeUserToken() error = %v", err)
	}
	for _, tt := range []struct {
		name string
		hash []byte
	}{
		{name: "an application token", hash: app.TokenHash},
		{name: "an expired refresh token", hash: expired.TokenHash},
		{name: "an unknown token", hash: tokenHash(99)},
		{name: "a refresh token its user revoked", hash: byHand.TokenHash},
	} {
		if err := in.Driver.ExchangeRefreshToken(ctx, tt.hash, time.Now(), newToken(dbtype.TokenAccess, ccc.NilUUID, tokenHash(30)), newToken(dbtype.TokenRefresh, ccc.NilUUID, tokenHash(31))); !httpio.HasNotFound(err) {
			t.Errorf("ExchangeRefreshToken() of %s error = %v, want NotFound", tt.name, err)
		}
	}
	if _, err := in.Driver.TokenByHash(ctx, app.TokenHash, time.Now()); err != nil {
		t.Errorf("TokenByHash() of the application token after a refused exchange error = %v, want it live", err)
	}
}

func testDeviceCodeLifecycle(ctx context.Context, t *testing.T, h *AuthHarness) {
	in := h.New(ctx, t, Auth, AuthConfig{Auth: true})
	user := createUser(ctx, t, in.Driver, "pat@lakeside.edu")
	access, refresh := newFamily(ccc.NilUUID, tokenHash(10), tokenHash(11))
	access.Outlet, refresh.Outlet, access.ClientID, refresh.ClientID = "", "", "", ""

	code := deviceCodePending(ctx, t, h, in, "BCDFGHJK", tokenHash(1))
	deviceCodePolls(ctx, t, h, in, code, access, refresh)
	deviceCodeApproval(ctx, t, h, in, code, user.ID)
	consumed := deviceCodeRedemption(ctx, t, h, in, code, user.ID, access, refresh)
	for _, tok := range []*dbtype.Token{access, refresh} {
		if tok.UserID != user.ID || tok.Outlet != droidsOutlet || tok.ClientID != corralClient || !tok.Family.Valid {
			t.Errorf("RedeemDeviceCode() filled %s as user %s, outlet %q, client %q, family %v; want the code's and the caller's family", tok.Kind, tok.UserID, tok.Outlet, tok.ClientID, tok.Family)
		}
		live, err := in.Driver.TokenByHash(ctx, tok.TokenHash, time.Now())
		if err != nil {
			t.Fatalf("TokenByHash(%s) after the redemption error = %v", tok.Kind, err)
		}
		if diff := cmp.Diff(tok, live, tokenOpts); diff != "" {
			t.Errorf("TokenByHash(%s) mismatch (-want +got):\n%s", tok.Kind, diff)
		}
		assertSameTime(t, string(tok.Kind)+" CreatedAt", live.CreatedAt, consumed)
	}
	deviceCodeDenied(ctx, t, in, user.ID, access, refresh)
	deviceCodeExpiredAndUnknown(ctx, t, in, user.ID, access, refresh)
}

// devicePollInterval is the interval the lifecycle's polls are held to.
const devicePollInterval = 5 * time.Second

// deviceCodePending inserts a device code and proves it pending from the insert, read
// by the person's code, created at the database's time.
func deviceCodePending(ctx context.Context, t *testing.T, h *AuthHarness, in *AuthInstance, userCode string, hash []byte) *dbtype.DeviceCode {
	t.Helper()

	code := newDeviceCode(userCode, hash)
	w := startWindow(h.ClockLead)
	if err := in.Driver.InsertDeviceCode(ctx, code); err != nil {
		t.Fatalf("InsertDeviceCode() error = %v", err)
	}
	w.done()
	got, err := in.Driver.DeviceCodeByUserCode(ctx, code.UserCode, time.Now())
	if err != nil {
		t.Fatalf("DeviceCodeByUserCode() error = %v", err)
	}
	if diff := cmp.Diff(code, got, deviceCodeOpts); diff != "" {
		t.Errorf("DeviceCodeByUserCode() mismatch (-want +got):\n%s", diff)
	}
	w.assertStamped(t, "DeviceCodeByUserCode().CreatedAt", got.CreatedAt)
	if got.ApprovedAt != nil || got.DeniedAt != nil || got.LastPolledAt != nil || got.ConsumedAt != nil || got.UserID.Valid {
		t.Errorf("DeviceCodeByUserCode() = %+v, want pending, unpolled, nobody's", got)
	}

	return code
}

// deviceCodePolls runs the client's polls before any decision: pending, recorded;
// too soon, slow down and nothing written; after the interval, pending again; and no
// token issued by any of them.
func deviceCodePolls(ctx context.Context, t *testing.T, h *AuthHarness, in *AuthInstance, code *dbtype.DeviceCode, access, refresh *dbtype.Token) {
	t.Helper()

	w := startWindow(h.ClockLead)
	_, status, err := in.Driver.RedeemDeviceCode(ctx, code.DeviceCodeHash, time.Now(), devicePollInterval, access, refresh)
	w.done()
	if err != nil || status != dbtype.DevicePending {
		t.Fatalf("RedeemDeviceCode() before the approval = %q, %v; want pending", status, err)
	}
	polled, err := in.Driver.DeviceCodeState(ctx, code.DeviceCodeHash)
	if err != nil || polled.LastPolledAt == nil {
		t.Fatalf("DeviceCodeState() after a poll = %+v, %v; want LastPolledAt stamped", polled, err)
	}
	w.assertStamped(t, "LastPolledAt", *polled.LastPolledAt)
	if _, status, err := in.Driver.RedeemDeviceCode(ctx, code.DeviceCodeHash, time.Now(), devicePollInterval, access, refresh); err != nil || status != dbtype.DeviceSlowDown {
		t.Errorf("RedeemDeviceCode() within the interval = %q, %v; want slow_down", status, err)
	}
	if again, err := in.Driver.DeviceCodeState(ctx, code.DeviceCodeHash); err != nil || !again.LastPolledAt.Equal(*polled.LastPolledAt) {
		t.Errorf("a poll within the interval moved LastPolledAt to %v, want %v kept", again.LastPolledAt, polled.LastPolledAt)
	}
	if _, status, err := in.Driver.RedeemDeviceCode(ctx, code.DeviceCodeHash, time.Now().Add(devicePollInterval+time.Second), devicePollInterval, access, refresh); err != nil || status != dbtype.DevicePending {
		t.Errorf("RedeemDeviceCode() after the interval = %q, %v; want pending", status, err)
	}
	if _, err := in.Driver.TokenState(ctx, access.TokenHash); !httpio.HasNotFound(err) {
		t.Errorf("a poll before the approval issued a token: TokenState() error = %v, want NotFound", err)
	}
}

// deviceCodeApproval approves the code as userID and proves one decision stands:
// approved at the database's time by the user, not pending any more, not approvable
// or deniable again.
func deviceCodeApproval(ctx context.Context, t *testing.T, h *AuthHarness, in *AuthInstance, code *dbtype.DeviceCode, userID ccc.UUID) {
	t.Helper()

	w := startWindow(h.ClockLead)
	if err := in.Driver.ApproveDeviceCode(ctx, code.ID, userID, time.Now()); err != nil {
		t.Fatalf("ApproveDeviceCode() error = %v", err)
	}
	w.done()
	approved, err := in.Driver.DeviceCodeState(ctx, code.DeviceCodeHash)
	if err != nil || approved.ApprovedAt == nil || approved.UserID.UUID != userID {
		t.Fatalf("DeviceCodeState() after the approval = %+v, %v; want approved by the user", approved, err)
	}
	w.assertStamped(t, "ApprovedAt", *approved.ApprovedAt)
	if _, err := in.Driver.DeviceCodeByUserCode(ctx, code.UserCode, time.Now()); !httpio.HasNotFound(err) {
		t.Errorf("DeviceCodeByUserCode() of an approved code error = %v, want NotFound", err)
	}
	if err := in.Driver.ApproveDeviceCode(ctx, code.ID, userID, time.Now()); !httpio.HasNotFound(err) {
		t.Errorf("second ApproveDeviceCode() error = %v, want NotFound", err)
	}
	if err := in.Driver.DenyDeviceCode(ctx, code.ID, time.Now()); !httpio.HasNotFound(err) {
		t.Errorf("DenyDeviceCode() of an approved code error = %v, want NotFound", err)
	}
}

// deviceCodeRedemption redeems the approved code once, as userID, and returns when it
// was consumed: the tokens are created at that time.
func deviceCodeRedemption(ctx context.Context, t *testing.T, h *AuthHarness, in *AuthInstance, code *dbtype.DeviceCode, userID ccc.UUID, access, refresh *dbtype.Token) time.Time {
	t.Helper()

	w := startWindow(h.ClockLead)
	redeemed, status, err := in.Driver.RedeemDeviceCode(ctx, code.DeviceCodeHash, time.Now(), devicePollInterval, access, refresh)
	w.done()
	if err != nil || status != dbtype.DeviceApproved {
		t.Fatalf("RedeemDeviceCode() of an approved code = %q, %v; want approved", status, err)
	}
	if redeemed.UserID.UUID != userID {
		t.Errorf("RedeemDeviceCode() returned a code approved by %v, want the user", redeemed.UserID)
	}
	consumed, err := in.Driver.DeviceCodeState(ctx, code.DeviceCodeHash)
	if err != nil || consumed.ConsumedAt == nil {
		t.Fatalf("DeviceCodeState() after the redemption = %+v, %v; want consumed", consumed, err)
	}
	w.assertStamped(t, "ConsumedAt", *consumed.ConsumedAt)
	if _, _, err := in.Driver.RedeemDeviceCode(ctx, code.DeviceCodeHash, time.Now(), devicePollInterval, access, refresh); !httpio.HasNotFound(err) {
		t.Errorf("second RedeemDeviceCode() error = %v, want NotFound", err)
	}

	return *consumed.ConsumedAt
}

// deviceCodeDenied proves a denied code answers its client denied and takes no
// approval.
func deviceCodeDenied(ctx context.Context, t *testing.T, in *AuthInstance, userID ccc.UUID, access, refresh *dbtype.Token) {
	t.Helper()

	denied := newDeviceCode("LMNPQRST", tokenHash(2))
	if err := in.Driver.InsertDeviceCode(ctx, denied); err != nil {
		t.Fatalf("InsertDeviceCode() error = %v", err)
	}
	if err := in.Driver.DenyDeviceCode(ctx, denied.ID, time.Now()); err != nil {
		t.Fatalf("DenyDeviceCode() error = %v", err)
	}
	if _, status, err := in.Driver.RedeemDeviceCode(ctx, denied.DeviceCodeHash, time.Now(), devicePollInterval, access, refresh); err != nil || status != dbtype.DeviceDenied {
		t.Errorf("RedeemDeviceCode() of a denied code = %q, %v; want denied", status, err)
	}
	if err := in.Driver.ApproveDeviceCode(ctx, denied.ID, userID, time.Now()); !httpio.HasNotFound(err) {
		t.Errorf("ApproveDeviceCode() of a denied code error = %v, want NotFound", err)
	}
}

// deviceCodeExpiredAndUnknown proves an expired code answers its client expired, is
// not read by its user code and takes no decision, and an unknown code is NotFound.
func deviceCodeExpiredAndUnknown(ctx context.Context, t *testing.T, in *AuthInstance, userID ccc.UUID, access, refresh *dbtype.Token) {
	t.Helper()

	expired := newDeviceCode("VWXZBCDF", tokenHash(3))
	expired.ExpiresAt = time.Now().Add(-time.Second)
	if err := in.Driver.InsertDeviceCode(ctx, expired); err != nil {
		t.Fatalf("InsertDeviceCode() error = %v", err)
	}
	if _, status, err := in.Driver.RedeemDeviceCode(ctx, expired.DeviceCodeHash, time.Now(), devicePollInterval, access, refresh); err != nil || status != dbtype.DeviceExpired {
		t.Errorf("RedeemDeviceCode() of an expired code = %q, %v; want expired", status, err)
	}
	if _, err := in.Driver.DeviceCodeByUserCode(ctx, expired.UserCode, time.Now()); !httpio.HasNotFound(err) {
		t.Errorf("DeviceCodeByUserCode() of an expired code error = %v, want NotFound", err)
	}
	if err := in.Driver.ApproveDeviceCode(ctx, expired.ID, userID, time.Now()); !httpio.HasNotFound(err) {
		t.Errorf("ApproveDeviceCode() of an expired code error = %v, want NotFound", err)
	}
	if _, _, err := in.Driver.RedeemDeviceCode(ctx, tokenHash(99), time.Now(), devicePollInterval, access, refresh); !httpio.HasNotFound(err) {
		t.Errorf("RedeemDeviceCode() of an unknown code error = %v, want NotFound", err)
	}
}

func testTokensCascade(ctx context.Context, t *testing.T, h *AuthHarness) {
	in := h.New(ctx, t, Auth, AuthConfig{Auth: true})
	user := createUser(ctx, t, in.Driver, "pat@lakeside.edu")
	app := newToken(dbtype.TokenApplication, user.ID, tokenHash(1))
	insertTokens(ctx, t, in.Driver, app)
	code := newDeviceCode("BCDFGHJK", tokenHash(2))
	if err := in.Driver.InsertDeviceCode(ctx, code); err != nil {
		t.Fatalf("InsertDeviceCode() error = %v", err)
	}
	if err := in.Driver.ApproveDeviceCode(ctx, code.ID, user.ID, time.Now()); err != nil {
		t.Fatalf("ApproveDeviceCode() error = %v", err)
	}

	if err := in.Driver.DeleteUser(ctx, user.ID); err != nil {
		t.Fatalf("DeleteUser() error = %v", err)
	}
	if _, err := in.Driver.TokenState(ctx, app.TokenHash); !httpio.HasNotFound(err) {
		t.Errorf("TokenState() after the user was deleted error = %v, want NotFound: the token goes with the user", err)
	}
	if _, err := in.Driver.DeviceCodeState(ctx, code.DeviceCodeHash); !httpio.HasNotFound(err) {
		t.Errorf("DeviceCodeState() after the user was deleted error = %v, want NotFound: the approved code goes with the user", err)
	}
}
