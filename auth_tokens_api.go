package session

import (
	"context"
	"strings"
	"time"

	"github.com/cccteam/ccc"
	"github.com/cccteam/ccc/tracer"
	"github.com/cccteam/httpio"
	"github.com/cccteam/logger"
	"github.com/cccteam/session/sessionstorage"
	"github.com/go-playground/errors/v5"
)

// tokenNameMaxLength is the longest name an application token takes.
const tokenNameMaxLength = 200

// ApplicationTokenRequest is what a person asks for when they issue an application
// token.
type ApplicationTokenRequest struct {
	// UserID is the person the token acts as.
	UserID ccc.UUID
	// Outlet is the registered machine outlet the token is for.
	Outlet string
	// Name is what the person calls the token, so they recognize it in their listing.
	Name string
	// ExpiresIn is how long the token lives, at most the Auth's application token
	// lifetime; zero takes that lifetime.
	ExpiresIn time.Duration
}

// IssuedToken is a token as it leaves the library, once: Secret is what the person or
// the client holds and is never read back, and Token is the row the store keeps, its
// hash left out.
type IssuedToken struct {
	Secret string
	Token  *sessionstorage.Token
}

// withoutHash is t with its hash left out, as the API hands rows out.
func withoutHash(t *sessionstorage.Token) *sessionstorage.Token {
	row := *t
	row.TokenHash = nil

	return &row
}

// CreateApplicationToken issues an application token for req: the secret is returned
// this once, and the store keeps its hash. The outlet must be registered
// (RegisterMachineOutlet), the name set and at most 200 characters, the lifetime at
// most the Auth's application token lifetime, and the user there and enabled;
// otherwise the request is refused with 400, or 404 for an unknown user.
func (p *AuthAPI[S, U, Tx]) CreateApplicationToken(ctx context.Context, req *ApplicationTokenRequest) (*IssuedToken, error) {
	ctx, span := tracer.Start(ctx)
	defer span.End()

	a := p.auth
	if err := a.requireOutlet(req.Outlet); err != nil {
		return nil, err
	}
	name := strings.TrimSpace(req.Name)
	if name == "" || len(name) > tokenNameMaxLength {
		return nil, httpio.NewBadRequestMessage("a token needs a name of at most 200 characters")
	}
	lifetime := req.ExpiresIn
	switch {
	case lifetime == 0:
		lifetime = a.settings.tokens.applicationMax
	case lifetime < 0 || lifetime > a.settings.tokens.applicationMax:
		return nil, httpio.NewBadRequestMessagef("a token lives at most %s", a.settings.tokens.applicationMax)
	}
	user, err := a.storage.User(ctx, req.UserID)
	if err != nil {
		return nil, errors.Wrap(err, "sessionstorage.AuthStore.User()")
	}
	if user.Disabled {
		return nil, httpio.NewBadRequestMessage("the user is disabled")
	}

	secret, hash, err := newSecret()
	if err != nil {
		return nil, err
	}
	id, err := ccc.NewUUID()
	if err != nil {
		return nil, errors.Wrap(err, "ccc.NewUUID()")
	}
	tok := &sessionstorage.Token{
		ID: id, TokenHash: hash, Kind: sessionstorage.TokenApplication, UserID: user.ID, Outlet: req.Outlet, Name: name,
		ExpiresAt: time.Now().Add(lifetime),
	}
	if err := a.storage.InsertToken(ctx, tok); err != nil {
		return nil, errors.Wrap(err, "sessionstorage.AuthStore.InsertToken()")
	}

	return &IssuedToken{Secret: secret, Token: withoutHash(tok)}, nil
}

// Tokens lists a person's live tokens, newest first, their hashes left out: their
// application tokens and the access and refresh tokens of their device grants.
func (p *AuthAPI[S, U, Tx]) Tokens(ctx context.Context, userID ccc.UUID) ([]*sessionstorage.Token, error) {
	ctx, span := tracer.Start(ctx)
	defer span.End()

	tokens, err := p.auth.storage.Tokens(ctx, userID)
	if err != nil {
		return nil, errors.Wrap(err, "sessionstorage.AuthStore.Tokens()")
	}
	rows := make([]*sessionstorage.Token, len(tokens))
	for i, t := range tokens {
		rows[i] = withoutHash(t)
	}

	return rows, nil
}

// RevokeToken revokes the live token id of userID: an application token alone, or a
// device grant's token with its family. A token that is not live, or not the user's,
// is NotFound.
func (p *AuthAPI[S, U, Tx]) RevokeToken(ctx context.Context, userID, id ccc.UUID) error {
	ctx, span := tracer.Start(ctx)
	defer span.End()

	if err := p.auth.storage.RevokeUserToken(ctx, userID, id, sessionstorage.TokenRevokedByHand); err != nil {
		return errors.Wrap(err, "sessionstorage.AuthStore.RevokeUserToken()")
	}

	return nil
}

// RevokeUserTokens revokes every live token of a person, for example when an
// operator takes their access away.
func (p *AuthAPI[S, U, Tx]) RevokeUserTokens(ctx context.Context, userID ccc.UUID) error {
	ctx, span := tracer.Start(ctx)
	defer span.End()

	if err := p.auth.storage.RevokeUserTokens(ctx, userID, sessionstorage.TokenRevokedWithUser); err != nil {
		return errors.Wrap(err, "sessionstorage.AuthStore.RevokeUserTokens()")
	}

	return nil
}

// DeviceAuthorizationRequest is what a command-line client asks for when it starts a
// device authorization.
type DeviceAuthorizationRequest struct {
	// ClientID names the client, as the person is told and the grant records.
	ClientID string
	// Outlet is the registered machine outlet the grant's tokens are for.
	Outlet string
}

// DeviceAuthorization is what a client is told when it starts a device authorization
// (RFC 8628, 3.2): the device code it polls with, the user code the person types, the
// application's page to type it at, that page with the code already in, how long the
// authorization waits, and the interval between polls.
type DeviceAuthorization struct {
	DeviceCode              string
	UserCode                string
	VerificationURI         string
	VerificationURIComplete string
	ExpiresIn               time.Duration
	Interval                time.Duration
}

// StartDeviceAuthorization starts a device authorization for req: the client shows
// the person the user code and the verification URI, and polls RedeemDeviceCode with
// the device code until the person decides. The client id must be set and the outlet
// registered, else 400.
func (p *AuthAPI[S, U, Tx]) StartDeviceAuthorization(ctx context.Context, req *DeviceAuthorizationRequest) (*DeviceAuthorization, error) {
	ctx, span := tracer.Start(ctx)
	defer span.End()

	a := p.auth
	if err := a.requireOutlet(req.Outlet); err != nil {
		return nil, err
	}
	clientID := strings.TrimSpace(req.ClientID)
	if clientID == "" || len(clientID) > tokenNameMaxLength {
		return nil, httpio.NewBadRequestMessage("a device authorization names its client, in at most 200 characters")
	}
	secret, hash, err := newSecret()
	if err != nil {
		return nil, err
	}
	userCode, err := newUserCode()
	if err != nil {
		return nil, err
	}
	id, err := ccc.NewUUID()
	if err != nil {
		return nil, errors.Wrap(err, "ccc.NewUUID()")
	}
	code := &sessionstorage.DeviceCode{
		ID: id, DeviceCodeHash: hash, UserCode: userCode, ClientID: clientID, Outlet: req.Outlet, ExpiresAt: time.Now().Add(a.settings.tokens.deviceCode),
	}
	if err := a.storage.InsertDeviceCode(ctx, code); err != nil {
		return nil, errors.Wrap(err, "sessionstorage.AuthStore.InsertDeviceCode()")
	}
	verification := a.settings.tokens.verificationURL

	return &DeviceAuthorization{
		DeviceCode: secret, UserCode: formatUserCode(userCode),
		VerificationURI: verification, VerificationURIComplete: verification + "?" + userCodeParam + "=" + formatUserCode(userCode),
		ExpiresIn: a.settings.tokens.deviceCode, Interval: a.settings.tokens.pollInterval,
	}, nil
}

// TokenPair is what a device grant or a refresh hands the client: the access token it
// presents on the outlet, how long that lives, and the refresh token it exchanges for
// the next pair.
type TokenPair struct {
	AccessToken  string
	RefreshToken string
	ExpiresIn    time.Duration
}

// mintPair mints a device grant's access and refresh tokens as the store takes them,
// in one new family, and the secrets the client receives. The store fills the user,
// outlet and client in from the grant or the token exchanged.
func (a *Auth[S, U, Tx]) mintPair() (access, refresh *sessionstorage.Token, pair *TokenPair, err error) {
	family, err := ccc.NewUUID()
	if err != nil {
		return nil, nil, nil, errors.Wrap(err, "ccc.NewUUID()")
	}
	pair = &TokenPair{ExpiresIn: a.settings.tokens.access}
	now := time.Now()
	mint := func(kind sessionstorage.TokenKind, lifetime time.Duration) (*sessionstorage.Token, string, error) {
		secret, hash, err := newSecret()
		if err != nil {
			return nil, "", err
		}
		id, err := ccc.NewUUID()
		if err != nil {
			return nil, "", errors.Wrap(err, "ccc.NewUUID()")
		}

		return &sessionstorage.Token{ID: id, TokenHash: hash, Kind: kind, Family: ccc.NullUUIDFromUUID(family), ExpiresAt: now.Add(lifetime)}, secret, nil
	}
	if access, pair.AccessToken, err = mint(sessionstorage.TokenAccess, a.settings.tokens.access); err != nil {
		return nil, nil, nil, err
	}
	if refresh, pair.RefreshToken, err = mint(sessionstorage.TokenRefresh, a.settings.tokens.refresh); err != nil {
		return nil, nil, nil, err
	}

	return access, refresh, pair, nil
}

// RedeemDeviceCode is the client's poll of its device authorization: the pair once
// the person approved it, with status DeviceApproved, and once only; otherwise no
// pair and the status, DevicePending while the person has not decided, DeviceSlowDown
// when the client polled before the interval passed, DeviceDenied, or DeviceExpired. A
// device code that is unknown or was redeemed already is NotFound.
func (p *AuthAPI[S, U, Tx]) RedeemDeviceCode(ctx context.Context, deviceCode string) (*TokenPair, sessionstorage.DeviceCodeStatus, error) {
	ctx, span := tracer.Start(ctx)
	defer span.End()

	a := p.auth
	access, refresh, pair, err := a.mintPair()
	if err != nil {
		return nil, "", err
	}
	_, status, err := a.storage.RedeemDeviceCode(ctx, hashToken(deviceCode), a.settings.tokens.pollInterval, access, refresh)
	if err != nil {
		return nil, "", errors.Wrap(err, "sessionstorage.AuthStore.RedeemDeviceCode()")
	}
	if status != sessionstorage.DeviceApproved {
		return nil, status, nil
	}

	return pair, status, nil
}

// RefreshTokens exchanges a refresh token for the next pair: the one presented is
// revoked and the pair is issued in its family, for its person, outlet and client. A
// token that is not a live refresh token is NotFound. A refresh token presented again
// after its exchange is a reuse: the whole family is revoked, so the client that
// holds the current pair loses it too, and the error is
// sessionstorage.ErrTokenReuse under an Unauthorized refusal.
func (p *AuthAPI[S, U, Tx]) RefreshTokens(ctx context.Context, refreshToken string) (*TokenPair, error) {
	ctx, span := tracer.Start(ctx)
	defer span.End()

	a := p.auth
	access, refresh, pair, err := a.mintPair()
	if err != nil {
		return nil, err
	}
	if err := a.storage.ExchangeRefreshToken(ctx, hashToken(refreshToken), access, refresh); err != nil {
		if errors.Is(err, sessionstorage.ErrTokenReuse) {
			logger.FromCtx(ctx).Warn("a rotated refresh token was presented again; its family is revoked")

			return nil, httpio.NewUnauthorizedMessageWithError(err, "the refresh token was reused; sign in again")
		}

		return nil, errors.Wrap(err, "sessionstorage.AuthStore.ExchangeRefreshToken()")
	}

	return pair, nil
}

// PendingDevice returns the device authorization the person's code names while it
// waits for their decision, its hash left out, so the approval page can say which
// client asks for which outlet. A code that names no pending authorization is NotFound.
func (p *AuthAPI[S, U, Tx]) PendingDevice(ctx context.Context, userCode string) (*sessionstorage.DeviceCode, error) {
	ctx, span := tracer.Start(ctx)
	defer span.End()

	code, err := p.auth.storage.DeviceCode(ctx, normalizeUserCode(userCode))
	if err != nil {
		return nil, errors.Wrap(err, "sessionstorage.AuthStore.DeviceCode()")
	}
	row := *code
	row.DeviceCodeHash = nil

	return &row, nil
}

// ApproveDevice records that userID approved the device authorization the person's
// code names; the client's next poll receives the pair as that person. A code that
// names no pending authorization is NotFound, so one decision stands.
func (p *AuthAPI[S, U, Tx]) ApproveDevice(ctx context.Context, userID ccc.UUID, userCode string) error {
	ctx, span := tracer.Start(ctx)
	defer span.End()

	code, err := p.auth.storage.DeviceCode(ctx, normalizeUserCode(userCode))
	if err != nil {
		return errors.Wrap(err, "sessionstorage.AuthStore.DeviceCode()")
	}
	if err := p.auth.storage.ApproveDeviceCode(ctx, code.ID, userID); err != nil {
		return errors.Wrap(err, "sessionstorage.AuthStore.ApproveDeviceCode()")
	}

	return nil
}

// DenyDevice records that the person denied the device authorization their code
// names; the client's next poll is told so. A code that names no pending
// authorization is NotFound.
func (p *AuthAPI[S, U, Tx]) DenyDevice(ctx context.Context, userCode string) error {
	ctx, span := tracer.Start(ctx)
	defer span.End()

	code, err := p.auth.storage.DeviceCode(ctx, normalizeUserCode(userCode))
	if err != nil {
		return errors.Wrap(err, "sessionstorage.AuthStore.DeviceCode()")
	}
	if err := p.auth.storage.DenyDeviceCode(ctx, code.ID); err != nil {
		return errors.Wrap(err, "sessionstorage.AuthStore.DenyDeviceCode()")
	}

	return nil
}
