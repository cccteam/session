package dbtype

import (
	"time"

	"github.com/cccteam/ccc"
	"github.com/go-playground/errors/v5"
)

// TokenKind is what a row of the tokens table is.
type TokenKind string

const (
	// TokenApplication is a token a person issued to an application of their own: a
	// bearer credential on a machine outlet that lives until its expiry or its
	// revocation.
	TokenApplication TokenKind = "application"
	// TokenAccess is the short-lived bearer credential a device grant or a refresh
	// issued to a command-line client. It and its refresh token share a family.
	TokenAccess TokenKind = "access"
	// TokenRefresh is the credential a command-line client exchanges for its next
	// access token. It is never presented on a machine outlet, and it rotates on every
	// exchange: the one presented is revoked and a successor issued in its family.
	TokenRefresh TokenKind = "refresh"
)

// Validate refuses a kind that is not one of the three.
func (k TokenKind) Validate() error {
	switch k {
	case TokenApplication, TokenAccess, TokenRefresh:
		return nil
	default:
		return errors.Newf("%q is not a token kind", string(k))
	}
}

// Bearer reports whether a token of the kind is presented as a bearer credential on
// a machine outlet: an application token or an access token. A refresh token is not.
func (k TokenKind) Bearer() bool {
	return k == TokenApplication || k == TokenAccess
}

// TokenRevocation says why a token was revoked.
type TokenRevocation string

const (
	// TokenRevokedByHand is a token the person, or the application on their behalf,
	// revoked.
	TokenRevokedByHand TokenRevocation = "revoked"
	// TokenRevokedRotated is a refresh token a successor replaced at an exchange.
	TokenRevokedRotated TokenRevocation = "rotated"
	// TokenRevokedReuse is a token revoked with its family because a rotated refresh
	// token of the family was presented again.
	TokenRevokedReuse TokenRevocation = "reuse"
	// TokenRevokedWithUser is a token revoked with every token of its user.
	TokenRevokedWithUser TokenRevocation = "user"
)

// Validate refuses a reason that is not one of the four.
func (r TokenRevocation) Validate() error {
	switch r {
	case TokenRevokedByHand, TokenRevokedRotated, TokenRevokedReuse, TokenRevokedWithUser:
		return nil
	default:
		return errors.Newf("%q is not a token revocation", string(r))
	}
}

// ErrTokenReuse is returned by a refresh exchange that was given a refresh token
// already rotated: the whole family is revoked, since a rotated token presented again
// means two parties hold it.
var ErrTokenReuse = errors.New("the refresh token was presented again after its rotation; its family is revoked")

// Token is a row of the tokens table: one credential. The client holds an opaque
// secret and the row keeps its hash. It is live while it is not revoked and not
// expired. CreatedAt, LastUsedAt and RevokedAt are the database's time; ExpiresAt is
// the library's deadline, written as given.
type Token struct {
	ID        ccc.UUID
	TokenHash []byte
	Kind      TokenKind
	// UserID is the person the token acts as.
	UserID ccc.UUID
	// Outlet names the machine outlet the token was issued for, the only one it is
	// accepted on.
	Outlet string
	// Name is the name the person gave an application token; "" for the tokens of a
	// device grant.
	Name string
	// Family groups a device grant's access and refresh tokens, and every successor a
	// refresh issues, so a reuse revokes them together; null for an application token.
	Family ccc.NullUUID
	// ClientID is the client a device grant was issued to; "" for an application token.
	ClientID      string
	CreatedAt     time.Time
	ExpiresAt     time.Time
	LastUsedAt    *time.Time
	RevokedAt     *time.Time
	RevokedReason TokenRevocation
}

// Live reports whether the token is live at now: not revoked and not expired.
func (t *Token) Live(now time.Time) bool {
	return t.RevokedAt == nil && t.ExpiresAt.After(now)
}

// DeviceCode is a row of the device codes table: one device authorization a
// command-line client started (RFC 8628). The client holds the opaque device code and
// the row keeps its hash; the person is shown the user code. The row is pending until
// a signed-in person approves or denies it, or it expires; an approved row is consumed
// once, when the client's poll redeems it for its tokens. CreatedAt, ApprovedAt,
// DeniedAt, LastPolledAt and ConsumedAt are the database's time; ExpiresAt is the
// library's deadline, written as given.
type DeviceCode struct {
	ID             ccc.UUID
	DeviceCodeHash []byte
	// UserCode is the code the person types, normalized: upper case, no separator.
	UserCode string
	ClientID string
	Outlet   string
	// UserID is the person who approved the authorization; null while it is pending.
	UserID       ccc.NullUUID
	CreatedAt    time.Time
	ExpiresAt    time.Time
	ApprovedAt   *time.Time
	DeniedAt     *time.Time
	LastPolledAt *time.Time
	ConsumedAt   *time.Time
}

// Pending reports whether the authorization still waits for the person at now.
func (d *DeviceCode) Pending(now time.Time) bool {
	return d.ApprovedAt == nil && d.DeniedAt == nil && d.ConsumedAt == nil && d.ExpiresAt.After(now)
}

// DeviceCodeStatus is what a client's poll of its device code learned.
type DeviceCodeStatus string

const (
	// DevicePending is a code the person has not decided on yet; poll again after the
	// interval.
	DevicePending DeviceCodeStatus = "pending"
	// DeviceSlowDown is a poll before the interval passed; nothing was read
	// or written for it, and it polls again after a longer interval.
	DeviceSlowDown DeviceCodeStatus = "slow_down"
	// DeviceApproved is a code the person approved, whose tokens were issued, once.
	DeviceApproved DeviceCodeStatus = "approved"
	// DeviceDenied is a code the person denied.
	DeviceDenied DeviceCodeStatus = "denied"
	// DeviceExpired is a code nobody decided on before the deadline.
	DeviceExpired DeviceCodeStatus = "expired"
)
