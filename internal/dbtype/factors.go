package dbtype

import (
	"time"

	"github.com/cccteam/ccc"
)

// FactorCode is a row of the factor codes table: one code the library mailed for a
// pending sign-in's second factor. The mail carries the code and the row keeps its
// hash, salted by the pending sign-in it belongs to. It is live while it is not
// consumed and not expired; Attempts counts the wrong codes entered against it, and
// the Auth consumes it at the limit, so a code is guessed at most that many times. A
// new code for the same pending sign-in consumes the earlier one. CreatedAt and
// ConsumedAt are the database's time; ExpiresAt is the library's deadline, written as
// given.
type FactorCode struct {
	ID ccc.UUID
	// PendingID is the pending sign-in the code was sent for.
	PendingID ccc.UUID
	// Email is the address the code was mailed to.
	Email      string
	CodeHash   []byte
	Attempts   int
	CreatedAt  time.Time
	ExpiresAt  time.Time
	ConsumedAt *time.Time
}

// TrustedDevice is a row of the trusted devices table: a browser the person asked to
// be remembered after a second factor, which then stands in for the factor at the
// person's next sign-ins until it expires or is revoked. The browser holds an opaque
// token in the trusted device cookie and the row keeps its hash. It is live while it is
// not revoked and not expired. CreatedAt, LastUsedAt and RevokedAt are the database's
// time; ExpiresAt is the library's deadline, written as given.
type TrustedDevice struct {
	ID         ccc.UUID
	UserID     ccc.UUID
	TokenHash  []byte
	CreatedAt  time.Time
	ExpiresAt  time.Time
	LastUsedAt *time.Time
	RevokedAt  *time.Time
}
