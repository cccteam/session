package dbtype

import (
	"time"

	"github.com/cccteam/ccc"
	"github.com/go-playground/errors/v5"
)

// MailLinkKind is what a mailed link does when it is followed.
type MailLinkKind string

const (
	// MailLinkInvitation invites an address into the application, or into one of its
	// tenants, with the roles the row carries. Whoever signs in or signs up at it
	// accepts it.
	MailLinkInvitation MailLinkKind = "invitation"
	// MailLinkVerification verifies an address a signed-in person adds to their own
	// account; UserID names the account.
	MailLinkVerification MailLinkKind = "verification"
	// MailLinkSignUp finishes a sign-up a person started by giving their address: the
	// follower sets a password and the account is created, the address verified.
	MailLinkSignUp MailLinkKind = "sign-up"
)

// Validate refuses a kind that is not one of the three.
func (k MailLinkKind) Validate() error {
	switch k {
	case MailLinkInvitation, MailLinkVerification, MailLinkSignUp:
		return nil
	default:
		return errors.Newf("%q is not a mail link kind", string(k))
	}
}

// MailLink is a row of the mail links table: one single-use link the library mailed.
// The mail carries an opaque token; the row keeps its hash. It is live while it is not
// consumed and not expired. CreatedAt and ConsumedAt are the database's time; ExpiresAt
// is the library's deadline, written as given.
type MailLink struct {
	ID        ccc.UUID
	TokenHash []byte
	Kind      MailLinkKind
	// Email is the address the link was mailed to, as given.
	Email string
	// UserID names the account a verification link belongs to; null for the other
	// kinds.
	UserID ccc.NullUUID
	// Tenant is the tenant an invitation seats the person in, "" for the application's
	// global surface or for the other kinds.
	Tenant string
	// RoleNames are the roles an invitation's acceptance grants; nil for the other
	// kinds.
	RoleNames []string
	// InvitedBy is the user who sent an invitation; null when unknown or for the other
	// kinds.
	InvitedBy  ccc.NullUUID
	CreatedAt  time.Time
	ExpiresAt  time.Time
	ConsumedAt *time.Time
}
