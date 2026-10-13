package signin

import (
	"context"
	"fmt"

	"github.com/cccteam/ccc"
	"github.com/cccteam/ccc/securehash"
	"github.com/cccteam/session/sessioninfo"
	"github.com/go-playground/errors/v5"
)

// UserResolver decides an external identity that is not linked to any user yet: the
// application's answer to who the person is. Every external method takes one at its
// registration, typed to the method's identity (azure.UserResolver, google.UserResolver,
// workos.UserResolver), and hands the core this form over the sign-in request. It runs
// in the first of a sign-in's two transactions, which commits unless an error is
// returned, so a rejection keeps the resolver's own writes; see "Storage and schema" in
// the README. Tx is the storage's transaction type: pgx.Tx on PostgreSQL,
// *spanner.ReadWriteTransaction on Spanner. Spanner may retry the transaction, so the
// resolver must not have side effects outside it.
type UserResolver[Tx any] func(ctx context.Context, tx Tx, req *sessioninfo.NewSessionRequest) (*Resolution, error)

// Policy decides a sign-in once its user is known and before any session exists, for
// every sign-in method. session.NewAuth requires one: AllowAll, or the application's
// rule. It runs in the transaction that inserts the session; the user resolution has
// committed by then, so the policy can read the user and the rows the resolver wrote,
// and req.User says how the user was found. The transaction commits unless an error is
// returned, so a DenySignIn or RequireMFA answer keeps the policy's own writes.
type Policy[Tx any] func(ctx context.Context, tx Tx, req *sessioninfo.NewSessionRequest) (*Decision, error)

// AllowAll is the sign-in policy that allows every sign-in. Pass it to session.NewAuth
// as it is; its transaction type is inferred from the storage.
func AllowAll[Tx any](context.Context, Tx, *sessioninfo.NewSessionRequest) (*Decision, error) {
	return &Decision{Outcome: AllowSignIn}, nil
}

// NewUser is the user a resolver provisions. It has no password unless PasswordHash is
// set.
type NewUser struct {
	Username     string
	PasswordHash *securehash.Hash
	Disabled     bool
}

// IdentityOutcome is a user resolver's decision for an external identity that is not
// yet linked to any user.
type IdentityOutcome int

const (
	// RejectIdentity refuses the sign-in with Resolution.Refusal. It is the zero value,
	// so an empty Resolution never grants access. The resolver's own writes are
	// committed.
	RejectIdentity IdentityOutcome = iota
	// LinkIdentity links the identity to Resolution.UserID and signs in. It is refused
	// for a user that has a password unless Resolution.TrustedForLinking is set.
	// Use RequireConfirmation for such a user.
	LinkIdentity
	// ProvisionUser creates the user in Resolution.NewUser, links the identity to it,
	// runs Resolution.OnProvisioned, and signs in. The user and its link stay even when
	// the sign-in policy then denies the sign-in or holds it for MFA.
	ProvisionUser
	// RequireConfirmation holds the identity as pending until the user enters the
	// password of the existing user Resolution.UserID. The identity is then linked.
	RequireConfirmation
)

// Resolution is a user resolver's answer for an unlinked external identity.
type Resolution struct {
	Outcome IdentityOutcome
	// UserID is the existing user for LinkIdentity and RequireConfirmation.
	UserID ccc.UUID
	// NewUser is the user to create for ProvisionUser.
	NewUser *NewUser
	// OnProvisioned runs in the resolver's transaction after the user is created,
	// so the application can write its own rows for it. Capture the transaction in the
	// resolver's closure. The rows commit with the user, so the sign-in policy and
	// the custom session data resolver can read them.
	OnProvisioned func(ctx context.Context, userID ccc.UUID) error
	// Tenant is the application's tenant key, stored on the identity link.
	Tenant string
	// TrustedForLinking allows LinkIdentity for a user that has a password. Set it
	// only for an enterprise connection on a domain the tenant has verified.
	TrustedForLinking bool
	// Refusal is the code returned to the client for RejectIdentity.
	Refusal sessioninfo.LoginRefusalCode
}

// PolicyOutcome is a sign-in policy's decision.
type PolicyOutcome int

const (
	// DenySignIn refuses the sign-in with Decision.Refusal. It is the zero value.
	// The policy's own writes are committed.
	DenySignIn PolicyOutcome = iota
	// AllowSignIn establishes the session.
	AllowSignIn
	// RequireMFA holds the sign-in as pending until the application completes its MFA
	// step and calls CompletePending.
	RequireMFA
)

// Decision is a sign-in policy's answer.
type Decision struct {
	Outcome PolicyOutcome
	Refusal sessioninfo.LoginRefusalCode
}

// The causes of a refused sign-in, for errors.Is. A refused sign-in is also a
// sessioninfo.LoginRefusal, which carries the code the login page receives, and an
// Unauthorized client message.
var (
	// ErrIdentityRejected is the cause when the user resolver returned
	// RejectIdentity. The code is Resolution.Refusal, or
	// sessioninfo.RefusedIdentityRejected when that is empty.
	ErrIdentityRejected = errors.New("signin: the user resolver rejected the identity")
	// ErrLinkRequiresConfirmation is the cause when the user resolver returned
	// LinkIdentity for a user that has a password, without TrustedForLinking. The
	// code is sessioninfo.RefusedIdentityRejected. The resolver should return
	// RequireConfirmation instead.
	ErrLinkRequiresConfirmation = errors.New(
		"signin: an identity can't be linked to a user that has a password without confirmation (or TrustedForLinking)")
	// ErrSignInDenied is the cause when the sign-in policy returned DenySignIn or no
	// decision. The code is Decision.Refusal, or sessioninfo.RefusedByPolicy.
	ErrSignInDenied = errors.New("signin: the sign-in policy denied the sign-in")
	// ErrUserDisabled is the cause when the sign-in resolved to a disabled user.
	// The code is sessioninfo.RefusedUserDisabled.
	ErrUserDisabled = errors.New("signin: the user is disabled")
)

// PendingSignInError is returned by a sign-in that resolved to a user but must wait.
// Its Reason is sessioninfo.PendingConfirmation when the user resolver returned
// RequireConfirmation, and sessioninfo.PendingMFA when the sign-in policy returned
// RequireMFA. UserID is the user it waits on. No session is written, but the user
// resolution and the hooks' own writes are committed. Use errors.As to read it.
type PendingSignInError struct {
	// Reason is why the sign-in waits.
	Reason sessioninfo.PendingReason
	// UserID is the user the sign-in resolved to.
	UserID ccc.NullUUID
	// Username is that user's username.
	Username string
	// Tenant is the resolver's tenant key for the link to be made.
	Tenant string
}

// Error describes the pending sign-in.
func (e *PendingSignInError) Error() string {
	return fmt.Sprintf("signin: sign-in pending %s for user %v", e.Reason, e.UserID)
}
