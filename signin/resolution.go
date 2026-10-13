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
	return Allow(), nil
}

// NewUser is the user a resolver provisions. It has no password unless PasswordHash is
// set.
type NewUser struct {
	Username     string
	PasswordHash *securehash.Hash
	Disabled     bool
}

// IdentityOutcome is what a Resolution does with an external identity that is not yet
// linked to any user. A resolver builds its Resolution with Reject, Link, Provision or
// Confirm; Resolution.Outcome reads it back.
type IdentityOutcome int

const (
	// RejectIdentity refuses the sign-in (Reject). It is the zero value, so a nil
	// Resolution never grants access. The resolver's own writes are committed.
	RejectIdentity IdentityOutcome = iota
	// LinkIdentity links the identity to an existing user and signs in (Link).
	LinkIdentity
	// ProvisionUser creates the user, links the identity to it and signs in (Provision).
	ProvisionUser
	// RequireConfirmation holds the identity as pending until the person enters the
	// password of the existing user it names; the identity is then linked (Confirm).
	RequireConfirmation
)

// Resolution is a user resolver's answer for an unlinked external identity, built with
// Reject, Link, Provision or Confirm and refined with ResolutionOptions. A nil
// Resolution rejects.
type Resolution struct {
	outcome       IdentityOutcome
	userID        ccc.UUID
	newUser       *NewUser
	onProvisioned func(ctx context.Context, userID ccc.UUID) error
	tenant        string
	trusted       bool
	refusal       sessioninfo.LoginRefusalCode
}

// ResolutionOption refines a Link, Provision or Confirm resolution.
type ResolutionOption func(r *Resolution)

// Tenant stores tenant, the application's tenant key, on the identity link.
func Tenant(tenant string) ResolutionOption {
	return func(r *Resolution) { r.tenant = tenant }
}

// Reject refuses the sign-in with code, or sessioninfo.RefusedIdentityRejected when
// code is empty. The resolver's own writes, such as a record of the refused attempt,
// are committed.
func Reject(code sessioninfo.LoginRefusalCode) *Resolution {
	return &Resolution{outcome: RejectIdentity, refusal: code}
}

// Link links the identity to the existing user userID and signs in. A user that has a
// password is refused (ErrLinkRequiresConfirmation) unless trusted is set, which is
// right only for an enterprise connection on a domain the tenant has verified; use
// Confirm for such a user otherwise.
func Link(userID ccc.UUID, trusted bool, opts ...ResolutionOption) *Resolution {
	r := &Resolution{outcome: LinkIdentity, userID: userID, trusted: trusted}
	for _, opt := range opts {
		opt(r)
	}

	return r
}

// Provision creates user, links the identity to it, runs onProvisioned and signs in.
// onProvisioned, nil for none, runs in the resolver's transaction once the user is
// created, so the application can write its own rows for it: capture the transaction
// in the resolver's closure. The rows commit with the user, so the sign-in policy and
// the custom session data resolver can read them. The user and its link stay even when
// the sign-in policy then denies the sign-in or holds it for MFA.
func Provision(user *NewUser, onProvisioned func(ctx context.Context, userID ccc.UUID) error, opts ...ResolutionOption) *Resolution {
	r := &Resolution{outcome: ProvisionUser, newUser: user, onProvisioned: onProvisioned}
	for _, opt := range opts {
		opt(r)
	}

	return r
}

// Confirm holds the identity as pending until the person enters the password of the
// existing user userID. The identity is then linked.
func Confirm(userID ccc.UUID, opts ...ResolutionOption) *Resolution {
	r := &Resolution{outcome: RequireConfirmation, userID: userID}
	for _, opt := range opts {
		opt(r)
	}

	return r
}

// Outcome is what the resolution does.
func (r *Resolution) Outcome() IdentityOutcome {
	return r.outcome
}

// UserID is the existing user of a Link or Confirm resolution.
func (r *Resolution) UserID() ccc.UUID {
	return r.userID
}

// NewUser is the user a Provision resolution creates.
func (r *Resolution) NewUser() *NewUser {
	return r.newUser
}

// OnProvisioned is a Provision resolution's hook, nil for none.
func (r *Resolution) OnProvisioned() func(ctx context.Context, userID ccc.UUID) error {
	return r.onProvisioned
}

// Tenant is the tenant key the resolution stores on the link.
func (r *Resolution) Tenant() string {
	return r.tenant
}

// Trusted reports whether a Link resolution may link a user that has a password.
func (r *Resolution) Trusted() bool {
	return r.trusted
}

// Refusal is a Reject resolution's code.
func (r *Resolution) Refusal() sessioninfo.LoginRefusalCode {
	return r.refusal
}

// PolicyOutcome is what a Decision does with a sign-in. A policy builds its Decision
// with Allow, Deny or RequireMFA; Decision.Outcome reads it back.
type PolicyOutcome int

const (
	// DenySignIn refuses the sign-in (Deny). It is the zero value, so a nil Decision
	// never grants access. The policy's own writes are committed.
	DenySignIn PolicyOutcome = iota
	// AllowSignIn establishes the session (Allow).
	AllowSignIn
	// HoldForMFA holds the sign-in as pending until the application completes its MFA
	// step and calls CompletePending (RequireMFA).
	HoldForMFA
)

// Decision is a sign-in policy's answer, built with Allow, Deny or RequireMFA. A nil
// Decision denies.
type Decision struct {
	outcome PolicyOutcome
	refusal sessioninfo.LoginRefusalCode
	factors []sessioninfo.AuthMethod
}

// Allow establishes the session.
func Allow() *Decision {
	return &Decision{outcome: AllowSignIn}
}

// Deny refuses the sign-in with code, or sessioninfo.RefusedByPolicy when code is
// empty. The policy's own writes are committed.
func Deny(code sessioninfo.LoginRefusalCode) *Decision {
	return &Decision{outcome: DenySignIn, refusal: code}
}

// RequireMFA holds the sign-in as pending until the application completes its MFA step
// and calls CompletePending with the step-up events. factors are the methods those
// events may record, the application's own names such as "email-otp"; a completion by
// any other method is refused. With no factors, any method completes the step.
func RequireMFA(factors ...sessioninfo.AuthMethod) *Decision {
	return &Decision{outcome: HoldForMFA, factors: factors}
}

// Outcome is what the decision does.
func (d *Decision) Outcome() PolicyOutcome {
	return d.outcome
}

// Refusal is a Deny decision's code.
func (d *Decision) Refusal() sessioninfo.LoginRefusalCode {
	return d.refusal
}

// Factors are the methods a RequireMFA decision accepts for the step-up; none means
// any.
func (d *Decision) Factors() []sessioninfo.AuthMethod {
	return d.factors
}

// The causes of a refused sign-in, for errors.Is. A refused sign-in is also a
// sessioninfo.LoginRefusal, which carries the code the login page receives, and an
// Unauthorized client message.
var (
	// ErrIdentityRejected is the cause when the user resolver returned
	// RejectIdentity (Reject). The code is the resolution's, or
	// sessioninfo.RefusedIdentityRejected when that is empty.
	ErrIdentityRejected = errors.New("signin: the user resolver rejected the identity")
	// ErrLinkRequiresConfirmation is the cause when the user resolver returned
	// LinkIdentity (Link) for a user that has a password, without trusted. The code is
	// sessioninfo.RefusedIdentityRejected. The resolver should return Confirm instead.
	ErrLinkRequiresConfirmation = errors.New(
		"signin: an identity can't be linked to a user that has a password without confirmation (or a trusted link)")
	// ErrSignInDenied is the cause when the sign-in policy returned DenySignIn or no
	// decision. The code is the decision's, or sessioninfo.RefusedByPolicy.
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
	// Factors are the methods the sign-in policy accepts for the MFA step, for
	// PendingMFA; none means any.
	Factors []sessioninfo.AuthMethod
}

// Error describes the pending sign-in.
func (e *PendingSignInError) Error() string {
	return fmt.Sprintf("signin: sign-in pending %s for user %v", e.Reason, e.UserID)
}
