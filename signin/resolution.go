package signin

import (
	"context"
	"fmt"

	"github.com/cccteam/ccc"
	"github.com/cccteam/ccc/securehash"
	"github.com/cccteam/session/sessioninfo"
	"github.com/go-playground/errors/v5"
)

// AccountRule is an application's own rule for an external identity's first sign-in:
// an identity that is not linked to any user yet is given to it, and it answers who
// the person is with Reject, Link, Provision or Confirm, or leaves the decision to the
// registration's standard rule with Standard, after checks of its own. It is optional
// on the Entra and Google methods, which have a standard rule (StandardAccountRule),
// and required on a method that has none (WorkOS, under internal until v0.13.1). Every
// external method takes one at its registration, typed to the method's identity
// (azure.AccountRule, google.AccountRule), and hands the core this form over the
// sign-in request. It runs in the first of a sign-in's two transactions, which commits
// unless an error is returned, so a rejection keeps the rule's own writes; see
// "Storage and schema" in the README. Tx is the storage's transaction type: pgx.Tx on
// PostgreSQL, *spanner.ReadWriteTransaction on Spanner. Spanner may retry the
// transaction, so the rule must not have side effects outside it. A linked identity
// never reaches it.
type AccountRule[Tx any] func(ctx context.Context, tx Tx, req *sessioninfo.NewSessionRequest) (*Resolution, error)

// StandardAccountRule is the library's rule for an external identity's first sign-in,
// declared on a registration (azure.Config.Accounts, google.Config.Accounts) and
// applied by the core inside the sign-in's first transaction, when the registration
// has no AccountRule or its AccountRule answers Standard. Every standard rule refuses
// a guest of the directory (guest_account) and, when the method synchronizes roles, a
// token asserting no application role (no_roles), both before any row is written; the
// identity's sign-in name (Identity.SignInName: the user principal name on Entra, the
// verified email on Google) is the username, and an identity without one is refused
// (no_email). A pre-created user under that name, matched without regard to case, is
// linked: after a password confirmation when the user has a password, outright when
// the user has none and signs in through no other connection yet. The rules differ in
// what happens to a person no user was created for.
type StandardAccountRule string

const (
	// MembersOfDirectory provisions an account for every member of the directory, under
	// the sign-in name. It is the default for a registration that serves one
	// organization.
	MembersOfDirectory StandardAccountRule = "members-of-directory"
	// InvitedUsersOnly provisions nothing: a person no user was created for is refused
	// (not_invited). The application creates the users under their sign-in names, with
	// or without a password, before they sign in.
	InvitedUsersOnly StandardAccountRule = "invited-users-only"
	// OpenSignUp provisions an account for anyone who signs in, under the sign-in name.
	// It is for public applications, with any organization or personal accounts; a
	// registration serving one organization refuses it at startup.
	OpenSignUp StandardAccountRule = "open-sign-up"
)

// Validate refuses a value that is not one of the standard rules. The empty value is
// refused too: a registration that applies no standard rule leaves it empty and
// requires an AccountRule, which the core checks itself.
func (r StandardAccountRule) Validate() error {
	switch r {
	case MembersOfDirectory, InvitedUsersOnly, OpenSignUp:
		return nil
	default:
		return errors.Newf("%q is not a standard account rule: use signin.MembersOfDirectory, signin.InvitedUsersOnly or signin.OpenSignUp", string(r))
	}
}

// Policy is the application's sign-in rule, asked once a sign-in's user is known and
// before any session exists, for every sign-in method and for a session the application
// starts for a user it authenticated itself. It is optional: an Auth without one
// decides a sign-in on the library's own checks (the user exists and is enabled, the
// identity is linked or resolved, roles reconcile); session.Auth.SetSignInPolicy sets
// one. It runs in the transaction that inserts the session; the user resolution has
// committed by then, so the policy can read the user and the rows the account rule wrote,
// and req.User says how the user was found. The transaction commits unless an error is
// returned, so a DenySignIn or RequireMFA answer keeps the policy's own writes.
type Policy[Tx any] func(ctx context.Context, tx Tx, req *sessioninfo.NewSessionRequest) (*Decision, error)

// Then returns the policy that asks p and, when p allows the sign-in, asks next and
// answers its decision: the library's tenant policy (TenantPolicy) first, then the
// application's own rule for what the tenant policy cannot know. A Deny or a
// RequireMFA from p is answered as it is, and next is not asked. A nil next is a
// wiring mistake and panics.
func (p Policy[Tx]) Then(next Policy[Tx]) Policy[Tx] {
	if next == nil {
		panic("signin: Policy.Then was given nil: pass the application's rule")
	}

	return func(ctx context.Context, tx Tx, req *sessioninfo.NewSessionRequest) (*Decision, error) {
		decision, err := p(ctx, tx, req)
		if err != nil {
			return nil, err
		}
		if decision == nil || decision.Outcome() != AllowSignIn {
			return decision, nil
		}

		return next(ctx, tx, req)
	}
}

// NewUser is the user a rule provisions. It has no password unless PasswordHash is
// set.
type NewUser struct {
	Username     string
	PasswordHash *securehash.Hash
	Disabled     bool
}

// IdentityOutcome is what a Resolution does with an external identity that is not yet
// linked to any user. An account rule builds its Resolution with Reject, Link,
// Provision, Confirm or Standard; Resolution.Outcome reads it back.
type IdentityOutcome int

const (
	// RejectIdentity refuses the sign-in (Reject). It is the zero value, so a nil
	// Resolution never grants access. The rule's own writes are committed.
	RejectIdentity IdentityOutcome = iota
	// LinkIdentity links the identity to an existing user and signs in (Link).
	LinkIdentity
	// ProvisionUser creates the user, links the identity to it and signs in (Provision).
	ProvisionUser
	// RequireConfirmation holds the identity as pending until the person enters the
	// password of the existing user it names; the identity is then linked (Confirm).
	RequireConfirmation
	// ApplyStandardRule leaves the identity to the registration's standard account rule
	// (Standard).
	ApplyStandardRule
)

// Resolution is an account rule's answer for an unlinked external identity, built with
// Reject, Link, Provision, Confirm or Standard and refined with ResolutionOptions. A
// nil Resolution rejects.
type Resolution struct {
	outcome       IdentityOutcome
	userID        ccc.UUID
	newUser       *NewUser
	onProvisioned func(ctx context.Context, userID ccc.UUID) error
	tenant        string
	trusted       bool
	refusal       sessioninfo.LoginRefusalCode
}

// ResolutionOption refines a Link, Provision, Confirm or Standard resolution.
type ResolutionOption func(r *Resolution)

// Tenant stores tenant, the application's tenant key, on the identity link. A standard
// rule stores the identity's connection (the Entra tenant id, the application's name
// for the Google Workspace) unless Standard is given another.
func Tenant(tenant string) ResolutionOption {
	return func(r *Resolution) { r.tenant = tenant }
}

// Reject refuses the sign-in with code, or sessioninfo.RefusedIdentityRejected when
// code is empty. The rule's own writes, such as a record of the refused attempt, are
// committed.
func Reject(code sessioninfo.LoginRefusalCode) *Resolution {
	return &Resolution{outcome: RejectIdentity, refusal: code}
}

// Standard leaves the identity to the registration's standard account rule
// (StandardAccountRule), once the custom rule's own checks have passed: the usual case
// stays the library's, and the rule only refuses or decides what the standard rule
// cannot know. Tenant replaces the tenant key the standard rule would store. A method
// without a standard rule fails the sign-in.
func Standard(opts ...ResolutionOption) *Resolution {
	r := &Resolution{outcome: ApplyStandardRule}
	for _, opt := range opts {
		opt(r)
	}

	return r
}

// Link links the identity to the existing user userID and signs in. A user that has a
// password is refused (ErrLinkRequiresConfirmation) unless trusted is set, which is
// right only for an enterprise connection on a domain the tenant has verified; use
// Confirm for such a user otherwise. A user without a password (one an external
// sign-in provisioned) cannot confirm, so the rule's own evidence is the only
// check: an untrusted link of an identity from another connection than the ones such
// a user already signs in through is refused (ErrLinkCrossConnection); the same
// connection, or a user with no identity yet, links. Never choose userID by an email
// address or another claim the identity's provider does not verify, unless the
// connection itself is one the application trusts, and then say so with trusted.
func Link(userID ccc.UUID, trusted bool, opts ...ResolutionOption) *Resolution {
	r := &Resolution{outcome: LinkIdentity, userID: userID, trusted: trusted}
	for _, opt := range opts {
		opt(r)
	}

	return r
}

// Provision creates user, links the identity to it, runs onProvisioned and signs in.
// onProvisioned, nil for none, runs in the rule's transaction once the user is
// created, so the application can write its own rows for it: capture the transaction
// in the rule's closure. The rows commit with the user, so the sign-in policy and
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
// existing user userID. The identity is then linked. A user without a password cannot
// confirm (the confirmation answers 401), so Confirm is for users that sign in with a
// password; a password-less user is linked with Link or refused with Reject.
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
	cause   error
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

// denyBecause is Deny with the cause the refusal carries beside ErrSignInDenied, for
// errors.Is: the library's own rules name theirs (ErrNoTenant, ErrConnectionNotInTenant,
// ErrDirectoryOnly).
func denyBecause(code sessioninfo.LoginRefusalCode, cause error) *Decision {
	return &Decision{outcome: DenySignIn, refusal: code, cause: cause}
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

// Cause is the cause a Deny decision of one of the library's own rules carries beside
// ErrSignInDenied (ErrNoTenant, ErrConnectionNotInTenant, ErrDirectoryOnly), nil for
// a Deny the application built.
func (d *Decision) Cause() error {
	return d.cause
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
	// ErrIdentityRejected is the cause when the account rule returned RejectIdentity
	// (Reject). The code is the resolution's, or sessioninfo.RefusedIdentityRejected
	// when that is empty.
	ErrIdentityRejected = errors.New("signin: the account rule rejected the identity")
	// ErrLinkRequiresConfirmation is the cause when the account rule returned
	// LinkIdentity (Link) for a user that has a password, without trusted. The code is
	// sessioninfo.RefusedIdentityRejected. The rule should return Confirm instead.
	ErrLinkRequiresConfirmation = errors.New(
		"signin: an identity can't be linked to a user that has a password without confirmation (or a trusted link)")
	// ErrLinkCrossConnection is the cause when the account rule returned LinkIdentity
	// (Link) without trusted, or a standard rule matched a pre-created user, for a user
	// that has no password and already signs in through another connection. No
	// confirmation can be asked of such a user, so the rule's evidence is the only
	// check, and a custom rule must say so with trusted, or reject. The code is
	// sessioninfo.RefusedIdentityRejected.
	ErrLinkCrossConnection = errors.New(
		"signin: an identity from another connection can't be linked to a user without a password unless the link is trusted")
	// ErrGuestAccount is the cause when a standard account rule refused a guest of the
	// directory (Identity.Guest). The code is sessioninfo.RefusedGuestAccount.
	ErrGuestAccount = errors.New("signin: the identity is a guest of its directory, not a member")
	// ErrNoRoles is the cause when a standard account rule refused a token that asserts
	// no application role for a method that synchronizes roles, before any row was
	// written. The code is sessioninfo.RefusedNoRoles.
	ErrNoRoles = errors.New("signin: the token asserts no application role")
	// ErrNoSignInName is the cause when a standard account rule found no sign-in name
	// on the identity to use as the username. The code is sessioninfo.RefusedNoEmail.
	ErrNoSignInName = errors.New("signin: the identity carries no sign-in name to use as the username")
	// ErrNotInvited is the cause when the invited-users-only rule matched no
	// pre-created user. The code is sessioninfo.RefusedNotInvited.
	ErrNotInvited = errors.New("signin: no user was created for the identity's sign-in name")
	// ErrSignInDenied is the cause when the sign-in policy returned DenySignIn or no
	// decision. The code is the decision's, or sessioninfo.RefusedByPolicy. A refusal
	// of the tenant policy carries its own cause beside it.
	ErrSignInDenied = errors.New("signin: the sign-in policy denied the sign-in")
	// ErrNoTenant is the cause when the tenant policy refused a person who is a member
	// of no tenant. The code is sessioninfo.RefusedNoTenant.
	ErrNoTenant = errors.New("signin: the person is a member of no tenant")
	// ErrConnectionNotInTenant is the cause when the tenant policy refused a sign-in
	// through a directory that no tenant of the person declares. The code is
	// sessioninfo.RefusedConnectionNotInTenant.
	ErrConnectionNotInTenant = errors.New("signin: no tenant of the person declares the directory the sign-in came through")
	// ErrDirectoryOnly is the cause when the tenant policy refused a sign-in that is not
	// through a directory because every tenant of the person admits its people through
	// their directories only. The code is sessioninfo.RefusedDirectoryOnly.
	ErrDirectoryOnly = errors.New("signin: every tenant of the person admits its people through their directories only")
	// ErrUserDisabled is the cause when the sign-in resolved to a disabled user.
	// The code is sessioninfo.RefusedUserDisabled.
	ErrUserDisabled = errors.New("signin: the user is disabled")
)

// PendingSignInError is returned by a sign-in that resolved to a user but must wait.
// Its Reason is sessioninfo.PendingConfirmation when the account rule returned
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
	// Tenant is the rule's tenant key for the link to be made.
	Tenant string
	// Factors are the methods the sign-in policy accepts for the MFA step, for
	// PendingMFA; none means any.
	Factors []sessioninfo.AuthMethod
}

// Error describes the pending sign-in.
func (e *PendingSignInError) Error() string {
	return fmt.Sprintf("signin: sign-in pending %s for user %v", e.Reason, e.UserID)
}
