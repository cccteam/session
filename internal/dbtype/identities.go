package dbtype

import (
	"context"
	"fmt"
	"time"

	"github.com/cccteam/ccc"
	"github.com/cccteam/httpio"
	"github.com/cccteam/session/sessioninfo"
	"github.com/go-playground/errors/v5"
)

// SessionIdentity is an identity link row: an external identity linked to an account.
// Its fields match sessionstorage.SessionIdentity, which converts from it.
type SessionIdentity struct {
	ID          ccc.UUID               `spanner:"Id"          db:"Id"`
	UserID      ccc.UUID               `spanner:"UserId"      db:"UserId"`
	Method      sessioninfo.AuthMethod `spanner:"Method"      db:"Method"`
	Connection  string                 `spanner:"Connection"  db:"Connection"`
	Subject     string                 `spanner:"Subject"     db:"Subject"`
	Tenant      *string                `spanner:"Tenant"      db:"Tenant"`
	EmailAtLink *string                `spanner:"EmailAtLink" db:"EmailAtLink"`
	CreatedAt   time.Time              `spanner:"CreatedAt"   db:"CreatedAt"`
	LastUsedAt  time.Time              `spanner:"LastUsedAt"  db:"LastUsedAt"`
}

// IdentityOutcome mirrors sessionstorage.IdentityOutcome, value for value.
type IdentityOutcome int

// The account resolver's outcomes; RejectIdentity is the zero value.
const (
	RejectIdentity IdentityOutcome = iota
	LinkIdentity
	ProvisionAccount
	RequireConfirmation
)

// Resolution mirrors sessionstorage.Resolution for the drivers.
type Resolution struct {
	Outcome           IdentityOutcome
	UserID            ccc.UUID
	NewUser           *InsertSessionUser
	OnProvisioned     func(ctx context.Context, userID ccc.UUID) error
	Tenant            string
	TrustedForLinking bool
	Refusal           sessioninfo.LoginRefusalCode
}

// PolicyOutcome mirrors sessionstorage.PolicyOutcome, value for value.
type PolicyOutcome int

// The sign-in policy's outcomes; DenySignIn is the zero value.
const (
	DenySignIn PolicyOutcome = iota
	AllowSignIn
	RequireMFA
)

// SignInDecision mirrors sessionstorage.SignInDecision for the drivers.
type SignInDecision struct {
	Outcome PolicyOutcome
	Refusal sessioninfo.LoginRefusalCode
}

// IsExternal reports whether identity is an external identity, resolved through the
// identities table. A password identity names its account directly (req.UserID), and an
// impersonation identity is the impersonation flow's own.
func IsExternal(identity *sessioninfo.Identity) bool {
	return identity != nil && identity.Method != sessioninfo.MethodPassword && identity.Method != sessioninfo.MethodImpersonation
}

// PolicyApplies reports whether the sign-in policy decides a session created for
// reason. It decides a sign-in (ReasonLogin) and a sign-in completed by confirming a new
// link (ReasonIdentityLinked); a session regenerated, completed after a step-up, started
// by the application itself, or impersonated has already been decided.
func PolicyApplies(reason sessioninfo.NewSessionReason) bool {
	return reason == sessioninfo.ReasonLogin || reason == sessioninfo.ReasonIdentityLinked
}

// The causes a refused sign-in carries; see sessionstorage for their documentation.
var (
	ErrIdentitiesNotConfigured  = errors.New("sessionstorage: identities are not configured: attach WithSpannerIdentities or WithPostgresIdentities")
	ErrIdentityRejected         = errors.New("sessionstorage: the account resolver rejected the identity")
	ErrLinkRequiresConfirmation = errors.New("sessionstorage: an identity can't be linked to an account that has a password without confirmation (or TrustedForLinking)")
	ErrSignInDenied             = errors.New("sessionstorage: the sign-in policy denied the sign-in")
	ErrAccountDisabled          = errors.New("sessionstorage: the account is disabled")
	ErrLastSignInMethod         = errors.New("sessionstorage: the identity is the account's last means of sign-in")
)

// Refusal renders a refused sign-in: code (fallback when code is empty) for the login
// page, cause for errors.Is, and an Unauthorized client message.
func Refusal(code, fallback sessioninfo.LoginRefusalCode, cause error, message string) error {
	if code == "" {
		code = fallback
	}

	return sessioninfo.NewLoginRefusal(code, httpio.NewUnauthorizedMessageWithError(cause, message))
}

// PendingSignInError reports a sign-in that resolved to an account but must wait before
// it becomes a session: the account resolver asked for a password confirmation, or the
// sign-in policy asked for MFA. Nothing was written: no account, no link, no session.
type PendingSignInError struct {
	// Reason is why the sign-in waits.
	Reason sessioninfo.PendingReason
	// UserID is the account the sign-in resolved to. It is null for an MFA wait on a
	// sign-in that would provision a new account.
	UserID ccc.NullUUID
	// Username is that account's username, when there is one.
	Username string
	// Tenant is the resolver's tenant key for the link to be made.
	Tenant string
}

// Error describes the pending sign-in.
func (e *PendingSignInError) Error() string {
	return fmt.Sprintf("sessionstorage: sign-in pending %s for account %v", e.Reason, e.UserID)
}

// Account is the part of an account row the sign-in flow decides on.
type Account struct {
	Username    string
	HasPassword bool
	Disabled    bool
}

// DecideSignIn refuses a disabled account, sets req.Username to the account's, and runs
// the sign-in policy when there is one (policy non-nil) and it applies to req.Reason. A
// pending outcome is the first result; a refusal is the error. provisioned says the
// account was created by this sign-in, so an MFA wait names no account: nothing is
// written while a sign-in waits.
func DecideSignIn(
	ctx context.Context, req *sessioninfo.NewSessionRequest, acct *Account, provisioned bool, tenant string,
	policy func(ctx context.Context) (*SignInDecision, error),
) (*PendingSignInError, error) {
	if acct.Disabled {
		return nil, Refusal("", sessioninfo.RefusedAccountDisabled, ErrAccountDisabled, "Account disabled")
	}
	req.Username = acct.Username

	if policy == nil || !PolicyApplies(req.Reason) {
		return nil, nil
	}

	decision, err := policy(ctx)
	if err != nil {
		return nil, errors.Wrap(err, "sign-in policy")
	}
	if decision == nil {
		decision = &SignInDecision{}
	}

	switch decision.Outcome {
	case AllowSignIn:
		return nil, nil
	case RequireMFA:
		pending := &PendingSignInError{Reason: sessioninfo.PendingMFA, Tenant: tenant}
		if !provisioned {
			pending.UserID, pending.Username = ccc.NullUUIDFromUUID(req.UserID), acct.Username
		}

		return pending, nil
	default:
		return nil, Refusal(decision.Refusal, sessioninfo.RefusedByPolicy, ErrSignInDenied, "sign-in denied")
	}
}
