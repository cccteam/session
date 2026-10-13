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

// SessionIdentity is an identity link row. Its fields match
// sessionstorage.SessionIdentity, which converts from it.
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

// The user resolver's outcomes; RejectIdentity is the zero value.
const (
	RejectIdentity IdentityOutcome = iota
	LinkIdentity
	ProvisionUser
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

// IsExternal reports whether identity is resolved through the identities table. A
// password identity names its user directly (req.UserID), and an impersonation
// identity belongs to the impersonation flow.
func IsExternal(identity *sessioninfo.Identity) bool {
	return identity != nil && identity.Method != sessioninfo.MethodPassword && identity.Method != sessioninfo.MethodImpersonation
}

// PolicyApplies reports whether the sign-in policy decides a session created for
// reason. It decides ReasonLogin and ReasonIdentityLinked. Every other session was
// already decided or is started by the application itself.
func PolicyApplies(reason sessioninfo.NewSessionReason) bool {
	return reason == sessioninfo.ReasonLogin || reason == sessioninfo.ReasonIdentityLinked
}

// The causes a refused sign-in carries; see sessionstorage for their documentation.
var (
	ErrIdentitiesNotConfigured  = errors.New("sessionstorage: identities are not configured: attach WithSpannerIdentities or WithPostgresIdentities")
	ErrIdentityRejected         = errors.New("sessionstorage: the user resolver rejected the identity")
	ErrLinkRequiresConfirmation = errors.New("sessionstorage: an identity can't be linked to a user that has a password without confirmation (or TrustedForLinking)")
	ErrSignInDenied             = errors.New("sessionstorage: the sign-in policy denied the sign-in")
	ErrUserDisabled             = errors.New("sessionstorage: the user is disabled")
	ErrLastSignInMethod         = errors.New("sessionstorage: the identity is the user's last means of sign-in")
)

// Refusal returns a refused sign-in's error. It carries code (or fallback when code is
// empty) for the login page, cause for errors.Is, and an Unauthorized client message.
func Refusal(code, fallback sessioninfo.LoginRefusalCode, cause error, message string) error {
	if code == "" {
		code = fallback
	}

	return sessioninfo.NewLoginRefusal(code, httpio.NewUnauthorizedMessageWithError(cause, message))
}

// PendingSignInError reports a sign-in that resolved to a user but must wait for a
// password confirmation or MFA. It is documented on sessionstorage.PendingSignInError.
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
	return fmt.Sprintf("sessionstorage: sign-in pending %s for user %v", e.Reason, e.UserID)
}

// User is the part of a user row the sign-in flow decides on.
type User struct {
	Username    string
	HasPassword bool
	Disabled    bool
}

// DecideSignIn refuses a disabled user, sets req.Username to the user's, and runs
// the policy when it is non-nil and applies to req.Reason. stop is a sign-in that does
// not go ahead: a refusal or a *PendingSignInError for MFA. The transaction commits
// on stop. err is the policy's error, which rolls the transaction back.
func DecideSignIn(
	ctx context.Context, req *sessioninfo.NewSessionRequest, acct *User, policy func(ctx context.Context) (*SignInDecision, error),
) (stop, err error) {
	if acct.Disabled {
		return Refusal("", sessioninfo.RefusedUserDisabled, ErrUserDisabled, "User disabled"), nil
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
		pending := &PendingSignInError{Reason: sessioninfo.PendingMFA, UserID: ccc.NullUUIDFromUUID(req.UserID), Username: acct.Username}
		if req.User != nil {
			pending.Tenant = req.User.Tenant
		}

		return pending, nil
	default:
		return Refusal(decision.Refusal, sessioninfo.RefusedByPolicy, ErrSignInDenied, "sign-in denied"), nil
	}
}

// SignInUser returns req's user as the sign-in policy and the custom session data
// resolver receive it.
func SignInUser(req *sessioninfo.NewSessionRequest, acct *User, source sessioninfo.UserSource, tenant string) *sessioninfo.SignInUser {
	return &sessioninfo.SignInUser{ID: req.UserID, Username: acct.Username, HasPassword: acct.HasPassword, Source: source, Tenant: tenant}
}
