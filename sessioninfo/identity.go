package sessioninfo

import (
	"encoding/json"
	"time"

	"github.com/cccteam/ccc"
)

// AuthMethod names a way a person proved who they are. Sign-in methods use the
// constants below; applications may record their own step-up methods (for example
// an emailed one-time code) with any other non-empty value.
type AuthMethod string

const (
	// MethodPassword is a username and password checked against SessionUsers.
	MethodPassword AuthMethod = "password"
	// MethodAzure is Microsoft Entra ID (Azure) OIDC.
	MethodAzure AuthMethod = "azure"
	// MethodGoogle is Google Workspace OIDC.
	MethodGoogle AuthMethod = "google"
	// MethodWorkOS is WorkOS SSO (SAML or OIDC brokered by WorkOS).
	MethodWorkOS AuthMethod = "workos"
	// MethodImpersonation records that a session was established by impersonation.
	// Its AuthEvent.Connection carries the actor.
	MethodImpersonation AuthMethod = "impersonation"
	// MethodLinkConfirmation records a password confirmation that linked a new
	// external identity to an existing account.
	MethodLinkConfirmation AuthMethod = "link-confirmation"
)

// Identity is a verified identity produced by a sign-in method, before (or as) it
// becomes a session. External identities are linked to an account through the
// identities table, keyed by (Method, Connection, Subject); Email is an attribute and
// is never used as a key.
type Identity struct {
	// Method is the sign-in method that verified this identity.
	Method AuthMethod
	// Connection is the upstream configuration the Subject is scoped to: the WorkOS
	// connection ID for MethodWorkOS, the tenant ID (tid) for MethodAzure, and empty
	// for MethodGoogle and MethodPassword.
	Connection string
	// Subject is the upstream subject: the WorkOS profile idp_id, the Azure oid, the
	// Google sub, or the account ID (as a string) for MethodPassword.
	Subject string
	// Email is the email address asserted by the method, if any.
	Email string
	// EmailVerified reports whether the method asserts the email is verified.
	EmailVerified bool
	// Claims is the method's full verified payload (ID-token claims or WorkOS
	// profile), passed through to resolvers and custom data hooks.
	Claims json.RawMessage
	// IdPAMR carries upstream authentication-method evidence (OIDC amr values or SAML
	// AuthnContextClassRef) when the method provides it. The library never
	// interprets it; policy hooks decide what it is worth.
	IdPAMR []string //nolint:revive // var-naming: IdP is the identity provider, not an ID; the name is the agreed contract
}

// AuthEvent records one step that authenticated a session: the initial sign-in and
// any later step-up (MFA) or link confirmation. A session's events are stored in the
// auth events table and read with the session.
type AuthEvent struct {
	Method     AuthMethod
	Connection string
	IdPAMR     []string //nolint:revive // var-naming: IdP is the identity provider, not an ID; the name is the agreed contract
	At         time.Time
}

// PendingReason says why a verified identity is waiting instead of becoming a session.
type PendingReason string

const (
	// PendingConfirmation means the identity resolves to an existing account that has a
	// password; the user must confirm with that password before the identity is linked.
	PendingConfirmation PendingReason = "confirmation"
	// PendingMFA means the sign-in policy requires the application's MFA step before
	// the session is established.
	PendingMFA PendingReason = "mfa"
)

// PendingIdentity is a verified identity held server-side for a short time while it
// waits for confirmation or MFA. It lives in a preauth stepping-stone session.
type PendingIdentity struct {
	Identity Identity
	Reason   PendingReason
	// UserID and Username name the account the identity waits on: the account to
	// confirm against, or the account to complete MFA for, including one the sign-in
	// has just provisioned.
	UserID    ccc.NullUUID
	Username  string
	ExpiresAt time.Time
	// ReturnURL is the path in the application the sign-in returns to once it
	// completes; empty for the root.
	ReturnURL string
}

// AccountSource says how an Auth sign-in found its account.
type AccountSource string

const (
	// AccountNamed means the sign-in named its account: a password sign-in.
	AccountNamed AccountSource = "named"
	// AccountExistingLink means the identity was already linked to the account.
	AccountExistingLink AccountSource = "existing-link"
	// AccountNewLink means the account resolver linked the identity to an existing
	// account in this sign-in (LinkIdentity).
	AccountNewLink AccountSource = "new-link"
	// AccountProvisioned means the account resolver created the account in this sign-in
	// (ProvisionAccount) and linked the identity to it.
	AccountProvisioned AccountSource = "provisioned"
)

// SignInAccount is the account an Auth sign-in resolved to, as NewSessionRequest.Account
// carries it to the sign-in policy and the custom session data resolver.
type SignInAccount struct {
	// ID is the account (SessionUsers.Id).
	ID ccc.UUID
	// Username is the account's username.
	Username string
	// HasPassword reports whether the account has a password.
	HasPassword bool
	// Source says how the sign-in found the account.
	Source AccountSource
	// Tenant is the application's tenant key of the identity's link: the stored link's
	// for an existing link, Resolution.Tenant for a link made in this sign-in, and empty
	// for a password sign-in.
	Tenant string
}

// Provisioned reports whether the sign-in created the account.
func (a *SignInAccount) Provisioned() bool {
	return a != nil && a.Source == AccountProvisioned
}

// Linked reports whether the sign-in linked its identity to the account: a new link to
// an existing account, or the link of an account it provisioned.
func (a *SignInAccount) Linked() bool {
	return a != nil && (a.Source == AccountNewLink || a.Source == AccountProvisioned)
}

const (
	// ReasonIdentityLinked indicates a session created when a new external identity
	// was linked to an existing account after confirmation.
	ReasonIdentityLinked NewSessionReason = "IdentityLinked"
	// ReasonStepUp indicates a session regenerated after a step-up (MFA) completed.
	ReasonStepUp NewSessionReason = "StepUp"
)

const (
	// RefusedIdentityRejected is the code for an external identity the application's
	// account resolver rejected (for example, no invite or roster entry).
	RefusedIdentityRejected LoginRefusalCode = "identity_rejected"
	// RefusedByPolicy is the code for a sign-in the application's policy denied (for
	// example, password sign-in for a tenant that requires SSO).
	RefusedByPolicy LoginRefusalCode = "policy_denied"
	// RefusedAccountDisabled is the code for a sign-in to a disabled account.
	RefusedAccountDisabled LoginRefusalCode = "account_disabled"
	// RefusedPendingExpired is the code for a confirmation or MFA step that arrived
	// after its pending identity expired.
	RefusedPendingExpired LoginRefusalCode = "pending_expired"
	// RefusedNoEmail is the code for an external identity with no email address where
	// the application requires one.
	RefusedNoEmail LoginRefusalCode = "no_email"
)
