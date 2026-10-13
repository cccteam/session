package sessioninfo

import (
	"encoding/json"
	"time"

	"github.com/cccteam/ccc"
)

// AuthMethod names a way a person proved who they are. Sign-in methods use the
// constants below. An application may record its own step-up method (for example an
// emailed one-time code) under any other non-empty value.
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
	// Its AuthEvent.Connection is the actor.
	MethodImpersonation AuthMethod = "impersonation"
	// MethodLinkConfirmation records a password confirmation that linked a new
	// external identity to an existing user.
	MethodLinkConfirmation AuthMethod = "link-confirmation"
)

// Identity is a verified identity produced by a sign-in method. An external identity
// is linked to a user by (Method, Connection, Subject). Email is an attribute and
// is never used as a key.
type Identity struct {
	// Method is the sign-in method that verified this identity.
	Method AuthMethod
	// Connection scopes the Subject. It is the WorkOS connection ID for MethodWorkOS
	// and the tenant ID (tid) for MethodAzure. It is empty for MethodGoogle and
	// MethodPassword.
	Connection string
	// Subject is the upstream subject. It is the WorkOS profile idp_id, the Azure oid,
	// the Google sub, or the user ID (as a string) for MethodPassword.
	Subject string
	// Email is the email address asserted by the method, if any.
	Email string
	// EmailVerified reports whether the method asserts the email is verified.
	EmailVerified bool
	// Claims is the method's verified payload (ID-token claims or WorkOS profile). It
	// is passed to resolvers and custom data hooks.
	Claims json.RawMessage
	// IDPAMR is the identity provider's authentication-method evidence (OIDC amr
	// values or SAML AuthnContextClassRef), when the method provides it. The library
	// does not interpret it.
	IDPAMR []string
}

// AuthEvent records one step that authenticated a session, such as the sign-in, a
// link confirmation or an MFA step. Events are stored in the auth events table and
// read with the session.
type AuthEvent struct {
	Method     AuthMethod
	Connection string
	IDPAMR     []string
	At         time.Time
}

// PendingReason says why a verified identity is waiting instead of becoming a session.
type PendingReason string

const (
	// PendingConfirmation means the identity resolves to an existing user that has a
	// password. The user must enter that password before the identity is linked.
	PendingConfirmation PendingReason = "confirmation"
	// PendingMFA means the sign-in policy requires the application's MFA step before
	// the session is established.
	PendingMFA PendingReason = "mfa"
)

// PendingIdentity is a verified identity that waits for a password confirmation or
// MFA before it becomes a session. See "What a pending identity is" in the README.
type PendingIdentity struct {
	Identity Identity
	Reason   PendingReason
	// UserID and Username name the user the identity waits on. This includes an
	// user the sign-in has just provisioned.
	UserID    ccc.NullUUID
	Username  string
	ExpiresAt time.Time
	// ReturnURL is the path the sign-in returns to once it completes. It is empty for
	// the root.
	ReturnURL string
	// Factors are the methods the sign-in policy accepts for the MFA step, for
	// PendingMFA; none means any.
	Factors []AuthMethod
}

// UserSource says how an Auth sign-in found its user.
type UserSource string

const (
	// UserNamed means the sign-in named its user (a password sign-in).
	UserNamed UserSource = "named"
	// UserExistingLink means the identity was already linked to the user.
	UserExistingLink UserSource = "existing-link"
	// UserNewLink means the user resolver linked the identity to an existing
	// user in this sign-in (LinkIdentity).
	UserNewLink UserSource = "new-link"
	// UserProvisioned means the user resolver created the user in this sign-in
	// (ProvisionUser) and linked the identity to it.
	UserProvisioned UserSource = "provisioned"
)

// SignInUser is the user an Auth sign-in resolved to. NewSessionRequest.User
// carries it to the sign-in policy and the custom session data resolver.
type SignInUser struct {
	// ID is the user (SessionUsers.Id).
	ID ccc.UUID
	// Username is the user's username.
	Username string
	// HasPassword reports whether the user has a password.
	HasPassword bool
	// Source says how the sign-in found the user.
	Source UserSource
	// Tenant is the application's tenant key on the identity's link. It is the stored
	// link's tenant, or the resolution's signin.Tenant for a link made in this sign-in. It is empty
	// for a password sign-in.
	Tenant string
}

// Provisioned reports whether the sign-in created the user.
func (a *SignInUser) Provisioned() bool {
	return a != nil && a.Source == UserProvisioned
}

// Linked reports whether the sign-in linked its identity to the user, either to an
// existing user or to one it provisioned.
func (a *SignInUser) Linked() bool {
	return a != nil && (a.Source == UserNewLink || a.Source == UserProvisioned)
}

const (
	// ReasonIdentityLinked indicates a session created when a new external identity
	// was linked to an existing user after a password confirmation.
	ReasonIdentityLinked NewSessionReason = "IdentityLinked"
	// ReasonStepUp indicates a session regenerated after a step-up (MFA) completed.
	ReasonStepUp NewSessionReason = "StepUp"
)

const (
	// RefusedIdentityRejected is the code for an external identity the application's
	// user resolver rejected (for example, no invite or roster entry).
	RefusedIdentityRejected LoginRefusalCode = "identity_rejected"
	// RefusedByPolicy is the code for a sign-in the application's policy denied (for
	// example, password sign-in for a tenant that requires SSO).
	RefusedByPolicy LoginRefusalCode = "policy_denied"
	// RefusedUserDisabled is the code for a sign-in to a disabled user.
	RefusedUserDisabled LoginRefusalCode = "user_disabled"
	// RefusedPendingExpired is the code for a confirmation or MFA step that arrived
	// after its pending identity expired.
	RefusedPendingExpired LoginRefusalCode = "pending_expired"
	// RefusedNoEmail is the code for an external identity with no email address where
	// the application requires one.
	RefusedNoEmail LoginRefusalCode = "no_email"
)
