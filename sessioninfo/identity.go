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
	// MethodApplication is the identity of a session the application starts for a
	// user it authenticated itself (AuthAPI.StartAuthenticatedSession): the user, named
	// by ID, with no identity to resolve; the session's auth events say how the person
	// authenticated. A pending identity held from such a start carries it.
	MethodApplication AuthMethod = "application"
)

// ThroughDirectory reports whether the method signs a person in through a directory:
// Microsoft Entra ID, Google Workspace and WorkOS, whose identities carry the directory
// as their connection (Identity.Connection, and AuthEvent.Connection on the session's
// first auth event). A password, a session the application starts for a user it
// authenticated itself, an impersonation, a link confirmation and a step the
// application records under its own name are not. A tenant's declaration admits a
// sign-in through a directory by naming the directory (signin.Directory); see
// signin.TenantPolicy.
func (m AuthMethod) ThroughDirectory() bool {
	switch m {
	case MethodAzure, MethodGoogle, MethodWorkOS:
		return true
	default:
		return false
	}
}

// Identity is a verified identity produced by a sign-in method. An external identity
// is linked to a user by (Method, Connection, Subject). Email is an attribute and
// is never used as a key.
type Identity struct {
	// Method is the sign-in method that verified this identity.
	Method AuthMethod
	// Connection scopes the Subject. It is the WorkOS connection ID for MethodWorkOS,
	// the tenant ID (tid) for MethodAzure, and the registration's configured
	// Connection, the application's own name for the Workspace organization, for
	// MethodGoogle. It is empty for MethodPassword.
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
	// SignInName is the name the person signs in with at the directory the identity
	// came from: the user principal name on Entra, the verified email on Google; ""
	// when the method has none. The standard account rules (signin.StandardAccountRule)
	// use it as the username of the account they provision or match. It is an
	// attribute, never a key.
	SignInName string
	// Organization is the organization the identity came from as the registration
	// names it: the tenant's name when the application gave one and its id otherwise
	// on Entra, the connection the Workspaces slot selected on Google; "" when the
	// method has none. The standard account rules store it as the tenant key of the
	// link they make, unless a custom rule names another. It is an attribute, never a
	// key: the key stays Connection.
	Organization string
	// Guest reports that the account is a guest of its directory, not a member: an
	// Entra B2B guest, whose preferred username is an address the directory did not
	// verify. The standard account rules refuse a guest; a custom rule decides for
	// itself.
	Guest bool
}

// AuthEvent records one step that authenticated a session, such as the sign-in, a
// link confirmation or an MFA step. Events are stored in the auth events table and
// read with the session.
type AuthEvent struct {
	Method     AuthMethod
	Connection string
	IDPAMR     []string
	// At is when the event happened. On an event given to the library, zero means the
	// time the database records it, which is the one to use unless the event happened
	// earlier; a time that is set is stored as given and must not be later than the
	// database's clock. On an event read back it is as stored.
	At time.Time
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
	// the application requires one, and for one with no sign-in name where a standard
	// account rule needs it as the username.
	RefusedNoEmail LoginRefusalCode = "no_email"
	// RefusedNotInvited is the code for an identity that is not linked yet and matches
	// no pre-created user, under the invited-users-only account rule.
	RefusedNotInvited LoginRefusalCode = "not_invited"
	// RefusedInvitationExpired is the code for a sign-in that an invitation alone
	// admitted, under the invited-users-only account rule, whose invitation had expired
	// or been used by the time the sign-in accepted it.
	RefusedInvitationExpired LoginRefusalCode = "invitation_expired"
	// RefusedGuestAccount is the code for an identity that is a guest of its directory
	// (Identity.Guest), which the standard account rules refuse.
	RefusedGuestAccount LoginRefusalCode = "guest_account"
	// RefusedUnlistedTenant is the code for an Entra token from a tenant the
	// registration's Tenants slot does not admit.
	RefusedUnlistedTenant LoginRefusalCode = "unlisted_tenant"
	// RefusedPersonalAccount is the code for an Entra token of a Microsoft personal
	// account under a registration that admits work or school accounts only.
	RefusedPersonalAccount LoginRefusalCode = "personal_account"
	// RefusedNoTenant is the code for a person who is a member of no tenant, under the
	// tenant policy (signin.TenantPolicy), which admits such a person only when it was
	// built with signin.AdmitWithoutTenant.
	RefusedNoTenant LoginRefusalCode = "no_tenant"
	// RefusedConnectionNotInTenant is the code for a sign-in through a directory that
	// no tenant of the person declares, under the tenant policy.
	RefusedConnectionNotInTenant LoginRefusalCode = "connection_not_in_tenant"
	// RefusedDirectoryOnly is the code for a sign-in that is not through a directory (a
	// password, a session the application starts itself) by a person whose every
	// tenant admits its people through their directories only, under the tenant
	// policy.
	RefusedDirectoryOnly LoginRefusalCode = "directory_only"
)
