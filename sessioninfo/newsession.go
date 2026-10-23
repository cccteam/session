package sessioninfo

import (
	"encoding/json"

	"github.com/cccteam/ccc"
)

// NewSessionReason identifies why a new session is being created, allowing a
// custom session data resolver to vary its behavior by trigger.
type NewSessionReason string

const (
	// ReasonLogin indicates the session is being created by an interactive credential login.
	ReasonLogin NewSessionReason = "Login"
	// ReasonExternalAuth indicates the session is being created for a user the
	// application authenticated itself (StartAuthenticatedSession); the sign-in policy
	// decides it like a login.
	ReasonExternalAuth NewSessionReason = "ExternalAuth"
	// ReasonRegeneration indicates an existing authenticated session is being replaced
	// with a new session ID (e.g. after a password change). Custom session data is
	// resolved fresh for the new session; it does not carry over.
	ReasonRegeneration NewSessionReason = "Regeneration"
	// ReasonPreauth indicates a trust-the-caller stepping-stone session with no user
	// record (e.g. MFA-pending enrollment flows).
	ReasonPreauth NewSessionReason = "Preauth"
	// ReasonImpersonation indicates an impersonated session being established
	// (StartImpersonatedSession): Username is the session's effective identity — the
	// impersonated user, or the actor for a role principal — and UserID is the
	// impersonated user's record ID, or the zero UUID for a role principal.
	ReasonImpersonation NewSessionReason = "Impersonation"
)

// NewSessionRequest carries the inputs to a new-session creation. It is a struct so
// future fields (e.g. prior custom session data) can be added without breaking resolvers.
type NewSessionRequest struct {
	// Reason identifies the trigger creating this session.
	Reason NewSessionReason
	// Username is the username the session is created for.
	Username string
	// UserID is the user record's ID. It is the zero UUID for session types that do
	// not track user records (e.g. preauth).
	UserID ccc.UUID
	// CustomData is caller-supplied custom session data for this creation: nil, or a
	// pointer to the struct type the storage's custom session data configuration was
	// built for. When non-nil it is written atomically with the session insert and the
	// configured resolver is NOT invoked for this creation (per-call data wins). It
	// requires a custom session data configuration on the storage.
	CustomData any
	// Claims holds the raw verified ID-token claims when the session is created by an
	// OIDC login; it is nil for all other session types. Resolvers unmarshal the fields
	// they need — the library does not curate a claims struct.
	Claims json.RawMessage
	// Tid and Oid are the verified tenant and directory-object GUID claims when the
	// session is created by an Azure OIDC login; they are empty for all other session
	// types. When the OIDC user anchor is enabled they key the OIDCUsers upsert, and
	// UserID is populated with the anchor record's ID before any resolver or hook runs.
	Tid string
	Oid string
	// Identity is the verified identity establishing an Auth session. It is nil for the
	// legacy session types.
	Identity *Identity
	// ProviderSessionID is the identity provider's session id the sign-in carried (an
	// OpenID Connect sid claim), which a provider-initiated logout names; "" when the
	// method has none. ProviderSessionIssuer is the registration's issuer it belongs
	// to, set with it or not at all. The session row records both.
	ProviderSessionID     string
	ProviderSessionIssuer string
	// RoleNames are the role names the sign-in method asserted for the person, which
	// the method reconciles once the session exists. They are nil when the method
	// synchronizes no roles, and never nil when it does: "no roles asserted" is an
	// empty list, which a standard account rule refuses (no_roles) before it writes a
	// row.
	RoleNames []string
	// AuthEvents are the auth events the new session records, in order, with the
	// session row. An impersonated session records its impersonation event first. When
	// AuthEvents is empty, a session that is not impersonated records one event for
	// Identity's method. An event with a zero At takes the session's creation time.
	// Events are written only when the storage has an auth events table.
	AuthEvents []AuthEvent
	// User is the user an Auth sign-in resolved to and how. The storage sets it
	// once the user is known, before the sign-in policy and the custom session data
	// resolver run, and leaves it set after the insert returns. It is nil while the
	// account rules run and for the legacy session types.
	User *SignInUser
	// Invitation is the live invitation the browser carries into this sign-in, nil
	// for none. The sign-in accepts it once the user is known and reports the outcome
	// in Invitation.Accepted; the application's acceptance hook runs in that
	// transaction. The sign-in policy runs afterwards and may read it.
	Invitation *Invitation
}
