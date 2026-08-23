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
	// ReasonExternalAuth indicates the session is being created for a user that was
	// already authenticated by an external system (e.g. StartAuthenticatedSession).
	ReasonExternalAuth NewSessionReason = "ExternalAuth"
	// ReasonRegeneration indicates an existing authenticated session is being replaced
	// with a new session ID (e.g. after a password change). Custom session data is
	// resolved fresh for the new session; it does not carry over.
	ReasonRegeneration NewSessionReason = "Regeneration"
	// ReasonPreauth indicates a trust-the-caller stepping-stone session with no user
	// record (e.g. MFA-pending enrollment flows).
	ReasonPreauth NewSessionReason = "Preauth"
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
	// session is created by an OIDC login; they are empty for all other session types.
	// When the OIDC user anchor is enabled they key the OIDCUsers upsert, and UserID is
	// populated with the anchor record's ID before any resolver or hook runs.
	Tid string
	Oid string
}
