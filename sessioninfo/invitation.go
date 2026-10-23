package sessioninfo

import (
	"time"

	"github.com/cccteam/ccc"
)

// Invitation is a live invitation as a sign-in carries it: the invitation the browser
// opened before the person signed in or signed up, read from its cookie. The sign-in
// accepts it once the user is known, in a transaction of its own after the user is
// resolved and before the sign-in policy decides: the invitation is consumed, the
// user's address is set from it when the user holds no verified address, and the
// application's acceptance hook grants the roles it names, so the tenant policy sees
// the membership. Accepted says whether that happened; it is false when the invitation
// had expired or been used meanwhile, and the sign-in then goes on without it.
type Invitation struct {
	// ID is the invitation's row.
	ID ccc.UUID
	// Email is the address the invitation was mailed to.
	Email string
	// Tenant is the tenant the invitation seats the person in, "" for the
	// application's global surface.
	Tenant string
	// RoleNames are the roles the acceptance grants, as the application names them.
	RoleNames []string
	// InvitedBy is the user who sent it, null when unknown.
	InvitedBy ccc.NullUUID
	// ExpiresAt is when the invitation stops being accepted.
	// CreatedAt is when it was sent, ExpiresAt when it stops standing.
	CreatedAt time.Time
	ExpiresAt time.Time
	// Accepted is set by the sign-in: whether this sign-in accepted the invitation.
	Accepted bool
}
