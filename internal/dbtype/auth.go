package dbtype

import (
	"github.com/cccteam/ccc"
	"github.com/cccteam/session/sessioninfo"
)

// SessionUserColumns holds the user columns of a new session row. UserID is null
// for a preauth session and a role-principal impersonation. Authenticated says whether
// the row's AuthenticatedAt takes the database's time at commit; it is false for a
// preauth session, which authenticates nothing, and the column stays null.
// ProviderSessionID is null unless the sign-in carried the provider's session id.
type SessionUserColumns struct {
	UserID            ccc.NullUUID
	Authenticated     bool
	ProviderSessionID *string
}

// NewSessionUserColumns returns the user columns of a new session for req.
func NewSessionUserColumns(req *sessioninfo.NewSessionRequest) SessionUserColumns {
	var user SessionUserColumns
	if !req.UserID.IsNil() {
		user.UserID = ccc.NullUUIDFromUUID(req.UserID)
	}
	user.Authenticated = req.Reason != sessioninfo.ReasonPreauth
	user.ProviderSessionID = OptionalString(req.ProviderSessionID)

	return user
}

// InitialAuthEvents returns the auth events a new session records, oldest first. An
// impersonated session records its impersonation first, with the actor as the
// connection. Then come req.AuthEvents or, when there are none and the session is not
// impersonated, the method that verified req.Identity. The events added here have a
// zero At, which the driver writes as the database's time at commit; an event of
// req.AuthEvents keeps the At it carries.
func InitialAuthEvents(req *sessioninfo.NewSessionRequest, imp *InsertImpersonation) []sessioninfo.AuthEvent {
	events := make([]sessioninfo.AuthEvent, 0, len(req.AuthEvents)+1)
	if imp != nil {
		events = append(events, sessioninfo.AuthEvent{Method: sessioninfo.MethodImpersonation, Connection: imp.ActorUsername})
	}

	switch {
	case len(req.AuthEvents) > 0:
		events = append(events, req.AuthEvents...)
	case imp == nil && req.Identity != nil:
		events = append(events, sessioninfo.AuthEvent{Method: req.Identity.Method, Connection: req.Identity.Connection, IDPAMR: req.Identity.IDPAMR})
	}

	return events
}

// OptionalString returns nil for the empty string, so an optional column stores NULL.
func OptionalString(s string) *string {
	if s == "" {
		return nil
	}

	return &s
}
