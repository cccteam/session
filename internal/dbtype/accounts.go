package dbtype

import (
	"time"

	"github.com/cccteam/ccc"
	"github.com/cccteam/session/sessioninfo"
)

// NewSessionAccount holds the accounts columns of a new session row. UserID is null
// for a preauth session and a role-principal impersonation. AuthenticatedAt is null for
// a preauth session and a pending identity's row, which authenticate nothing.
type NewSessionAccount struct {
	UserID          ccc.NullUUID
	AuthenticatedAt *time.Time
}

// SessionAccount returns the accounts columns of a new session for req, created at at.
func SessionAccount(req *sessioninfo.NewSessionRequest, at time.Time) NewSessionAccount {
	var account NewSessionAccount
	if !req.UserID.IsNil() {
		account.UserID = ccc.NullUUIDFromUUID(req.UserID)
	}
	if req.Reason != sessioninfo.ReasonPreauth && req.Reason != sessioninfo.ReasonPendingIdentity {
		account.AuthenticatedAt = &at
	}

	return account
}

// ResolvesCustomData reports whether the custom session data resolver runs for req. It
// runs for every session except a pending identity's row, which has no account.
func ResolvesCustomData(req *sessioninfo.NewSessionRequest) bool {
	return req.Reason != sessioninfo.ReasonPendingIdentity
}

// InitialAuthEvents returns the auth events a new session records, oldest first. An
// impersonated session records its impersonation first, with the actor as the
// connection. Then come req.AuthEvents or, when there are none and the session is not
// impersonated, the method that verified req.Identity. An event with a zero At takes at.
func InitialAuthEvents(req *sessioninfo.NewSessionRequest, imp *InsertImpersonation, at time.Time) []sessioninfo.AuthEvent {
	events := make([]sessioninfo.AuthEvent, 0, len(req.AuthEvents)+1)
	if imp != nil {
		events = append(events, sessioninfo.AuthEvent{Method: sessioninfo.MethodImpersonation, Connection: imp.ActorUsername, At: at})
	}

	switch {
	case len(req.AuthEvents) > 0:
		for _, event := range req.AuthEvents {
			if event.At.IsZero() {
				event.At = at
			}
			events = append(events, event)
		}
	case imp == nil && req.Identity != nil:
		events = append(events, sessioninfo.AuthEvent{Method: req.Identity.Method, Connection: req.Identity.Connection, IDPAMR: req.Identity.IDPAMR, At: at})
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
