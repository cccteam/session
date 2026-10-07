package dbtype

import (
	"time"

	"github.com/cccteam/ccc"
	"github.com/cccteam/session/sessioninfo"
)

// NewSessionAccount is what a new session row records about its account when the
// accounts columns are enabled: the account (null for a preauth session and a
// role-principal impersonation) and when the session was authenticated (null for a
// preauth stepping stone or a pending identity's row, which authenticate nothing).
type NewSessionAccount struct {
	UserID          ccc.NullUUID
	AuthenticatedAt *time.Time
}

// SessionAccount renders the account columns of a new session for req, created at.
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

// ResolvesCustomData reports whether the custom session data resolver runs for a
// session created for req: for every session but a pending identity's stepping-stone
// row, which has no account and carries no custom session data.
func ResolvesCustomData(req *sessioninfo.NewSessionRequest) bool {
	return req.Reason != sessioninfo.ReasonPendingIdentity
}

// InitialAuthEvents are the auth events a new session records when an auth events
// table is configured, oldest first: for an impersonated session the impersonation, with
// the actor as its connection, then req.AuthEvents; otherwise req.AuthEvents when the
// request carries any, or else the sign-in method that verified req.Identity. An event
// with a zero At takes at. It is empty for a session that carries none of them.
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
		events = append(events, sessioninfo.AuthEvent{Method: req.Identity.Method, Connection: req.Identity.Connection, IdPAMR: req.Identity.IdPAMR, At: at})
	}

	return events
}

// OptionalString is nil for the empty string: an optional text column's NULL.
func OptionalString(s string) *string {
	if s == "" {
		return nil
	}

	return &s
}
