package dbtype

import (
	"time"

	"github.com/cccteam/ccc"
	"github.com/cccteam/session/sessioninfo"
)

// NewSessionAccount is what a new session row records about its account when the
// accounts columns are enabled: the account (null for a preauth session and a
// role-principal impersonation) and when the session was authenticated (null for a
// preauth stepping stone, which authenticates nothing).
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
	if req.Reason != sessioninfo.ReasonPreauth {
		account.AuthenticatedAt = &at
	}

	return account
}

// InitialAuthEvent is the auth event a new session records first when an auth events
// table is configured: the sign-in method that verified req.Identity, or, for an
// impersonated session, the impersonation with the actor as its connection. It is nil
// for a session that carries neither.
func InitialAuthEvent(req *sessioninfo.NewSessionRequest, imp *InsertImpersonation, at time.Time) *sessioninfo.AuthEvent {
	switch {
	case imp != nil:
		return &sessioninfo.AuthEvent{Method: sessioninfo.MethodImpersonation, Connection: imp.ActorUsername, At: at}
	case req.Identity != nil:
		return &sessioninfo.AuthEvent{Method: req.Identity.Method, Connection: req.Identity.Connection, IdPAMR: req.Identity.IdPAMR, At: at}
	default:
		return nil
	}
}

// OptionalString is nil for the empty string: an optional text column's NULL.
func OptionalString(s string) *string {
	if s == "" {
		return nil
	}

	return &s
}
