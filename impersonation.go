package session

import (
	"context"
	"net/http"
	"time"

	"github.com/cccteam/ccc"
	"github.com/cccteam/session/internal/basesession"
	"github.com/cccteam/session/internal/sessioncore"
	"github.com/cccteam/session/sessioninfo"
)

// ImpersonationRequest describes the impersonated session to establish. It is a
// struct so future fields can be added without breaking callers.
type ImpersonationRequest = sessioncore.ImpersonationRequest

// ImpersonationQuery narrows an ActiveImpersonations listing; see
// sessioninfo.ImpersonationQuery. The zero query lists every active impersonation.
type ImpersonationQuery = sessioninfo.ImpersonationQuery

// ImpersonationAuditHook receives every lifecycle event of an impersonated session.
// For the Started event a returned error fails the establishment — the session is
// destroyed and the caller sees the error — so an application that must persist
// evidence before the session lives can guarantee it. Errors from other events are
// logged.
type ImpersonationAuditHook = func(ctx context.Context, event sessioninfo.ImpersonationEvent) error

// WithImpersonationTimeout sets the hard cap on an impersonated session's lifetime.
// The cap is absolute: it is fixed when the session is established and idle-activity
// renewal never extends past it. The idle session timeout applies independently. The
// default is one hour.
func WithImpersonationTimeout(d time.Duration) BaseSessionOption {
	return func(b *basesession.BaseSession) {
		b.ImpersonationTimeout = d
	}
}

// WithImpersonationAudit registers the hook that receives impersonation lifecycle
// events (see ImpersonationAuditHook). Events are logged with the canonical evidence
// attributes whether or not a hook is registered.
func WithImpersonationAudit(hook ImpersonationAuditHook) BaseSessionOption {
	return func(b *basesession.BaseSession) {
		b.ImpersonationAudit = hook
	}
}

// StartImpersonatedSession establishes a session that operates as req.Principal on
// behalf of req.Actor; see AuthAPI.StartImpersonatedSession for the model.
//
// Preauth has no user record, so a user principal is taken as given: the session's
// username is the principal's name and its user ID is zero, exactly as Login trusts
// the caller's username. Whether that user exists is the application's guard.
//
// Establishment is refused when the storage has no impersonation table and when the
// calling context is itself an impersonated session (no chaining). Optional customData
// (at most one *T) follows Login's semantics.
func (p *PreauthAPI[T]) StartImpersonatedSession(ctx context.Context, w http.ResponseWriter, req *ImpersonationRequest, customData ...*T) (ccc.UUID, error) {
	return p.shared().StartImpersonatedSession(ctx, w, req, customData, sessioncore.IdentityAsGiven)
}

// DestroyImpersonatedSessions expires every live impersonated session established by
// actor and ends their records with reason Revoked — the offboarding and incident
// tool. It errors when the storage has no impersonation table.
func (p *PreauthAPI[T]) DestroyImpersonatedSessions(ctx context.Context, actor string) error {
	return p.shared().DestroyImpersonatedSessions(ctx, actor)
}

// ActiveImpersonations lists the impersonated sessions that are live right now, newest
// first — the admin surface's view of who is acting as whom. A session is active while
// its record has not ended, its hard cap has not passed, its session row is not
// expired, and it has seen activity within the idle session timeout. q narrows the
// listing by actor and/or principal; nil lists every active impersonation. It errors
// when the storage has no impersonation table.
func (p *PreauthAPI[T]) ActiveImpersonations(ctx context.Context, q *ImpersonationQuery) ([]*sessioninfo.Impersonation, error) {
	return p.shared().ActiveImpersonations(ctx, q)
}

// DestroyImpersonatedSession ends one live impersonated session — the operator's action
// on an ActiveImpersonations row: the session row is expired and the record ended with
// reason Revoked, in one transaction, so the next request on that session is refused as
// expired. A session that is not impersonated, or whose record has already ended, is
// left untouched. Who may revoke is the application's guard. It errors when the storage
// has no impersonation table.
func (p *PreauthAPI[T]) DestroyImpersonatedSession(ctx context.Context, sessionID ccc.UUID) error {
	return p.shared().DestroyImpersonatedSession(ctx, sessionID)
}

// EndImpersonation ends the impersonated session in ctx with reason Released and, for a
// local actor whose own session is still live, gives the response that session's
// cookies so the actor is back in it without logging in; restored reports whether that
// happened. See EndImpersonation on the handler type and the "Impersonated sessions"
// section of the README.
func (p *PreauthAPI[T]) EndImpersonation(ctx context.Context, w http.ResponseWriter) (restored bool, err error) {
	return p.shared().EndImpersonation(ctx, w)
}
