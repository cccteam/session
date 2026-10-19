package legacy

import (
	"context"
	"net/http"

	"github.com/cccteam/ccc"
	"github.com/cccteam/session"
	"github.com/cccteam/session/internal/sessioncore"
	"github.com/cccteam/session/sessioninfo"
)

// StartImpersonatedSession establishes a session that operates as req.Principal on
// behalf of req.Actor — the new authentication flow for impersonation. Everything
// after establishment is an ordinary session: for a user principal the session's
// username is the impersonated user, so every consumer sees exactly what that user
// would see; for a role principal it is the actor. The impersonation record is written
// atomically with the session, is joined into every subsequent session read, and its
// evidence is stamped on every request's log entry.
//
// Password auth resolves a user principal against SessionUsers: the session carries the
// record's username and ID, and a missing or disabled user is refused. A role principal's
// session carries the actor's own username. For a local actor (no ActorRealm) that name
// is their own user, and the session is theirs, narrowed to the role. For a foreign
// actor (ActorRealm set) the name is borrowed, so the role principal is refused when it
// is already a SessionUsers row — one name must never mean two users in one
// session table; the actor logs in as that user or impersonates it as a user
// principal instead.
//
// Establishment is refused when the storage has no impersonation table
// (sessionstorage.WithImpersonation), when the calling context is itself an
// impersonated session (no chaining), when a local actor's SourceSessionID is missing or
// is not their live session in this application, and when a user principal names a
// missing or disabled user. The session's hard cap is the impersonation timeout, shortened by
// req.MaxDuration. Optional customData (at most one *T) follows
// StartAuthenticatedSession's semantics; the configured resolver receives
// ReasonImpersonation.
func (p *PasswordAuthAPI[T, U]) StartImpersonatedSession(ctx context.Context, w http.ResponseWriter, req *session.ImpersonationRequest, customData ...*T) (ccc.UUID, error) {
	return p.passwordAuth.shared().StartImpersonatedSession(ctx, w, req, customData, sessioncore.UserIdentity(p.passwordAuth.storage))
}

// DestroyImpersonatedSessions expires every live impersonated session established by
// actor and ends their records with reason Revoked — the offboarding and incident
// tool. It errors when the storage has no impersonation table.
func (p *PasswordAuthAPI[T, U]) DestroyImpersonatedSessions(ctx context.Context, actor string) error {
	return p.passwordAuth.shared().DestroyImpersonatedSessions(ctx, actor)
}

// ActiveImpersonations lists the impersonated sessions that are live right now, newest
// first — the admin surface's view of who is acting as whom. A session is active while
// its record has not ended, its hard cap has not passed, its session row is not
// expired, and it has seen activity within the idle session timeout. q narrows the
// listing by actor and/or principal; nil lists every active impersonation. It errors
// when the storage has no impersonation table.
func (p *PasswordAuthAPI[T, U]) ActiveImpersonations(ctx context.Context, q *session.ImpersonationQuery) ([]*sessioninfo.Impersonation, error) {
	return p.passwordAuth.shared().ActiveImpersonations(ctx, q)
}

// DestroyImpersonatedSession ends one live impersonated session — the operator's action
// on an ActiveImpersonations row: the session row is expired and the record ended with
// reason Revoked, in one transaction, so the next request on that session is refused as
// expired. A session that is not impersonated, or whose record has already ended, is
// left untouched. Who may revoke is the application's guard. It errors when the storage
// has no impersonation table.
func (p *PasswordAuthAPI[T, U]) DestroyImpersonatedSession(ctx context.Context, sessionID ccc.UUID) error {
	return p.passwordAuth.shared().DestroyImpersonatedSession(ctx, sessionID)
}

// EndImpersonation ends the impersonated session in ctx with reason Released and, for a
// local actor whose own session is still live, gives the response that session's
// cookies so the actor is back in it without logging in; restored reports whether that
// happened. See EndImpersonation on the handler type and the "Impersonated sessions"
// section of the README.
func (p *PasswordAuthAPI[T, U]) EndImpersonation(ctx context.Context, w http.ResponseWriter) (restored bool, err error) {
	return p.passwordAuth.shared().EndImpersonation(ctx, w)
}

// StartImpersonatedSession establishes a session that operates as req.Principal on
// behalf of req.Actor; see PasswordAuthAPI.StartImpersonatedSession for the model.
//
// An impersonated OIDC session authenticates no ID token, so a user principal is taken
// as given — the session's username is the principal's name (the same value a login
// would derive from the token) and its user ID is zero. No OIDC user anchor is upserted
// and no roles are synchronized. The session row carries no identity provider session
// ID, so FrontChannelLogout never ends it: it ends by its hard cap, idle expiry, Logout,
// or DestroyImpersonatedSessions. The configured custom session data resolver receives
// ReasonImpersonation with no claims.
//
// Establishment is refused when the storage has no impersonation table and when the
// calling context is itself an impersonated session (no chaining). Optional customData
// (at most one *T) is written atomically with the session, overriding the resolver.
func (p *OIDCAzureAPI[T, U]) StartImpersonatedSession(ctx context.Context, w http.ResponseWriter, req *session.ImpersonationRequest, customData ...*T) (ccc.UUID, error) {
	return p.shared().StartImpersonatedSession(ctx, w, req, customData, sessioncore.IdentityAsGiven)
}

// DestroyImpersonatedSessions expires every live impersonated session established by
// actor and ends their records with reason Revoked — the offboarding and incident
// tool. It errors when the storage has no impersonation table.
func (p *OIDCAzureAPI[T, U]) DestroyImpersonatedSessions(ctx context.Context, actor string) error {
	return p.shared().DestroyImpersonatedSessions(ctx, actor)
}

// ActiveImpersonations lists the impersonated sessions that are live right now, newest
// first — the admin surface's view of who is acting as whom. A session is active while
// its record has not ended, its hard cap has not passed, its session row is not
// expired, and it has seen activity within the idle session timeout. q narrows the
// listing by actor and/or principal; nil lists every active impersonation. It errors
// when the storage has no impersonation table.
func (p *OIDCAzureAPI[T, U]) ActiveImpersonations(ctx context.Context, q *session.ImpersonationQuery) ([]*sessioninfo.Impersonation, error) {
	return p.shared().ActiveImpersonations(ctx, q)
}

// DestroyImpersonatedSession ends one live impersonated session — the operator's action
// on an ActiveImpersonations row: the session row is expired and the record ended with
// reason Revoked, in one transaction, so the next request on that session is refused as
// expired. A session that is not impersonated, or whose record has already ended, is
// left untouched. Who may revoke is the application's guard. It errors when the storage
// has no impersonation table.
func (p *OIDCAzureAPI[T, U]) DestroyImpersonatedSession(ctx context.Context, sessionID ccc.UUID) error {
	return p.shared().DestroyImpersonatedSession(ctx, sessionID)
}

// EndImpersonation ends the impersonated session in ctx with reason Released and, for a
// local actor whose own session is still live, gives the response that session's
// cookies so the actor is back in it without logging in; restored reports whether that
// happened. See EndImpersonation on the handler type and the "Impersonated sessions"
// section of the README.
func (p *OIDCAzureAPI[T, U]) EndImpersonation(ctx context.Context, w http.ResponseWriter) (restored bool, err error) {
	return p.shared().EndImpersonation(ctx, w)
}
