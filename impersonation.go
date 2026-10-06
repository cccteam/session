package session

import (
	"context"
	"net/http"
	"time"

	"github.com/cccteam/ccc"
	"github.com/cccteam/ccc/accesstypes"
	"github.com/cccteam/ccc/tracer"
	"github.com/cccteam/httpio"
	"github.com/cccteam/logger"
	"github.com/cccteam/session/internal/basesession"
	"github.com/cccteam/session/sessioninfo"
	"github.com/go-playground/errors/v5"
)

// ImpersonationRequest describes the impersonated session to establish. It is a
// struct so future fields can be added without breaking callers.
type ImpersonationRequest struct {
	// Actor is the authenticated real user the session acts on behalf of. Required.
	Actor string
	// ActorRealm names the application or identity provider that authenticated the
	// actor, when it differs from this application (e.g. "admin-portal"). Leave it empty
	// for a local actor: an account of this application, logged in here, whose own
	// session is SourceSessionID.
	ActorRealm string
	// SourceSessionID is the actor's own session. For a local actor it is required and
	// verified: a live, non-impersonated session of this application carrying the
	// actor's username. It is kept alive by the impersonated session's activity and
	// EndImpersonation returns the actor to it. For a foreign actor it is the session in
	// the source application, optional, for cross-application correlation.
	SourceSessionID ccc.NullUUID
	// Principal is the authorization subject the session evaluates against:
	// accesstypes.UserPrincipal for an impersonated user, or accesstypes.RolePrincipal
	// for a role. Required. How a user principal becomes the session's identity depends
	// on the session type — see StartImpersonatedSession on each API.
	Principal accesstypes.Principal
	// Mask attenuates the session to the listed permissions; the zero mask
	// (accesstypes.AllowAll()) leaves it unrestricted, and
	// accesstypes.MaskPermissions(accesstypes.DenyAll(), accesstypes.List, accesstypes.Read)
	// is a read-only session.
	Mask accesstypes.PermissionMask
	// Reason is a free-text justification (a ticket reference, a support note)
	// recorded on the impersonation record. Optional; an application's guard may
	// require it.
	Reason string
	// MaxDuration shortens the session's hard cap below the configured
	// impersonation timeout; zero or a longer value leaves the cap unchanged.
	MaxDuration time.Duration
}

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
// is their own account, and the session is theirs, narrowed to the role. For a foreign
// actor (ActorRealm set) the name is borrowed, so the role principal is refused when it
// is already a SessionUsers account — one name must never mean two accounts in one
// session table; the actor logs in as that account or impersonates it as a user
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
func (p *PasswordAuthAPI[T, U]) StartImpersonatedSession(ctx context.Context, w http.ResponseWriter, req *ImpersonationRequest, customData ...*T) (ccc.UUID, error) {
	return startImpersonatedSession(ctx, w, p.passwordAuth.baseSession, req, customData, p.passwordAuth.identity())
}

// DestroyImpersonatedSessions expires every live impersonated session established by
// actor and ends their records with reason Revoked — the offboarding and incident
// tool. It errors when the storage has no impersonation table.
func (p *PasswordAuthAPI[T, U]) DestroyImpersonatedSessions(ctx context.Context, actor string) error {
	if err := p.passwordAuth.baseSession.DestroyImpersonatedSessions(ctx, actor); err != nil {
		return errors.Wrap(err, "basesession.BaseSession.DestroyImpersonatedSessions()")
	}

	return nil
}

// ActiveImpersonations lists the impersonated sessions that are live right now, newest
// first — the admin surface's view of who is acting as whom. A session is active while
// its record has not ended, its hard cap has not passed, its session row is not
// expired, and it has seen activity within the idle session timeout. q narrows the
// listing by actor and/or principal; nil lists every active impersonation. It errors
// when the storage has no impersonation table.
func (p *PasswordAuthAPI[T, U]) ActiveImpersonations(ctx context.Context, q *ImpersonationQuery) ([]*sessioninfo.Impersonation, error) {
	imps, err := p.passwordAuth.baseSession.ActiveImpersonations(ctx, q)
	if err != nil {
		return nil, errors.Wrap(err, "basesession.BaseSession.ActiveImpersonations()")
	}

	return imps, nil
}

// DestroyImpersonatedSession ends one live impersonated session — the operator's action
// on an ActiveImpersonations row: the session row is expired and the record ended with
// reason Revoked, in one transaction, so the next request on that session is refused as
// expired. A session that is not impersonated, or whose record has already ended, is
// left untouched. Who may revoke is the application's guard. It errors when the storage
// has no impersonation table.
func (p *PasswordAuthAPI[T, U]) DestroyImpersonatedSession(ctx context.Context, sessionID ccc.UUID) error {
	if err := p.passwordAuth.baseSession.DestroyImpersonatedSession(ctx, sessionID); err != nil {
		return errors.Wrap(err, "basesession.BaseSession.DestroyImpersonatedSession()")
	}

	return nil
}

// EndImpersonation ends the impersonated session in ctx with reason Released and, for a
// local actor whose own session is still live, gives the response that session's
// cookies so the actor is back in it without logging in; restored reports whether that
// happened. See EndImpersonation on the handler type and the "Impersonated sessions"
// section of the README.
func (p *PasswordAuthAPI[T, U]) EndImpersonation(ctx context.Context, w http.ResponseWriter) (restored bool, err error) {
	restored, err = p.passwordAuth.baseSession.EndImpersonationAPI(ctx, w)
	if err != nil {
		return false, errors.Wrap(err, "basesession.BaseSession.EndImpersonationAPI()")
	}

	return restored, nil
}

// StartImpersonatedSession establishes a session that operates as req.Principal on
// behalf of req.Actor; see PasswordAuthAPI.StartImpersonatedSession for the model.
//
// Preauth has no user record, so a user principal is taken as given: the session's
// username is the principal's name and its user ID is zero, exactly as Login trusts
// the caller's username. Whether that user exists is the application's guard.
//
// Establishment is refused when the storage has no impersonation table and when the
// calling context is itself an impersonated session (no chaining). Optional customData
// (at most one *T) follows Login's semantics.
func (p *PreauthAPI[T]) StartImpersonatedSession(ctx context.Context, w http.ResponseWriter, req *ImpersonationRequest, customData ...*T) (ccc.UUID, error) {
	return startImpersonatedSession(ctx, w, p.preauth.baseSession, req, customData, identityAsGiven)
}

// DestroyImpersonatedSessions expires every live impersonated session established by
// actor and ends their records with reason Revoked — the offboarding and incident
// tool. It errors when the storage has no impersonation table.
func (p *PreauthAPI[T]) DestroyImpersonatedSessions(ctx context.Context, actor string) error {
	if err := p.preauth.baseSession.DestroyImpersonatedSessions(ctx, actor); err != nil {
		return errors.Wrap(err, "basesession.BaseSession.DestroyImpersonatedSessions()")
	}

	return nil
}

// ActiveImpersonations lists the impersonated sessions that are live right now, newest
// first — the admin surface's view of who is acting as whom. A session is active while
// its record has not ended, its hard cap has not passed, its session row is not
// expired, and it has seen activity within the idle session timeout. q narrows the
// listing by actor and/or principal; nil lists every active impersonation. It errors
// when the storage has no impersonation table.
func (p *PreauthAPI[T]) ActiveImpersonations(ctx context.Context, q *ImpersonationQuery) ([]*sessioninfo.Impersonation, error) {
	imps, err := p.preauth.baseSession.ActiveImpersonations(ctx, q)
	if err != nil {
		return nil, errors.Wrap(err, "basesession.BaseSession.ActiveImpersonations()")
	}

	return imps, nil
}

// DestroyImpersonatedSession ends one live impersonated session — the operator's action
// on an ActiveImpersonations row: the session row is expired and the record ended with
// reason Revoked, in one transaction, so the next request on that session is refused as
// expired. A session that is not impersonated, or whose record has already ended, is
// left untouched. Who may revoke is the application's guard. It errors when the storage
// has no impersonation table.
func (p *PreauthAPI[T]) DestroyImpersonatedSession(ctx context.Context, sessionID ccc.UUID) error {
	if err := p.preauth.baseSession.DestroyImpersonatedSession(ctx, sessionID); err != nil {
		return errors.Wrap(err, "basesession.BaseSession.DestroyImpersonatedSession()")
	}

	return nil
}

// EndImpersonation ends the impersonated session in ctx with reason Released and, for a
// local actor whose own session is still live, gives the response that session's
// cookies so the actor is back in it without logging in; restored reports whether that
// happened. See EndImpersonation on the handler type and the "Impersonated sessions"
// section of the README.
func (p *PreauthAPI[T]) EndImpersonation(ctx context.Context, w http.ResponseWriter) (restored bool, err error) {
	restored, err = p.preauth.baseSession.EndImpersonationAPI(ctx, w)
	if err != nil {
		return false, errors.Wrap(err, "basesession.BaseSession.EndImpersonationAPI()")
	}

	return restored, nil
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
func (p *OIDCAzureAPI[T, U]) StartImpersonatedSession(ctx context.Context, w http.ResponseWriter, req *ImpersonationRequest, customData ...*T) (ccc.UUID, error) {
	return startImpersonatedSession(ctx, w, p.oidc.baseSession, req, customData, identityAsGiven)
}

// DestroyImpersonatedSessions expires every live impersonated session established by
// actor and ends their records with reason Revoked — the offboarding and incident
// tool. It errors when the storage has no impersonation table.
func (p *OIDCAzureAPI[T, U]) DestroyImpersonatedSessions(ctx context.Context, actor string) error {
	if err := p.oidc.baseSession.DestroyImpersonatedSessions(ctx, actor); err != nil {
		return errors.Wrap(err, "basesession.BaseSession.DestroyImpersonatedSessions()")
	}

	return nil
}

// ActiveImpersonations lists the impersonated sessions that are live right now, newest
// first — the admin surface's view of who is acting as whom. A session is active while
// its record has not ended, its hard cap has not passed, its session row is not
// expired, and it has seen activity within the idle session timeout. q narrows the
// listing by actor and/or principal; nil lists every active impersonation. It errors
// when the storage has no impersonation table.
func (p *OIDCAzureAPI[T, U]) ActiveImpersonations(ctx context.Context, q *ImpersonationQuery) ([]*sessioninfo.Impersonation, error) {
	imps, err := p.oidc.baseSession.ActiveImpersonations(ctx, q)
	if err != nil {
		return nil, errors.Wrap(err, "basesession.BaseSession.ActiveImpersonations()")
	}

	return imps, nil
}

// DestroyImpersonatedSession ends one live impersonated session — the operator's action
// on an ActiveImpersonations row: the session row is expired and the record ended with
// reason Revoked, in one transaction, so the next request on that session is refused as
// expired. A session that is not impersonated, or whose record has already ended, is
// left untouched. Who may revoke is the application's guard. It errors when the storage
// has no impersonation table.
func (p *OIDCAzureAPI[T, U]) DestroyImpersonatedSession(ctx context.Context, sessionID ccc.UUID) error {
	if err := p.oidc.baseSession.DestroyImpersonatedSession(ctx, sessionID); err != nil {
		return errors.Wrap(err, "basesession.BaseSession.DestroyImpersonatedSession()")
	}

	return nil
}

// EndImpersonation ends the impersonated session in ctx with reason Released and, for a
// local actor whose own session is still live, gives the response that session's
// cookies so the actor is back in it without logging in; restored reports whether that
// happened. See EndImpersonation on the handler type and the "Impersonated sessions"
// section of the README.
func (p *OIDCAzureAPI[T, U]) EndImpersonation(ctx context.Context, w http.ResponseWriter) (restored bool, err error) {
	restored, err = p.oidc.baseSession.EndImpersonationAPI(ctx, w)
	if err != nil {
		return false, errors.Wrap(err, "basesession.BaseSession.EndImpersonationAPI()")
	}

	return restored, nil
}

// StartImpersonatedSession establishes a session that operates as req.Principal on
// behalf of req.Actor; see PasswordAuthAPI.StartImpersonatedSession for the model and
// OIDCAzureAPI.StartImpersonatedSession for what an impersonated OIDC session does not
// do (no anchor upsert, no role synchronization, no identity provider session). A user
// principal is taken as given: the session's username is the principal's name (the
// email a login would take from the token) and its user ID is zero.
//
// Establishment is refused when the storage has no impersonation table and when the
// calling context is itself an impersonated session (no chaining). Optional customData
// (at most one *T) is written atomically with the session, overriding the resolver.
func (p *OIDCGoogleAPI[T, U]) StartImpersonatedSession(ctx context.Context, w http.ResponseWriter, req *ImpersonationRequest, customData ...*T) (ccc.UUID, error) {
	return startImpersonatedSession(ctx, w, p.oidc.baseSession, req, customData, identityAsGiven)
}

// DestroyImpersonatedSessions expires every live impersonated session established by
// actor and ends their records with reason Revoked — the offboarding and incident
// tool. It errors when the storage has no impersonation table.
func (p *OIDCGoogleAPI[T, U]) DestroyImpersonatedSessions(ctx context.Context, actor string) error {
	if err := p.oidc.baseSession.DestroyImpersonatedSessions(ctx, actor); err != nil {
		return errors.Wrap(err, "basesession.BaseSession.DestroyImpersonatedSessions()")
	}

	return nil
}

// ActiveImpersonations lists the impersonated sessions that are live right now, newest
// first — the admin surface's view of who is acting as whom. A session is active while
// its record has not ended, its hard cap has not passed, its session row is not
// expired, and it has seen activity within the idle session timeout. q narrows the
// listing by actor and/or principal; nil lists every active impersonation. It errors
// when the storage has no impersonation table.
func (p *OIDCGoogleAPI[T, U]) ActiveImpersonations(ctx context.Context, q *ImpersonationQuery) ([]*sessioninfo.Impersonation, error) {
	imps, err := p.oidc.baseSession.ActiveImpersonations(ctx, q)
	if err != nil {
		return nil, errors.Wrap(err, "basesession.BaseSession.ActiveImpersonations()")
	}

	return imps, nil
}

// DestroyImpersonatedSession ends one live impersonated session — the operator's action
// on an ActiveImpersonations row: the session row is expired and the record ended with
// reason Revoked, in one transaction, so the next request on that session is refused as
// expired. A session that is not impersonated, or whose record has already ended, is
// left untouched. Who may revoke is the application's guard. It errors when the storage
// has no impersonation table.
func (p *OIDCGoogleAPI[T, U]) DestroyImpersonatedSession(ctx context.Context, sessionID ccc.UUID) error {
	if err := p.oidc.baseSession.DestroyImpersonatedSession(ctx, sessionID); err != nil {
		return errors.Wrap(err, "basesession.BaseSession.DestroyImpersonatedSession()")
	}

	return nil
}

// EndImpersonation ends the impersonated session in ctx with reason Released and, for a
// local actor whose own session is still live, gives the response that session's
// cookies so the actor is back in it without logging in; restored reports whether that
// happened. See EndImpersonation on the handler type and the "Impersonated sessions"
// section of the README.
func (p *OIDCGoogleAPI[T, U]) EndImpersonation(ctx context.Context, w http.ResponseWriter) (restored bool, err error) {
	restored, err = p.oidc.baseSession.EndImpersonationAPI(ctx, w)
	if err != nil {
		return false, errors.Wrap(err, "basesession.BaseSession.EndImpersonationAPI()")
	}

	return restored, nil
}

// identityResolver is what a session type contributes to establishment: how a user
// principal becomes the session's identity, and whether an actor may hold a role
// principal's session under their own name.
type identityResolver struct {
	// user resolves a user principal to the session's username and user record ID.
	user func(ctx context.Context, user accesstypes.User) (username string, userID ccc.UUID, err error)
	// actor guards a role principal, whose session carries the actor's own username:
	// it refuses when that name already belongs to an account in this store, so one
	// name never means two accounts in one session table. Nil when the store has no
	// username-keyed accounts.
	actor func(ctx context.Context, actor string) error
}

// identityAsGiven is the resolver for session types with no username-keyed local user
// record (Preauth, OIDC): the principal's name is the username, the user ID is zero, and
// no name can collide with an account.
var identityAsGiven = identityResolver{
	user: func(_ context.Context, user accesstypes.User) (string, ccc.UUID, error) {
		return string(user), ccc.NilUUID, nil
	},
}

// startImpersonatedSession is the establishing flow shared by every session type: the
// type-independent refusals, identity resolution through resolveUser, the record, and
// the BaseSession step that writes, evidences and sets cookies.
func startImpersonatedSession[T any](
	ctx context.Context, w http.ResponseWriter, base *basesession.BaseSession, req *ImpersonationRequest, customData []*T, resolve identityResolver,
) (ccc.UUID, error) {
	if len(customData) > 1 {
		return ccc.NilUUID, errors.New("at most one customData value may be provided; it is the complete custom session data row")
	}

	ctx, span := tracer.Start(ctx)
	defer span.End()

	if !base.Storage.ImpersonationEnabled() {
		return ccc.NilUUID, basesession.ErrImpersonationNotConfigured
	}
	if req == nil || req.Actor == "" {
		return ccc.NilUUID, httpio.NewBadRequestMessage("impersonation requires an actor")
	}
	if impersonatedContext(ctx) {
		return ccc.NilUUID, httpio.NewForbiddenMessage("an impersonated session cannot establish another impersonated session")
	}

	username, userID, err := impersonatedIdentity(ctx, req, resolve)
	if err != nil {
		return ccc.NilUUID, err
	}

	now := time.Now()
	imp := &sessioninfo.Impersonation{
		Actor:           req.Actor,
		ActorRealm:      req.ActorRealm,
		SourceSessionID: req.SourceSessionID,
		Principal:       req.Principal,
		Mask:            req.Mask,
		Reason:          req.Reason,
		StartedAt:       now,
		ExpiresAt:       now.Add(base.ImpersonationTTL(req.MaxDuration)),
	}

	newSessionReq := &sessioninfo.NewSessionRequest{
		Reason:   sessioninfo.ReasonImpersonation,
		Username: username,
		UserID:   userID,
	}
	if len(customData) == 1 && customData[0] != nil {
		newSessionReq.CustomData = customData[0]
	}

	id, err := base.StartImpersonatedSession(ctx, w, newSessionReq, imp)
	if err != nil {
		return ccc.NilUUID, errors.Wrap(err, "basesession.BaseSession.StartImpersonatedSession()")
	}

	return id, nil
}

// impersonatedIdentity resolves the session's effective identity for req: the actor
// with the zero UUID for a role principal (once the type's guard allows a foreign
// actor's name), or the type's answer for a user principal.
func impersonatedIdentity(ctx context.Context, req *ImpersonationRequest, resolve identityResolver) (username string, userID ccc.UUID, err error) {
	if role, ok := req.Principal.Role(); ok {
		if role == "" {
			return "", ccc.NilUUID, httpio.NewBadRequestMessage("impersonation requires a role name for a role principal")
		}
		if resolve.actor != nil && req.ActorRealm != "" {
			if err := resolve.actor(ctx, req.Actor); err != nil {
				return "", ccc.NilUUID, err
			}
		}

		return req.Actor, ccc.NilUUID, nil
	}

	user, _ := req.Principal.User()
	if user == "" {
		return "", ccc.NilUUID, httpio.NewBadRequestMessage("impersonation requires a user or role principal")
	}

	return resolve.user(ctx, user)
}

// identity is password auth's identity resolver: user principals resolve against
// SessionUsers, and a role principal for a foreign actor is refused when the actor's
// name is already an account there.
func (p *PasswordAuth[T, U]) identity() identityResolver {
	return identityResolver{user: p.impersonatedUser, actor: p.refuseShadowedActor}
}

// impersonatedUser resolves a user principal against SessionUsers: the record's username
// and ID; a missing user is an error and a disabled one is refused.
func (p *PasswordAuth[T, U]) impersonatedUser(ctx context.Context, user accesstypes.User) (string, ccc.UUID, error) {
	record, err := p.storage.UserByUserName(ctx, string(user))
	if err != nil {
		return "", ccc.NilUUID, errors.Wrap(err, "sessionstorage.PasswordAuthStore.UserByUserName()")
	}
	if record.Disabled {
		return "", ccc.NilUUID, httpio.NewUnauthorizedMessage("Account disabled")
	}

	return record.Username, record.ID, nil
}

// refuseShadowedActor refuses a role-principal session for a foreign actor whose
// username is already an account in SessionUsers. The session row would carry that
// name, and the store's username-keyed operations could not tell the two apart; the
// actor logs in as that account or impersonates it as a user principal instead. A local
// actor's name is their own account and is never checked here.
func (p *PasswordAuth[T, U]) refuseShadowedActor(ctx context.Context, actor string) error {
	_, err := p.storage.UserByUserName(ctx, actor)
	switch {
	case err == nil:
		return httpio.NewForbiddenMessagef("%q is a user of this application: log in as that user or impersonate it as a user principal", actor)
	case httpio.HasNotFound(err):
		return nil
	default:
		return errors.Wrap(err, "sessionstorage.PasswordAuthStore.UserByUserName()")
	}
}

// sessionUserInfo resolves the validated session's user record for the request
// context. A foreign actor's role-principal session has no local user — the actor is
// not a user of this application — so no record is looked up and none can be disabled.
// Every other session, a local actor's role-principal session included, must map to an
// existing, enabled user.
func (p *PasswordAuth[T, U]) sessionUserInfo(ctx context.Context, sessInfo *sessioninfo.SessionInfo) (*sessioninfo.UserInfo, error) {
	if imp, ok := impersonationInCtx(ctx); ok && imp.Principal.IsRole() && !imp.IsLocalActor() {
		return &sessioninfo.UserInfo{Username: sessInfo.Username}, nil
	}

	user, err := p.storage.UserByUserName(ctx, sessInfo.Username)
	if err != nil {
		return nil, errors.Wrap(err, "sessionstorage.PasswordAuthStore.UserByUserName()")
	}
	if user.Disabled {
		return nil, httpio.NewUnauthorizedMessage("Session Expired")
	}

	return &sessioninfo.UserInfo{ID: user.ID, Username: user.Username, Disabled: user.Disabled}, nil
}

// refuseImpersonated guards the library's identity-mutating handlers. A self
// operation (changing the session user's own username or password) is refused in
// every impersonated session — it would alter the impersonated user's credentials.
// Other user-management operations are refused only under a mask, which declares the
// session read-only. Refusals are evidenced as IdentityOperationBlocked events.
func (p *PasswordAuth[T, U]) refuseImpersonated(ctx context.Context, operation string, selfOperation bool) error {
	imp, ok := impersonationInCtx(ctx)
	if !ok {
		return nil
	}
	if !selfOperation && imp.Mask.IsZero() {
		return nil
	}

	if err := p.baseSession.EmitImpersonationEvent(ctx, sessioninfo.ImpersonationIdentityOperationBlocked, imp, operation); err != nil {
		logger.FromCtx(ctx).Error(err)
	}

	return httpio.NewForbiddenMessagef("%s is not permitted in an impersonated session", operation)
}

// impersonationInCtx returns the impersonation record of the validated session in
// ctx, if any. Unlike sessioninfo.ImpersonationFromCtx it does not panic without a
// session: the establishing call may arrive from a server-to-server context with
// none, and the library's handlers are exercised without one in tests.
func impersonationInCtx(ctx context.Context) (*sessioninfo.Impersonation, bool) {
	sessData, ok := ctx.Value(sessioninfo.CtxSessionInfo).(*sessioninfo.SessionData)
	if !ok || sessData.Impersonation == nil {
		return nil, false
	}

	return sessData.Impersonation, true
}

// impersonatedContext reports whether ctx carries a validated impersonated session.
func impersonatedContext(ctx context.Context) bool {
	_, ok := impersonationInCtx(ctx)

	return ok
}
