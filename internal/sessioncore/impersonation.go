package sessioncore

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
	"github.com/cccteam/session/sessionstorage"
	"github.com/go-playground/errors/v5"
)

// ImpersonationRequest describes the impersonated session to establish. It is a
// struct so future fields can be added without breaking callers.
type ImpersonationRequest struct {
	// Actor is the authenticated real user the session acts on behalf of. Required.
	Actor string
	// ActorRealm names the application or identity provider that authenticated the
	// actor, when it differs from this application (e.g. "admin-portal"). Leave it empty
	// for a local actor: a user of this application, logged in here, whose own
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

// IdentityResolver is what a session type contributes to establishment: how a user
// principal becomes the session's identity, and whether an actor may hold a role
// principal's session under their own name.
type IdentityResolver struct {
	// user resolves a user principal to the session's username and user record ID.
	User func(ctx context.Context, user accesstypes.User) (username string, userID ccc.UUID, err error)
	// actor guards a role principal, whose session carries the actor's own username:
	// it refuses when that name already belongs to a user in this store, so one
	// name never means two users in one session table. Nil when the store has no
	// username-keyed users.
	Actor func(ctx context.Context, actor string) error
}

// IdentityAsGiven is the resolver for session types with no username-keyed local user
// record (Preauth, OIDC): the principal's name is the username, the user ID is zero, and
// no name can collide with a user.
var IdentityAsGiven = IdentityResolver{
	User: func(_ context.Context, user accesstypes.User) (string, ccc.UUID, error) {
		return string(user), ccc.NilUUID, nil
	},
}

// StartImpersonatedSession is the establishing flow shared by every session type: the
// type-independent refusals, identity resolution through resolveUser, the record, and
// the BaseSession step that writes, evidences and sets cookies.
func StartImpersonatedSession[T any](
	ctx context.Context, w http.ResponseWriter, base *basesession.BaseSession, req *ImpersonationRequest, customData []*T, resolve IdentityResolver,
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
	if ImpersonatedContext(ctx) {
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
	// An impersonation started on a signed-in session keeps that session's provider
	// session id, so a provider-initiated logout of the actor ends it too.
	if current, ok := ctx.Value(sessioninfo.CtxSessionInfo).(*sessioninfo.SessionData); ok && current != nil {
		newSessionReq.ProviderSessionID = current.ProviderSessionID
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
func impersonatedIdentity(ctx context.Context, req *ImpersonationRequest, resolve IdentityResolver) (username string, userID ccc.UUID, err error) {
	if role, ok := req.Principal.Role(); ok {
		if role == "" {
			return "", ccc.NilUUID, httpio.NewBadRequestMessage("impersonation requires a role name for a role principal")
		}
		if resolve.Actor != nil && req.ActorRealm != "" {
			if err := resolve.Actor(ctx, req.Actor); err != nil {
				return "", ccc.NilUUID, err
			}
		}

		return req.Actor, ccc.NilUUID, nil
	}

	user, _ := req.Principal.User()
	if user == "" {
		return "", ccc.NilUUID, httpio.NewBadRequestMessage("impersonation requires a user or role principal")
	}

	return resolve.User(ctx, user)
}

// UserStore is the user lookup the identity resolver and the session user check
// need: the Auth store and the legacy password store both have it.
type UserStore interface {
	UserByUserName(ctx context.Context, username string) (*sessionstorage.SessionUser, error)
}

// UserIdentity is the identity resolver of Auth and the legacy PasswordAuth, whose users are
// SessionUsers records. A user principal resolves against storage. A foreign actor's
// role principal is refused when the actor's name is already a user there.
func UserIdentity(storage UserStore) IdentityResolver {
	return IdentityResolver{
		User: func(ctx context.Context, user accesstypes.User) (string, ccc.UUID, error) {
			return impersonatedUser(ctx, storage, user)
		},
		Actor: func(ctx context.Context, actor string) error {
			return refuseShadowedActor(ctx, storage, actor)
		},
	}
}

// impersonatedUser returns a user principal's SessionUsers username and ID. A
// missing user is an error, and a disabled one is refused.
func impersonatedUser(ctx context.Context, storage UserStore, user accesstypes.User) (string, ccc.UUID, error) {
	record, err := storage.UserByUserName(ctx, string(user))
	if err != nil {
		return "", ccc.NilUUID, errors.Wrap(err, "UserStore.UserByUserName()")
	}
	if record.Disabled {
		return "", ccc.NilUUID, httpio.NewUnauthorizedMessage("User disabled")
	}

	return record.Username, record.ID, nil
}

// refuseShadowedActor refuses a role-principal session for a foreign actor whose
// username is already a user in SessionUsers. The session row would carry that
// name, and the store's username-keyed operations could not tell the two apart; the
// actor logs in as that user or impersonates it as a user principal instead. A local
// actor's name is their own user and is never checked here.
func refuseShadowedActor(ctx context.Context, storage UserStore, actor string) error {
	_, err := storage.UserByUserName(ctx, actor)
	switch {
	case err == nil:
		return httpio.NewForbiddenMessagef("%q is a user of this application: log in as that user or impersonate it as a user principal", actor)
	case httpio.HasNotFound(err):
		return nil
	default:
		return errors.Wrap(err, "UserStore.UserByUserName()")
	}
}

// SessionUserInfo resolves the validated session's user record for the request
// context. A foreign actor's role-principal session has no local user — the actor is
// not a user of this application — so no record is looked up and none can be disabled.
// Every other session, a local actor's role-principal session included, must map to an
// existing, enabled user.
func SessionUserInfo(ctx context.Context, storage UserStore, sessInfo *sessioninfo.SessionInfo) (*sessioninfo.UserInfo, error) {
	if imp, ok := ImpersonationInCtx(ctx); ok && imp.Principal.IsRole() && !imp.IsLocalActor() {
		return &sessioninfo.UserInfo{Username: sessInfo.Username}, nil
	}

	user, err := storage.UserByUserName(ctx, sessInfo.Username)
	if err != nil {
		return nil, errors.Wrap(err, "UserStore.UserByUserName()")
	}
	if user.Disabled {
		return nil, httpio.NewUnauthorizedMessage("Session Expired")
	}

	return &sessioninfo.UserInfo{ID: user.ID, Username: user.Username, Disabled: user.Disabled}, nil
}

// RefuseImpersonated guards the library's identity-mutating handlers. A self
// operation (changing the session user's own username or password) is refused in
// every impersonated session — it would alter the impersonated user's credentials.
// Other user-management operations are refused only under a mask, which declares the
// session read-only. Refusals are evidenced as IdentityOperationBlocked events.
func RefuseImpersonated(ctx context.Context, base *basesession.BaseSession, operation string, selfOperation bool) error {
	imp, ok := ImpersonationInCtx(ctx)
	if !ok {
		return nil
	}
	if !selfOperation && imp.Mask.IsZero() {
		return nil
	}

	if err := base.EmitImpersonationEvent(ctx, sessioninfo.ImpersonationIdentityOperationBlocked, imp, operation); err != nil {
		logger.FromCtx(ctx).Error(err)
	}

	return httpio.NewForbiddenMessagef("%s is not permitted in an impersonated session", operation)
}

// ImpersonationInCtx returns the impersonation record of the validated session in
// ctx, if any. Unlike sessioninfo.ImpersonationFromCtx it does not panic without a
// session: the establishing call may arrive from a server-to-server context with
// none, and the library's handlers are exercised without one in tests.
func ImpersonationInCtx(ctx context.Context) (*sessioninfo.Impersonation, bool) {
	sessData, ok := ctx.Value(sessioninfo.CtxSessionInfo).(*sessioninfo.SessionData)
	if !ok || sessData.Impersonation == nil {
		return nil, false
	}

	return sessData.Impersonation, true
}

// ImpersonatedContext reports whether ctx carries a validated impersonated session.
func ImpersonatedContext(ctx context.Context) bool {
	_, ok := ImpersonationInCtx(ctx)

	return ok
}
