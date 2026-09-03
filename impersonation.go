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
	internalcookie "github.com/cccteam/session/internal/cookie"
	"github.com/cccteam/session/sessioninfo"
	"github.com/go-playground/errors/v5"
)

// defaultImpersonationTimeout is the hard cap on an impersonated session's lifetime
// when WithImpersonationTimeout is not set.
var defaultImpersonationTimeout = time.Hour

// ImpersonationRequest describes the impersonated session to establish. It is a
// struct so future fields can be added without breaking callers.
type ImpersonationRequest struct {
	// Actor is the authenticated real user the session acts on behalf of. Required.
	Actor string
	// ActorRealm names the application or identity provider that authenticated the
	// actor, when it differs from this application (e.g. "admin-portal"). Optional.
	ActorRealm string
	// SourceSessionID is the actor's session in the source application, for
	// cross-application correlation. Optional.
	SourceSessionID ccc.NullUUID
	// Principal is the authorization subject the session evaluates against:
	// accesstypes.UserPrincipal for an impersonated user (who must exist and not be
	// disabled), or accesstypes.RolePrincipal for a role. Required.
	Principal accesstypes.Principal
	// Mask attenuates the session to the listed permissions; the zero mask leaves it
	// unrestricted. accesstypes.MaskPermissions(accesstypes.List, accesstypes.Read) is
	// a read-only session.
	Mask accesstypes.PermissionMask
	// Reason is a free-text justification (a ticket reference, a support note)
	// recorded on the impersonation record. Optional; an application's guard may
	// require it.
	Reason string
	// MaxDuration shortens the session's hard cap below the configured
	// impersonation timeout; zero or a longer value leaves the cap unchanged.
	MaxDuration time.Duration
}

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
// Establishment is refused when the storage has no impersonation table
// (sessionstorage.WithImpersonation), when the calling context is itself an
// impersonated session (no chaining), and when a user principal names a missing or
// disabled user. The session's hard cap is the impersonation timeout, shortened by
// req.MaxDuration. Optional customData (at most one *T) follows
// StartAuthenticatedSession's semantics; the configured resolver receives
// ReasonImpersonation.
func (p *PasswordAuthAPI[T, U]) StartImpersonatedSession(ctx context.Context, w http.ResponseWriter, req *ImpersonationRequest, customData ...*T) (ccc.UUID, error) {
	if len(customData) > 1 {
		return ccc.NilUUID, errors.New("at most one customData value may be provided; it is the complete custom session data row")
	}
	var data *T
	if len(customData) == 1 {
		data = customData[0]
	}

	return p.passwordAuth.startImpersonatedSession(ctx, w, req, data)
}

// DestroyImpersonatedSessions expires every live impersonated session established by
// actor and ends their records with reason Revoked — the offboarding and incident
// tool. It errors when the storage has no impersonation table.
func (p *PasswordAuthAPI[T, U]) DestroyImpersonatedSessions(ctx context.Context, actor string) error {
	if !p.passwordAuth.storage.ImpersonationEnabled() {
		return errImpersonationNotConfigured
	}

	if err := p.passwordAuth.storage.DestroyImpersonatedSessions(ctx, actor); err != nil {
		return errors.Wrap(err, "sessionstorage.PasswordAuthStore.DestroyImpersonatedSessions()")
	}

	return nil
}

var errImpersonationNotConfigured = errors.New("impersonation is not configured on the storage: attach sessionstorage.WithImpersonation")

func (p *PasswordAuth[T, U]) startImpersonatedSession(ctx context.Context, w http.ResponseWriter, req *ImpersonationRequest, customData *T) (ccc.UUID, error) {
	ctx, span := tracer.Start(ctx)
	defer span.End()

	if !p.storage.ImpersonationEnabled() {
		return ccc.NilUUID, errImpersonationNotConfigured
	}
	if req == nil || req.Actor == "" {
		return ccc.NilUUID, httpio.NewBadRequestMessage("impersonation requires an actor")
	}
	if impersonatedContext(ctx) {
		return ccc.NilUUID, httpio.NewForbiddenMessage("an impersonated session cannot establish another impersonated session")
	}

	username, userID, err := p.impersonatedIdentity(ctx, req)
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
		ExpiresAt:       now.Add(p.impersonationTTL(req.MaxDuration)),
	}

	newSessionReq := &sessioninfo.NewSessionRequest{
		Reason:   sessioninfo.ReasonImpersonation,
		Username: username,
		UserID:   userID,
	}
	if customData != nil {
		newSessionReq.CustomData = customData
	}

	id, err := p.storage.CreateImpersonatedSession(ctx, newSessionReq, imp)
	if err != nil {
		return ccc.NilUUID, errors.Wrap(err, "sessionstorage.PasswordAuthStore.CreateImpersonatedSession()")
	}
	imp.SessionID = id

	if err := p.baseSession.EmitImpersonationEvent(ctx, sessioninfo.ImpersonationStarted, imp, ""); err != nil {
		// A failed audit fails the establishment: the session is destroyed before the
		// caller sees the error, so no unevidenced impersonated session ever lives.
		if derr := p.storage.DestroySession(ctx, id); derr != nil {
			logger.FromCtx(ctx).Error(errors.Wrap(derr, "sessionstorage.PasswordAuthStore.DestroySession()"))
		}

		return ccc.NilUUID, errors.Wrap(err, "basesession.BaseSession.EmitImpersonationEvent()")
	}

	p.baseSession.CookieHandler.NewAuthCookie(w, true, id)
	// write new XSRF Token Cookie to match the new SessionID
	p.baseSession.CookieHandler.CreateXSRFTokenCookie(w, id)

	// Evidence on the establishing request's own log entry (the source side).
	l := logger.FromCtx(ctx).AddRequestAttribute("Username", username).AddRequestAttribute(string(internalcookie.SessionID), id)
	for _, a := range imp.Attributes() {
		l = l.AddRequestAttribute(a.Key, a.Value)
	}

	return id, nil
}

// impersonatedIdentity resolves the session's effective identity for req: the
// impersonated user's username and record ID for a user principal (who must exist and
// not be disabled), or the actor with the zero UUID for a role principal.
func (p *PasswordAuth[T, U]) impersonatedIdentity(ctx context.Context, req *ImpersonationRequest) (username string, userID ccc.UUID, err error) {
	if role, ok := req.Principal.Role(); ok {
		if role == "" {
			return "", ccc.NilUUID, httpio.NewBadRequestMessage("impersonation requires a role name for a role principal")
		}

		return req.Actor, ccc.NilUUID, nil
	}

	user, _ := req.Principal.User()
	if user == "" {
		return "", ccc.NilUUID, httpio.NewBadRequestMessage("impersonation requires a user or role principal")
	}

	record, err := p.storage.UserByUserName(ctx, string(user))
	if err != nil {
		return "", ccc.NilUUID, errors.Wrap(err, "sessionstorage.PasswordAuthStore.UserByUserName()")
	}
	if record.Disabled {
		return "", ccc.NilUUID, httpio.NewUnauthorizedMessage("Account disabled")
	}

	return record.Username, record.ID, nil
}

// impersonationTTL returns the hard cap for a new impersonated session: the configured
// impersonation timeout (or the default), shortened by a positive maxDuration.
func (p *PasswordAuth[T, U]) impersonationTTL(maxDuration time.Duration) time.Duration {
	ttl := p.baseSession.ImpersonationTimeout
	if ttl <= 0 {
		ttl = defaultImpersonationTimeout
	}
	if maxDuration > 0 && maxDuration < ttl {
		ttl = maxDuration
	}

	return ttl
}

// sessionUserInfo resolves the validated session's user record for the request
// context. An impersonated role principal has no local user — the actor is not a
// user of this application — so no record is looked up and none can be disabled;
// every other session must map to an existing, enabled user.
func (p *PasswordAuth[T, U]) sessionUserInfo(ctx context.Context, sessInfo *sessioninfo.SessionInfo) (*sessioninfo.UserInfo, error) {
	if imp, ok := impersonationInCtx(ctx); ok && imp.Principal.IsRole() {
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
