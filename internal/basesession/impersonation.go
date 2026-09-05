package basesession

import (
	"context"
	"net/http"
	"time"

	"github.com/cccteam/ccc"
	"github.com/cccteam/ccc/accesstypes"
	"github.com/cccteam/ccc/tracer"
	"github.com/cccteam/httpio"
	"github.com/cccteam/logger"
	internalcookie "github.com/cccteam/session/internal/cookie"
	"github.com/cccteam/session/sessioninfo"
	"github.com/go-playground/errors/v5"
)

// DefaultImpersonationTimeout is the hard cap on an impersonated session's lifetime
// when BaseSession.ImpersonationTimeout is zero.
var DefaultImpersonationTimeout = time.Hour

// ErrImpersonationNotConfigured is returned by every impersonation API when the storage
// has no impersonation record table.
var ErrImpersonationNotConfigured = errors.New("impersonation is not configured on the storage: attach sessionstorage.WithImpersonation")

// ImpersonationTTL returns the hard cap for a new impersonated session: the configured
// impersonation timeout (or the default), shortened by a positive maxDuration.
func (s *BaseSession) ImpersonationTTL(maxDuration time.Duration) time.Duration {
	ttl := s.ImpersonationTimeout
	if ttl <= 0 {
		ttl = DefaultImpersonationTimeout
	}
	if maxDuration > 0 && maxDuration < ttl {
		ttl = maxDuration
	}

	return ttl
}

// StartImpersonatedSession is the establishing step shared by every session type once
// the effective identity is resolved: it writes the session row and its record
// atomically, delivers the Started event (a failing audit hook destroys the session and
// fails the call, so no unevidenced impersonated session ever lives), writes the auth
// and XSRF cookies, and stamps the evidence on the establishing request's log entry.
// req.Username is the session's effective identity; imp.SessionID is set on return.
func (s *BaseSession) StartImpersonatedSession(ctx context.Context, w http.ResponseWriter, req *sessioninfo.NewSessionRequest, imp *sessioninfo.Impersonation) (ccc.UUID, error) {
	ctx, span := tracer.Start(ctx)
	defer span.End()

	if err := s.verifyLocalActor(ctx, imp); err != nil {
		return ccc.NilUUID, err
	}

	id, err := s.Storage.CreateImpersonatedSession(ctx, req, imp)
	if err != nil {
		return ccc.NilUUID, errors.Wrap(err, "sessionstorage.BaseStore.CreateImpersonatedSession()")
	}
	imp.SessionID = id
	// The establishing call's own span carries the evidence on the source side.
	span.SetAttributes(impersonationSpanAttributes(imp)...)

	if err := s.EmitImpersonationEvent(ctx, sessioninfo.ImpersonationStarted, imp, ""); err != nil {
		if derr := s.Storage.DestroySession(ctx, id); derr != nil {
			logger.FromCtx(ctx).Error(errors.Wrap(derr, "sessionstorage.BaseStore.DestroySession()"))
		}

		return ccc.NilUUID, errors.Wrap(err, "basesession.BaseSession.EmitImpersonationEvent()")
	}

	// The establishing call is a same-site handoff, never an OAuth redirect, so the
	// cookie is SameSite=Strict for every session type.
	s.CookieHandler.NewAuthCookie(w, true, id)
	// write new XSRF Token Cookie to match the new SessionID
	s.CookieHandler.CreateXSRFTokenCookie(w, id)

	// Evidence on the establishing request's own log entry (the source side).
	l := logger.FromCtx(ctx).AddRequestAttribute("Username", req.Username).AddRequestAttribute(string(internalcookie.SessionID), id)
	for _, a := range imp.Attributes() {
		l = l.AddRequestAttribute(a.Key, a.Value)
	}

	return id, nil
}

// verifyLocalActor proves a local actor's claim. An actor with no ActorRealm is an
// account of this application, so the request must name the actor's own session in
// this store as SourceSessionID, and that session must be live, not itself impersonated,
// and carry the actor's username. A foreign actor (ActorRealm set) was authenticated
// elsewhere and has nothing here to check.
func (s *BaseSession) verifyLocalActor(ctx context.Context, imp *sessioninfo.Impersonation) error {
	if !imp.IsLocalActor() {
		return nil
	}
	if !imp.SourceSessionID.Valid {
		return httpio.NewBadRequestMessage("a local actor must name their own session as SourceSessionID; an actor authenticated by another application sets ActorRealm")
	}

	src, err := s.Storage.Session(ctx, imp.SourceSessionID.UUID)
	if err != nil {
		return httpio.NewForbiddenMessageWithError(err, "the actor's source session is not a session of this application")
	}
	if !s.live(src) || src.Impersonation != nil || src.Username != imp.Actor {
		return httpio.NewForbiddenMessagef("session %s is not a live session of %q in this application", src.ID, imp.Actor)
	}

	return nil
}

// live reports whether a session row is neither destroyed nor past the idle timeout.
func (s *BaseSession) live(sess *sessioninfo.SessionData) bool {
	return !sess.Expired && time.Since(sess.UpdatedAt) <= s.SessionTimeout
}

// EndImpersonationResponse is the body of the EndImpersonation handler.
type EndImpersonationResponse struct {
	// Restored reports that the browser's cookies name the actor's own session again;
	// false means the actor must log in.
	Restored bool `json:"restored"`
}

// EndImpersonation ends the impersonated session and, when it can, returns the actor to
// their own session; see EndImpersonationAPI. The body says which happened.
func (s *BaseSession) EndImpersonation() http.HandlerFunc {
	return s.Handle(func(w http.ResponseWriter, r *http.Request) error {
		ctx, span := tracer.Start(r.Context())
		defer span.End()

		restored, err := s.EndImpersonationAPI(ctx, w)
		if err != nil {
			return httpio.NewEncoder(w).ClientMessage(ctx, err)
		}

		return httpio.NewEncoder(w).Ok(EndImpersonationResponse{Restored: restored})
	})
}

// EndImpersonationAPI ends the impersonated session in ctx: the session row is expired
// and the record ends with reason Released, in one storage transaction, and the end is
// announced as an Ended event. For a local actor whose source session is still live,
// not itself impersonated, and still theirs, the response is given that session's
// cookies, so the actor is back in their own session without logging in; restored
// reports whether that happened. A context whose session is not impersonated is
// refused.
func (s *BaseSession) EndImpersonationAPI(ctx context.Context, w http.ResponseWriter) (restored bool, err error) {
	ctx, span := tracer.Start(ctx)
	defer span.End()

	sessData, ok := ctx.Value(sessioninfo.CtxSessionInfo).(*sessioninfo.SessionData)
	if !ok || sessData.Impersonation == nil {
		return false, httpio.NewBadRequestMessage("the session is not impersonated")
	}
	imp := sessData.Impersonation

	// One transaction: a session must never be left with an ended record and a live
	// row, which would validate while ActiveImpersonations no longer lists it.
	if err := s.Storage.DestroyImpersonatedSession(ctx, sessData.ID, sessioninfo.ImpersonationEndedByRelease); err != nil {
		return false, errors.Wrap(err, "sessionstorage.BaseStore.DestroyImpersonatedSession()")
	}

	now := time.Now()
	imp.EndedAt = &now
	imp.EndReason = sessioninfo.ImpersonationEndedByRelease
	if err := s.EmitImpersonationEvent(ctx, sessioninfo.ImpersonationEnded, imp, ""); err != nil {
		logger.FromCtx(ctx).Error(err)
	}

	src, ok := s.restorableSource(ctx, imp)
	if !ok {
		return false, nil
	}

	s.CookieHandler.NewAuthCookie(w, true, src.ID)
	s.CookieHandler.CreateXSRFTokenCookie(w, src.ID)
	logger.FromCtx(ctx).AddRequestAttribute("RestoredSessionId", src.ID)

	return true, nil
}

// restorableSource loads a local actor's own session and reports whether they can be
// returned to it: it is live, not itself impersonated, and still carries the actor's
// username. A foreign actor's session lives in another application.
func (s *BaseSession) restorableSource(ctx context.Context, imp *sessioninfo.Impersonation) (*sessioninfo.SessionData, bool) {
	if !imp.IsLocalActor() || !imp.SourceSessionID.Valid {
		return nil, false
	}

	src, err := s.Storage.Session(ctx, imp.SourceSessionID.UUID)
	if err != nil {
		if !httpio.HasNotFound(err) {
			logger.FromCtx(ctx).Error(errors.Wrap(err, "sessionstorage.BaseStore.Session()"))
		}

		return nil, false
	}
	if !s.live(src) || src.Impersonation != nil || src.Username != imp.Actor {
		return nil, false
	}

	return src, true
}

// DestroyImpersonatedSessions expires every live impersonated session established by
// actor and ends their records with reason Revoked. It errors when the storage has no
// impersonation table.
func (s *BaseSession) DestroyImpersonatedSessions(ctx context.Context, actor string) error {
	if !s.Storage.ImpersonationEnabled() {
		return ErrImpersonationNotConfigured
	}

	if err := s.Storage.DestroyImpersonatedSessions(ctx, actor); err != nil {
		return errors.Wrap(err, "sessionstorage.BaseStore.DestroyImpersonatedSessions()")
	}

	return nil
}

// ImpersonationResponse is the impersonation portion of the Authenticated response,
// present only for an impersonated session so a frontend can banner it and render
// read-only affordances.
type ImpersonationResponse struct {
	Actor         string    `json:"actor"`
	ActorRealm    string    `json:"actorRealm,omitempty"`
	PrincipalKind string    `json:"principalKind"`
	Principal     string    `json:"principal"`
	Mask          []string  `json:"mask,omitempty"`
	Reason        string    `json:"reason,omitempty"`
	ExpiresAt     time.Time `json:"expiresAt"`
}

// NewImpersonationResponse renders the record for the Authenticated response; nil in,
// nil out. Mask is omitted for an unrestricted session.
func NewImpersonationResponse(imp *sessioninfo.Impersonation) *ImpersonationResponse {
	if imp == nil {
		return nil
	}

	res := &ImpersonationResponse{
		Actor:         imp.Actor,
		ActorRealm:    imp.ActorRealm,
		PrincipalKind: imp.PrincipalKind(),
		Principal:     imp.PrincipalName(),
		Reason:        imp.Reason,
		ExpiresAt:     imp.ExpiresAt,
	}
	if perms := imp.Mask.Permissions(); perms != nil {
		res.Mask = make([]string, len(perms))
		for i, perm := range perms {
			res.Mask[i] = string(perm)
		}
	}

	return res
}

// EmitImpersonationEvent logs a lifecycle event of an impersonated session with the
// record's evidence attributes, records it as an event on the current trace span, and
// delivers it to the audit hook when one is configured. It returns the hook's error, if
// any; the log line and span event are written regardless.
func (s *BaseSession) EmitImpersonationEvent(ctx context.Context, kind sessioninfo.ImpersonationEventKind, imp *sessioninfo.Impersonation, operation string) error {
	addImpersonationSpanEvent(ctx, kind, imp, operation)

	attrs := logger.FromCtx(ctx).WithAttributes()
	for _, a := range imp.Attributes() {
		attrs = attrs.AddAttribute(a.Key, a.Value)
	}
	attrs = attrs.AddAttribute("impersonation.event", string(kind))
	if operation != "" {
		attrs = attrs.AddAttribute("impersonation.operation", operation)
	}
	if imp.EndReason != "" {
		attrs = attrs.AddAttribute("impersonation.end_reason", string(imp.EndReason))
	}

	switch kind {
	case sessioninfo.ImpersonationIdentityOperationBlocked, sessioninfo.ImpersonationWriteBlocked:
		attrs.Logger().Warnf("impersonation: %s refused for %s", operation, imp.Principal)
	case sessioninfo.ImpersonationStarted, sessioninfo.ImpersonationEnded:
		attrs.Logger().Infof("impersonation %s: %s as %s", kind, imp.Actor, imp.Principal)
	default:
		attrs.Logger().Infof("impersonation %s", kind)
	}

	if s.ImpersonationAudit == nil {
		return nil
	}

	event := sessioninfo.ImpersonationEvent{Kind: kind, Impersonation: imp, Operation: operation, At: time.Now()}
	if err := s.ImpersonationAudit(ctx, event); err != nil {
		return errors.Wrapf(err, "impersonation audit hook (%s)", kind)
	}

	return nil
}

// DestroyImpersonatedSession ends one live impersonated session: the session row is
// expired and the record ended with reason Revoked, in one transaction — the
// single-session form of DestroyImpersonatedSessions. The next request on that session
// is refused as expired. A session that is not impersonated, or whose record has already
// ended, is left untouched. It errors when the storage has no impersonation table.
func (s *BaseSession) DestroyImpersonatedSession(ctx context.Context, sessionID ccc.UUID) error {
	if !s.Storage.ImpersonationEnabled() {
		return ErrImpersonationNotConfigured
	}

	if err := s.Storage.DestroyImpersonatedSession(ctx, sessionID, sessioninfo.ImpersonationEndedByRevocation); err != nil {
		return errors.Wrap(err, "sessionstorage.BaseStore.DestroyImpersonatedSession()")
	}

	return nil
}

// ActiveImpersonations lists the impersonated sessions that are live right now,
// newest first: their record has not ended, their hard cap has not passed, their
// session row is not expired, and the session has seen activity within the idle
// session timeout. q narrows the listing; nil lists every active impersonation. It
// errors when the storage has no impersonation table.
func (s *BaseSession) ActiveImpersonations(ctx context.Context, q *sessioninfo.ImpersonationQuery) ([]*sessioninfo.Impersonation, error) {
	ctx, span := tracer.Start(ctx)
	defer span.End()

	if !s.Storage.ImpersonationEnabled() {
		return nil, ErrImpersonationNotConfigured
	}
	if q == nil {
		q = &sessioninfo.ImpersonationQuery{}
	}

	imps, err := s.Storage.ActiveImpersonations(ctx, time.Now().Add(-s.SessionTimeout), q)
	if err != nil {
		return nil, errors.Wrap(err, "sessionstorage.BaseStore.ActiveImpersonations()")
	}

	return imps, nil
}

// EnforceReadOnlyMask refuses non-safe requests (anything but GET, HEAD, OPTIONS and
// TRACE) from an impersonated session whose mask is read-only — a mask allowing nothing
// beyond List and Read — with 403 Forbidden, evidenced as a WriteBlocked event. Every
// other request, including every request of a session that is not impersonated or not
// masked, passes through. It runs after ValidateSession; without a validated session in
// the context it passes the request through.
//
// The middleware is a coarse, opt-in backstop: it stops a read-only session from
// reaching any mutating handler regardless of whether that handler consults the mask.
// It is not a substitute for honoring the mask in permission checks (Execute reaches
// handlers by POST, and a session masked to Execute is not read-only).
func (s *BaseSession) EnforceReadOnlyMask(next http.Handler) http.Handler {
	return s.Handle(func(w http.ResponseWriter, r *http.Request) error {
		ctx := r.Context()

		if !internalcookie.SafeMethods.Contain(r.Method) {
			if sessData, ok := ctx.Value(sessioninfo.CtxSessionInfo).(*sessioninfo.SessionData); ok && sessData.Impersonation != nil && readOnlyMask(sessData.Impersonation.Mask) {
				operation := r.Method + " " + r.URL.Path
				if err := s.EmitImpersonationEvent(ctx, sessioninfo.ImpersonationWriteBlocked, sessData.Impersonation, operation); err != nil {
					logger.FromCtx(ctx).Error(err)
				}

				return httpio.NewEncoder(w).ClientMessage(ctx, httpio.NewForbiddenMessage("this session is read-only"))
			}
		}

		next.ServeHTTP(w, r)

		return nil
	})
}

// readOnlyMask reports whether mask is read-only: restricted, and allowing nothing
// beyond List and Read. The unrestricted mask is not read-only; the mask that allows
// nothing is.
func readOnlyMask(mask accesstypes.PermissionMask) bool {
	if mask.IsZero() {
		return false
	}
	for _, perm := range mask.Permissions() {
		if perm != accesstypes.List && perm != accesstypes.Read {
			return false
		}
	}

	return true
}

// endImpersonation records an observed end of an impersonated session — an expiry
// noticed at validation — on its record and announces it. Failures are logged, never
// returned: the session is already being refused, and the record is evidence rather
// than a gate.
func (s *BaseSession) endImpersonation(ctx context.Context, sessData *sessioninfo.SessionData, reason sessioninfo.ImpersonationEndReason) {
	imp := sessData.Impersonation
	if imp == nil || imp.EndedAt != nil {
		return
	}

	if err := s.Storage.EndImpersonation(ctx, imp.SessionID, reason); err != nil {
		logger.FromCtx(ctx).Error(errors.Wrap(err, "sessionstorage.BaseStore.EndImpersonation()"))

		return
	}

	now := time.Now()
	imp.EndedAt = &now
	imp.EndReason = reason
	if err := s.EmitImpersonationEvent(ctx, sessioninfo.ImpersonationEnded, imp, ""); err != nil {
		logger.FromCtx(ctx).Error(err)
	}
}

// LogoutAPI destroys the session in ctx. For an impersonated session that this
// request validated, the record's end (written by DestroySession as Logout) is
// announced as an Ended event.
func (s *BaseSession) LogoutAPI(ctx context.Context) error {
	if err := s.Storage.DestroySession(ctx, sessioninfo.IDFromCtx(ctx)); err != nil {
		return errors.Wrap(err, "sessionstorage.BaseStore.DestroySession()")
	}

	sessData, ok := ctx.Value(sessioninfo.CtxSessionInfo).(*sessioninfo.SessionData)
	if !ok || sessData.Impersonation == nil || sessData.Impersonation.EndedAt != nil {
		return nil
	}

	now := time.Now()
	sessData.Impersonation.EndedAt = &now
	sessData.Impersonation.EndReason = sessioninfo.ImpersonationEndedByLogout
	if err := s.EmitImpersonationEvent(ctx, sessioninfo.ImpersonationEnded, sessData.Impersonation, ""); err != nil {
		logger.FromCtx(ctx).Error(err)
	}

	return nil
}

// impersonationExpired reports whether an impersonated session's hard cap has passed.
func impersonationExpired(sessData *sessioninfo.SessionData) bool {
	return sessData.Impersonation != nil && !time.Now().Before(sessData.Impersonation.ExpiresAt)
}

// impersonationEnded reports whether an impersonated session's record has ended. The
// record is the authority: a session whose record has ended is over even if its row
// was not expired with it, so no ended-but-live session can keep validating while
// ActiveImpersonations no longer lists it.
func impersonationEnded(sessData *sessioninfo.SessionData) bool {
	return sessData.Impersonation != nil && sessData.Impersonation.EndedAt != nil
}
