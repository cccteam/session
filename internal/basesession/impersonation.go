package basesession

import (
	"context"
	"time"

	"github.com/cccteam/logger"
	"github.com/cccteam/session/sessioninfo"
	"github.com/go-playground/errors/v5"
)

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
// record's evidence attributes and delivers it to the audit hook when one is
// configured. It returns the hook's error, if any; the log line is written regardless.
func (s *BaseSession) EmitImpersonationEvent(ctx context.Context, kind sessioninfo.ImpersonationEventKind, imp *sessioninfo.Impersonation, operation string) error {
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
	case sessioninfo.ImpersonationIdentityOperationBlocked:
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
