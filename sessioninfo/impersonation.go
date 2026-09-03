package sessioninfo

import (
	"context"
	"fmt"
	"net/http"
	"time"

	"github.com/cccteam/ccc"
	"github.com/cccteam/ccc/accesstypes"
)

// Impersonation is the record of an impersonated session: who established it
// (the actor), what it operates as (the principal), and how it is attenuated
// (the mask). Its presence is what marks a session as impersonated. The
// session's effective identity — SessionInfo.Username — is the impersonated
// user for a user principal and the actor for a role principal, so every
// consumer that reads the session sees exactly what it would see had that
// identity logged in; the actor is recoverable from this record alone.
type Impersonation struct {
	// SessionID is the impersonated session — the record's key, and the value
	// every piece of evidence carries under AttrImpersonationSessionID.
	SessionID ccc.UUID
	// Actor is the authenticated real user the session acts on behalf of.
	Actor string
	// ActorRealm names the application or identity provider that authenticated
	// the actor, when it differs from this application (e.g. "admin-portal").
	ActorRealm string
	// SourceSessionID is the actor's session in the source application, when
	// known, for cross-application correlation.
	SourceSessionID ccc.NullUUID
	// Principal is the authorization subject the session evaluates against.
	Principal accesstypes.Principal
	// Mask is the permission allowlist the session is attenuated by; the zero
	// mask is unrestricted.
	Mask accesstypes.PermissionMask
	// Reason is the free-text justification supplied when the session was
	// established (a ticket reference, a support note); empty when none was.
	Reason string
	// StartedAt is when the session was established.
	StartedAt time.Time
	// ExpiresAt is the hard cap: the session is expired once this instant
	// passes, regardless of activity.
	ExpiresAt time.Time
	// EndedAt is when the end of the session was observed (logout, revocation,
	// or expiry noticed at validation); nil while the session is live or if it
	// expired unobserved.
	EndedAt *time.Time
	// EndReason says how the session ended; empty while EndedAt is nil.
	EndReason ImpersonationEndReason
}

// ImpersonationEndReason says how an impersonated session ended.
type ImpersonationEndReason string

const (
	// ImpersonationEndedByLogout is a session the actor logged out of.
	ImpersonationEndedByLogout ImpersonationEndReason = "Logout"
	// ImpersonationEndedByRevocation is a session ended administratively
	// (DestroyImpersonatedSessions).
	ImpersonationEndedByRevocation ImpersonationEndReason = "Revoked"
	// ImpersonationEndedByExpiry is a session whose hard cap or idle timeout
	// passed, observed when the next request was validated.
	ImpersonationEndedByExpiry ImpersonationEndReason = "Expired"
)

// Canonical attribute keys for impersonation evidence. Session validation
// stamps them onto the request logger (the request-level entry and every
// line logged within the request); applications, dashboards and alerting
// should reference these constants rather than respell them.
const (
	// AttrImpersonationActor is the real user acting.
	AttrImpersonationActor = "impersonation.actor"
	// AttrImpersonationActorRealm is the application or IdP that authenticated the actor.
	AttrImpersonationActorRealm = "impersonation.actor_realm"
	// AttrImpersonationPrincipalKind is "User" or "Role".
	AttrImpersonationPrincipalKind = "impersonation.principal_kind"
	// AttrImpersonationPrincipal is the impersonated user or role name.
	AttrImpersonationPrincipal = "impersonation.principal"
	// AttrImpersonationMask is the permission allowlist, "unrestricted" when none.
	AttrImpersonationMask = "impersonation.mask"
	// AttrImpersonationSessionID is the impersonated session's ID — the record's key.
	AttrImpersonationSessionID = "impersonation.session_id"
	// AttrImpersonationSourceSessionID is the actor's session in the source application, when known.
	AttrImpersonationSourceSessionID = "impersonation.source_session_id"

	// AttrPrincipalKind is "User" or "Role": the kind of the principal a configured
	// resolver chose for the request, stamped only when it differs from the default.
	AttrPrincipalKind = "principal.kind"
	// AttrPrincipal is the name of the principal a configured resolver chose for the
	// request, stamped only when it differs from the default.
	AttrPrincipal = "principal"
)

// Principal kinds as rendered for evidence and storage.
const (
	// PrincipalKindUser is an impersonated user.
	PrincipalKindUser = "User"
	// PrincipalKindRole is an impersonated role.
	PrincipalKindRole = "Role"
)

// PrincipalKind renders the principal's kind for evidence and storage:
// PrincipalKindUser or PrincipalKindRole.
func (i *Impersonation) PrincipalKind() string {
	if i.Principal.IsRole() {
		return PrincipalKindRole
	}

	return PrincipalKindUser
}

// PrincipalName renders the impersonated user or role name for evidence.
func (i *Impersonation) PrincipalName() string {
	if role, ok := i.Principal.Role(); ok {
		return string(role)
	}
	user, _ := i.Principal.User()

	return string(user)
}

// Attributes returns the record's evidence as canonical key/value pairs, in
// a stable order, for stamping onto loggers, spans, and events.
func (i *Impersonation) Attributes() []Attribute {
	attrs := []Attribute{
		{Key: AttrImpersonationActor, Value: i.Actor},
		{Key: AttrImpersonationPrincipalKind, Value: i.PrincipalKind()},
		{Key: AttrImpersonationPrincipal, Value: i.PrincipalName()},
		{Key: AttrImpersonationMask, Value: i.Mask.String()},
		{Key: AttrImpersonationSessionID, Value: i.SessionID.String()},
	}
	if i.ActorRealm != "" {
		attrs = append(attrs, Attribute{Key: AttrImpersonationActorRealm, Value: i.ActorRealm})
	}
	if i.SourceSessionID.Valid {
		attrs = append(attrs, Attribute{Key: AttrImpersonationSourceSessionID, Value: i.SourceSessionID.String()})
	}

	return attrs
}

// Attribute is one key/value pair of impersonation evidence.
type Attribute struct {
	Key   string
	Value string
}

// ImpersonationEventKind identifies a lifecycle event of an impersonated session.
type ImpersonationEventKind string

const (
	// ImpersonationStarted fires when an impersonated session is established.
	ImpersonationStarted ImpersonationEventKind = "Started"
	// ImpersonationEnded fires when the end of an impersonated session is
	// observed; the record's EndReason says how.
	ImpersonationEnded ImpersonationEventKind = "Ended"
	// ImpersonationIdentityOperationBlocked fires when an impersonated
	// session attempts an identity operation the library refuses (a password
	// or username change on the impersonated user, or user management under
	// a mask); Operation names the handler.
	ImpersonationIdentityOperationBlocked ImpersonationEventKind = "IdentityOperationBlocked"
	// ImpersonationWriteBlocked fires when a read-only impersonated session
	// attempts a non-safe HTTP request that the EnforceReadOnlyMask middleware
	// refuses; Operation is the method and path ("POST /api/partners").
	ImpersonationWriteBlocked ImpersonationEventKind = "WriteBlocked"
)

// ImpersonationEvent is delivered to the application's audit hook for each
// lifecycle event of an impersonated session.
type ImpersonationEvent struct {
	Kind          ImpersonationEventKind
	Impersonation *Impersonation
	// Operation names what was refused: the handler for IdentityOperationBlocked, the
	// method and path for WriteBlocked; empty otherwise.
	Operation string
	At        time.Time
}

// ImpersonationFromRequest returns the impersonation record from the request
// context and true, or nil and false for a session that is not impersonated.
// It panics when no session is in the context, like FromRequest.
func ImpersonationFromRequest(r *http.Request) (*Impersonation, bool) {
	return ImpersonationFromCtx(r.Context())
}

// ImpersonationFromCtx returns the impersonation record from the context and
// true, or nil and false for a session that is not impersonated. It panics
// when no session is in the context, like FromCtx.
func ImpersonationFromCtx(ctx context.Context) (*Impersonation, bool) {
	sess, ok := ctx.Value(CtxSessionInfo).(*SessionData)
	if !ok {
		panic(fmt.Sprintf("failed to find %s in request context", CtxSessionInfo))
	}
	if sess.Impersonation == nil {
		return nil, false
	}

	return sess.Impersonation, true
}

// PrincipalFromCtx returns the authorization subject of the session in the
// context: the principal a configured resolver chose for this request when it
// did; otherwise the impersonation record's principal for an impersonated
// session; otherwise the session user's own principal. Callers never branch on
// whether the session is impersonated, or on whether a resolver is configured,
// to obtain the subject. It panics when no session is in the context, like
// FromCtx.
func PrincipalFromCtx(ctx context.Context) accesstypes.Principal {
	sess, ok := ctx.Value(CtxSessionInfo).(*SessionData)
	if !ok {
		panic(fmt.Sprintf("failed to find %s in request context", CtxSessionInfo))
	}
	if sess.Principal != (accesstypes.Principal{}) {
		return sess.Principal
	}
	if sess.Impersonation != nil {
		return sess.Impersonation.Principal
	}

	return accesstypes.UserPrincipal(accesstypes.User(sess.Username))
}

// ActorFromCtx returns the real user behind the session in the context: the
// impersonation record's actor for an impersonated session, otherwise the
// session's username.
func ActorFromCtx(ctx context.Context) string {
	if imp, ok := ImpersonationFromCtx(ctx); ok {
		return imp.Actor
	}

	return FromCtx(ctx).Username
}

// MaskFromCtx returns the permission mask of the session in the context: the
// impersonation record's mask for an impersonated session, otherwise the
// unrestricted mask.
func MaskFromCtx(ctx context.Context) accesstypes.PermissionMask {
	if imp, ok := ImpersonationFromCtx(ctx); ok {
		return imp.Mask
	}

	return accesstypes.PermissionMask{}
}
