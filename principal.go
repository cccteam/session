package session

import (
	"context"

	"github.com/cccteam/ccc/accesstypes"
	"github.com/cccteam/session/internal/basesession"
)

// PrincipalResolver chooses the authorization subject of a validated request. It runs
// inside session validation with the session in ctx — sessioninfo.FromCtx, the custom
// session data (sessioninfo.CustomDataFromCtx) and the impersonation record are all
// available — and returns the principal the request evaluates permissions against.
// Returning the zero Principal keeps the default (the impersonation record's principal,
// or the session user's own). An error fails the request as a server error, not an
// unauthorized one: the session is valid; the application could not decide what it acts
// as.
//
// A resolver chooses which subject, never which grants: grants come from the permission
// store at check time. A resolver must therefore derive the subject from something live
// (the credential a machine session was established with, an external system read per
// request), never from role membership copied into the session at login — that freezes
// the user's role for the life of the session and defeats the store. Put membership in
// the permission store instead and let the default user principal apply.
type PrincipalResolver = func(ctx context.Context) (accesstypes.Principal, error)

// WithPrincipalResolver installs the resolver that chooses each validated request's
// authorization subject (sessioninfo.PrincipalFromCtx). It is the seam for the narrow
// case of a session whose subject genuinely is not a user — a service or API-key session
// acting as the role bound to its credential, or membership held in an external system
// and read live — without an impersonation record and without storing anything: the
// choice is made per request at validation time. It is not for a role snapshotted into
// custom session data, and not for a user choosing a role for one session (that is an
// impersonation record: evidenced, capped, revocable). See the README, "Choosing the
// principal".
//
// The resolver runs for ordinary sessions and for user-principal impersonations (so an
// impersonated user's session acts as that user would); a role-principal impersonation
// already names its subject and skips it. When the resolver changes the principal the
// choice is stamped on the request's log entry and trace span as principal.kind and
// principal (sessioninfo.AttrPrincipalKind, sessioninfo.AttrPrincipal).
func WithPrincipalResolver(resolve PrincipalResolver) BaseSessionOption {
	return func(b *basesession.BaseSession) {
		b.PrincipalResolver = resolve
	}
}
