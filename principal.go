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
type PrincipalResolver = func(ctx context.Context) (accesstypes.Principal, error)

// WithPrincipalResolver installs the resolver that chooses each validated request's
// authorization subject (sessioninfo.PrincipalFromCtx). It is the seam for a session
// whose subject is not its user — a partner portal whose sessions act as the role held
// in custom session data, for instance — without an impersonation record and without
// storing anything: the choice is made per request at validation time.
//
// The resolver runs for ordinary sessions and for user-principal impersonations (so an
// impersonated user's session acts as that user would); a role-principal impersonation
// already names its subject and skips it. When the resolver changes the principal the
// choice is stamped on the request's log entry as principal.kind and principal
// (sessioninfo.AttrPrincipalKind, sessioninfo.AttrPrincipal).
func WithPrincipalResolver(resolve PrincipalResolver) BaseSessionOption {
	return func(b *basesession.BaseSession) {
		b.PrincipalResolver = resolve
	}
}
