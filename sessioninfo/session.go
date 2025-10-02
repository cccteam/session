package sessioninfo

import (
	"context"
	"net/http"

	"github.com/cccteam/logger"
)

// ctxKey is a type for storing values in the request context
type ctxKey string

const (
	// CtxSessionInfo is the key used to store the SessionInfo in the context.
	CtxSessionInfo ctxKey = "sessionInfo"
)

// FromRequest returns the session information from the request context.
func FromRequest(r *http.Request) *SessionInfo {
	sessionInfo, ok := r.Context().Value(CtxSessionInfo).(*SessionInfo)
	if !ok {
		logger.Req(r).Errorf("failed to find %s in request context", CtxSessionInfo)
	}

	return sessionInfo
}

// FromCtx returns the session information from the context.
func FromCtx(ctx context.Context) *SessionInfo {
	sessionInfo, ok := ctx.Value(CtxSessionInfo).(*SessionInfo)
	if !ok {
		logger.Ctx(ctx).Errorf("failed to find %s in request context", CtxSessionInfo)
	}

	return sessionInfo
}
