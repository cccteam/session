package sessioninfo

import (
	"context"
	"fmt"
	"net/http"
)

// ctxKey is a type for storing values in the request context
type ctxKey string

const (
	// CtxSessionInfo is the key used to store the SessionInfo in the context.
	CtxSessionInfo ctxKey = "sessionInfo"
	// CtxUserInfo is the key used to store the UserInfo in the context.
	CtxUserInfo ctxKey = "userInfo"
)

// FromRequest returns the session information from the request context.
func FromRequest(r *http.Request) *SessionInfo {
	return FromCtx(r.Context())
}

// FromCtx returns the session information from the context.
func FromCtx(ctx context.Context) *SessionInfo {
	sessionInfo, ok := ctx.Value(CtxSessionInfo).(*SessionInfo)
	if !ok {
		panic(fmt.Sprintf("failed to find %s in request context", CtxSessionInfo))
	}

	return sessionInfo
}

// UserFromRequest returns the user information from the request context
func UserFromRequest(r *http.Request) *UserInfo {
	return UserFromCtx(r.Context())
}

// UserFromCtx returns the user information from the context
func UserFromCtx(ctx context.Context) *UserInfo {
	userInfo, ok := ctx.Value(CtxUserInfo).(*UserInfo)
	if !ok {
		panic(fmt.Sprintf("failed to find %s in request context", CtxUserInfo))
	}

	return userInfo
}
