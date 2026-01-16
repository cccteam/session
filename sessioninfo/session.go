package sessioninfo

import (
	"context"
	"fmt"
	"net/http"

	"github.com/cccteam/ccc"
	"github.com/cccteam/logger"
)

// CTXKey is a type for storing values in the request context
type CTXKey string

const (
	// CtxSessionInfo is the key used to store the SessionInfo in the context.
	CtxSessionInfo CTXKey = "sessionInfo"
	// CtxUserInfo is the key used to store the UserInfo in the context.
	CtxUserInfo CTXKey = "userInfo"

	// CTXSessionID is the key for storing SessionID in context
	CTXSessionID CTXKey = "sessionID"
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

// IDFromRequest returns the sessionID from the request
func IDFromRequest(r *http.Request) ccc.UUID {
	return IDFromCtx(r.Context())
}

// IDFromCtx returns the sessionID from the request context
func IDFromCtx(ctx context.Context) ccc.UUID {
	id, ok := ctx.Value(CTXSessionID).(ccc.UUID)
	if !ok {
		logger.FromCtx(ctx).Errorf("failed to find %s in request context", CTXSessionID)
	}

	return id
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
