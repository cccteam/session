package sessioninfo

import (
	"context"
	"fmt"
	"net/http"

	"github.com/cccteam/ccc"
	"github.com/cccteam/httpio"
	"github.com/go-playground/errors/v5"
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
	sessionData, ok := ctx.Value(CtxSessionInfo).(*SessionData)
	if !ok {
		panic(fmt.Sprintf("failed to find %s in request context", CtxSessionInfo))
	}

	return sessionData.SessionInfo
}

// IDFromRequest returns the sessionID from the request
func IDFromRequest(r *http.Request) ccc.UUID {
	return IDFromCtx(r.Context())
}

// IDFromCtx returns the sessionID from the request context
func IDFromCtx(ctx context.Context) ccc.UUID {
	id, ok := ctx.Value(CTXSessionID).(ccc.UUID)
	if !ok {
		panic(fmt.Sprintf("failed to find %s in request context", CTXSessionID))
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

// CustomDataFromRequest returns the strongly typed custom session data from the request context.
// T must match the type used in WithCustomSessionDataTable.
func CustomDataFromRequest[T any](r *http.Request) (T, error) {
	return CustomDataFromCtx[T](r.Context())
}

// CustomDataFromCtx returns the strongly typed custom session data from the context.
// T must match the type used in WithCustomSessionDataTable.
func CustomDataFromCtx[T any](ctx context.Context) (T, error) {
	var zeroVal T

	sess, ok := ctx.Value(CtxSessionInfo).(*SessionData)
	if !ok {
		panic(fmt.Sprintf("failed to find %s in request context", CtxSessionInfo))
	}

	if sess.CustomData == nil {
		return zeroVal, errors.New("no custom session data found in context")
	}

	v, ok := sess.CustomData.(T)
	if !ok {
		return zeroVal, httpio.NewBadRequestMessagef("custom session data type mismatch: want %T, got %T", zeroVal, sess.CustomData)
	}

	return v, nil
}
