package sessioninfo

import (
	"net/http"

	"github.com/cccteam/logger"
)

type ctxKey string

const (
	CtxSessionInfo ctxKey = "sessionInfo"
)

func FromRequest(r *http.Request) *SessionInfo {
	sessionInfo, ok := r.Context().Value(CtxSessionInfo).(*SessionInfo)
	if !ok {
		logger.Req(r).Errorf("failed to find %s in request context", CtxSessionInfo)
	}

	return sessionInfo
}
