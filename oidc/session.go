package oidc

import (
	"net/http"

	"github.com/cccteam/logger"
	"github.com/cccteam/session/sessiontypes"
)

type ctxKey string

const (
	CtxSessionInfo ctxKey = "sessionInfo"
)

func SessionInfoFromRequest(r *http.Request) *sessiontypes.SessionInfo {
	sessionInfo, ok := r.Context().Value(CtxSessionInfo).(*sessiontypes.SessionInfo)
	if !ok {
		logger.Req(r).Errorf("failed to find %s in request context", CtxSessionInfo)
	}

	return sessionInfo
}
