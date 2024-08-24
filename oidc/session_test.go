package oidc

import (
	"context"
	"net/http"
	"net/http/httptest"
	"reflect"
	"testing"

	"github.com/cccteam/ccc"
	"github.com/cccteam/session/sessiontypes"
)

func Test_sessionInfoFromRequest(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name string
		r    *http.Request
		want *sessiontypes.SessionInfo
	}{
		{
			name: "does not find session info in request",
			r:    httptest.NewRequest(http.MethodGet, "/testPath", http.NoBody),
		},
		{
			name: "gets session info from request",
			r: func() *http.Request {
				req := httptest.NewRequest(http.MethodGet, "/testPath", http.NoBody)
				req = req.WithContext(context.WithValue(context.Background(), CtxSessionInfo, &sessiontypes.SessionInfo{ID: ccc.UUIDMustParse("de6e1a12-2d4d-4c4d-aaf1-d82cb9a9eff5")}))
				return req
			}(),
			want: &sessiontypes.SessionInfo{ID: ccc.UUIDMustParse("de6e1a12-2d4d-4c4d-aaf1-d82cb9a9eff5")},
		},
	}
	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			if got := SessionInfoFromRequest(tt.r); !reflect.DeepEqual(got, tt.want) {
				t.Errorf("sessionInfoFromRequest() = %v, want %v", got, tt.want)
			}
		})
	}
}
