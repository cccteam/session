package oidc

import (
	"context"
	"net/http"
	"net/http/httptest"
	"reflect"
	"testing"

	"github.com/cccteam/ccc"
	"github.com/cccteam/session/sessioninfo"
)

func Test_sessionInfoFromRequest(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name string
		r    *http.Request
		want *sessioninfo.SessionInfo
	}{
		{
			name: "does not find session info in request",
			r:    httptest.NewRequest(http.MethodGet, "/testPath", http.NoBody),
		},
		{
			name: "gets session info from request",
			r: func() *http.Request {
				req := httptest.NewRequest(http.MethodGet, "/testPath", http.NoBody)
				req = req.WithContext(context.WithValue(context.Background(), sessioninfo.CtxSessionInfo, &sessioninfo.SessionInfo{ID: ccc.Must(ccc.UUIDFromString("de6e1a12-2d4d-4c4d-aaf1-d82cb9a9eff5"))}))
				return req
			}(),
			want: &sessioninfo.SessionInfo{ID: ccc.Must(ccc.UUIDFromString("de6e1a12-2d4d-4c4d-aaf1-d82cb9a9eff5"))},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			if got := sessioninfo.FromRequest(tt.r); !reflect.DeepEqual(got, tt.want) {
				t.Errorf("sessionInfoFromRequest() = %v, want %v", got, tt.want)
			}
		})
	}
}
