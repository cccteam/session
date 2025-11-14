package sessioninfo

import (
	"context"
	"net/http"
	"net/http/httptest"
	"reflect"
	"testing"

	"github.com/cccteam/ccc"
)

func Test_sessionInfoFromRequest(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name string
		r    *http.Request
		want *SessionInfo
	}{
		{
			name: "does not find session info in request",
			r:    httptest.NewRequest(http.MethodGet, "/testPath", http.NoBody),
			want: nil,
		},
		{
			name: "gets session info from request",
			r: func() *http.Request {
				req := httptest.NewRequest(http.MethodGet, "/testPath", http.NoBody)
				req = req.WithContext(context.WithValue(context.Background(), CtxSessionInfo, &SessionInfo{ID: ccc.Must(ccc.UUIDFromString("de6e1a12-2d4d-4c4d-aaf1-d82cb9a9eff5"))}))

				return req
			}(),
			want: &SessionInfo{ID: ccc.Must(ccc.UUIDFromString("de6e1a12-2d4d-4c4d-aaf1-d82cb9a9eff5"))},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			if got := FromRequest(tt.r); !reflect.DeepEqual(got, tt.want) {
				t.Errorf("FromRequest() = %v, want %v", got, tt.want)
			}
			if got := FromCtx(tt.r.Context()); !reflect.DeepEqual(got, tt.want) {
				t.Errorf("FromCtx() = %v, want %v", got, tt.want)
			}
		})
	}
}
