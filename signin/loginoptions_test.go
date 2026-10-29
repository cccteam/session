package signin

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/cccteam/httpio"
)

func TestSelectAccount(t *testing.T) {
	t.Parallel()

	for _, tt := range []struct {
		name    string
		target  string
		want    bool
		wantErr bool
	}{
		{name: "no prompt asks for nothing", target: "/login"},
		{name: "an empty prompt asks for nothing", target: "/login?prompt="},
		{name: "select_account asks for the chooser", target: "/login?prompt=select_account", want: true},
		{name: "none is refused", target: "/login?prompt=none", wantErr: true},
		{name: "consent is refused", target: "/login?prompt=consent", wantErr: true},
		{name: "a list is refused", target: "/login?prompt=select_account+consent", wantErr: true},
	} {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			got, err := SelectAccount(httptest.NewRequestWithContext(t.Context(), http.MethodGet, tt.target, http.NoBody))
			if (err != nil) != tt.wantErr {
				t.Fatalf("SelectAccount() error = %v, wantErr %v", err, tt.wantErr)
			}
			if tt.wantErr && !httpio.HasBadRequest(err) {
				t.Errorf("SelectAccount() error = %v, want a 400", err)
			}
			if got != tt.want {
				t.Errorf("SelectAccount() = %v, want %v", got, tt.want)
			}
		})
	}
}
