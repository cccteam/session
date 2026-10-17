package legacy

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/cccteam/session"
	"github.com/cccteam/session/mock/mock_azure"
	gomock "go.uber.org/mock/gomock"
)

// offSiteReturnURLs are return URLs a crafted login link could carry to send the browser
// off-site after sign-in, directly or once a redirect helper or the browser normalizes
// them (dot segments, backslashes, percent-encoded separators, control characters).
var offSiteReturnURLs = []string{
	"http://evil.com",
	"https://evil.com",
	"//evil.com",
	`/\evil.com`,
	`/./\evil.com`,
	`/a/../\evil.com`,
	"/.//evil.com",
	"/..//evil.com",
	"/%2F%2Fevil.com",
	"/%5Cevil.com",
	"/%2e/%5cevil.com",
	"/\tevil",
	"/ /evil.com",
	`\\evil.com`,
	"/%0d%0aSet-Cookie:x",
	"reports",
}

// TestOIDCCallback_ReturnURLStaysInTheApplication: the callback shell of the older OIDC
// session types writes the Location header from the verifier's return URL; it is exactly
// "/" for each off-site value, whatever the verifier returned.
func TestOIDCCallback_ReturnURLStaysInTheApplication(t *testing.T) {
	t.Parallel()

	for _, returnURL := range offSiteReturnURLs {
		t.Run(returnURL, func(t *testing.T) {
			t.Parallel()
			ctrl := gomock.NewController(t)
			p, err := NewPasswordAuth[session.NoCustomData, session.NoCustomData](newPasswordStoreMock(ctrl), cookieKey)
			if err != nil {
				t.Fatalf("NewPasswordAuth() error = %v", err)
			}
			authn := mock_azure.NewMockAuthenticator(ctrl)
			h := oidcCallback(p.baseSession, authn, func(context.Context, http.ResponseWriter, *http.Request) (string, error) {
				return returnURL, nil
			})

			rr := httptest.NewRecorder()
			h.ServeHTTP(rr, httptest.NewRequestWithContext(context.Background(), http.MethodGet, "/callback", http.NoBody))

			if loc := rr.Header().Values("Location"); rr.Code != http.StatusFound || len(loc) != 1 || loc[0] != "/" {
				t.Errorf("CallbackOIDC() = %d %q, want 302 exactly \"/\"", rr.Code, loc)
			}
		})
	}
}
