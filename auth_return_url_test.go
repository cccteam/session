package session

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"

	"github.com/cccteam/ccc"
	"github.com/cccteam/session/internal/workos"
	"github.com/cccteam/session/sessioninfo"
	"github.com/cccteam/session/signin"
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

// returnURLFixture is an Auth with WorkOS sign-in registered over the real WorkOS client,
// whose code exchange a fake WorkOS answers with one profile.
type returnURLFixture struct {
	*authFixture
	sso    *workos.Method
	client *workos.Client
	// identity is the WorkOS identity the method's resolver was last given.
	identity *workos.Identity
}

func newReturnURLFixture(t *testing.T, ctrl *gomock.Controller) *returnURLFixture {
	t.Helper()

	fake := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.Copy(io.Discard, r.Body)
		_, _ = io.WriteString(w, `{"profile":{"id":"prof_1","idp_id":"idp_1","connection_id":"conn_1","organization_id":"org_1","email":"pat@lakeside.edu"}}`)
	}))
	t.Cleanup(fake.Close)

	f := &returnURLFixture{authFixture: newAuthFixture(t, ctrl)}
	f.client = workos.NewClient(f.auth.cookies.ForRegistration("workos"), "sk", "client", "https://app/sso/callback")
	f.client.SetBaseURL(fake.URL)
	f.sso = workos.SignIn(f.auth, "workos", func(_ context.Context, _ mockTx, identity *workos.Identity) (*signin.Resolution, error) {
		f.identity = identity

		return signin.Provision(&signin.NewUser{Username: identity.Email}, nil), nil
	}, &workos.Config{Authenticator: f.client})

	return f
}

// callback runs the WorkOS callback of a login whose state cookie carries returnURL as
// it was stored, as a login before this check, or a forged state, would leave it.
func (f *returnURLFixture) callback(t *testing.T, returnURL string) *httptest.ResponseRecorder {
	t.Helper()

	started := httptest.NewRecorder()
	authURL, err := f.client.AuthorizationURL(context.Background(), started, "org_1", returnURL)
	if err != nil {
		t.Fatalf("AuthorizationURL() error = %v", err)
	}
	u, err := url.Parse(authURL)
	if err != nil {
		t.Fatalf("url.Parse() error = %v", err)
	}

	return f.serve(f.sso.Callback(), http.MethodGet, "/sso/callback?code=c&state="+url.QueryEscape(u.Query().Get("state")), nil, started.Result().Cookies())
}

// TestAuth_ReturnURLStaysInTheApplication drives the external Login, Callback and
// pending flows with each off-site return URL and asserts on the raw Location header the
// handler emits, not a parsed URL: a redirect helper or the browser that normalizes the
// value after the sanitizer is what turns /./\evil.com into a redirect off-site.
func TestAuth_ReturnURLStaysInTheApplication(t *testing.T) {
	t.Parallel()

	for _, returnURL := range offSiteReturnURLs {
		t.Run(returnURL, func(t *testing.T) {
			t.Parallel()

			t.Run("the login refuses it with 400 and redirects nowhere", func(t *testing.T) {
				t.Parallel()
				f := newReturnURLFixture(t, gomock.NewController(t))

				rr := f.serve(f.sso.Login(), http.MethodGet, "/sso/login?organization=org_1&returnUrl="+url.QueryEscape(returnURL), nil, nil)

				if rr.Code != http.StatusBadRequest || rr.Header().Get("Location") != "" {
					t.Errorf("Login() = %d %q, want 400 and no Location", rr.Code, rr.Header().Get("Location"))
				}
			})

			t.Run("a callback that carries it signs in and returns to the root", func(t *testing.T) {
				t.Parallel()
				f := newReturnURLFixture(t, gomock.NewController(t))
				f.expectSignIn(ccc.Must(ccc.NewUUID()), nil, func(req *sessioninfo.NewSessionRequest) error {
					req.UserID, req.Username = ccc.Must(ccc.NewUUID()), "pat"

					return nil
				})

				rr := f.callback(t, returnURL)

				if loc := rr.Header().Values("Location"); rr.Code != http.StatusFound || len(loc) != 1 || loc[0] != "/" {
					t.Errorf("Callback() = %d %q, want 302 exactly \"/\"", rr.Code, loc)
				}
			})

			t.Run("a callback that carries it and becomes pending names no return URL", func(t *testing.T) {
				t.Parallel()
				f := newReturnURLFixture(t, gomock.NewController(t))
				f.expectSignIn(ccc.Must(ccc.NewUUID()), nil, func(*sessioninfo.NewSessionRequest) error {
					return &signin.PendingSignInError{Reason: sessioninfo.PendingConfirmation, UserID: ccc.NullUUIDFromUUID(ccc.Must(ccc.NewUUID())), Username: "pat"}
				})
				f.expectHold("pat")

				rr := f.callback(t, returnURL)

				if rr.Code != http.StatusFound || rr.Header().Get("Location") != "/login?pending=confirmation" {
					t.Errorf("Callback() = %d %q, want 302 exactly \"/login?pending=confirmation\"", rr.Code, rr.Header().Get("Location"))
				}

				status := f.serve(f.auth.Pending().Status(), http.MethodGet, "/pending", nil, rr.Result().Cookies())
				var body struct {
					ReturnURL string `json:"returnUrl"`
				}
				if err := json.Unmarshal(status.Body.Bytes(), &body); err != nil || status.Code != http.StatusOK || body.ReturnURL != "/" {
					t.Errorf("Status() = %d %s, want 200 with returnUrl \"/\"", status.Code, status.Body.String())
				}
			})
		})
	}
}

// TestAuth_ReturnURLInTheApplication is the other half: a return URL in the application,
// with its query and fragment, reaches the Location header and the pending status
// byte for byte.
func TestAuth_ReturnURLInTheApplication(t *testing.T) {
	t.Parallel()

	for _, returnURL := range []string{"/reports", "/settings/single-sign-on?test=done", "/reports#x", "/a/b?x=1#y", "/settings/"} {
		t.Run(returnURL, func(t *testing.T) {
			t.Parallel()

			t.Run("a sign-in returns to it", func(t *testing.T) {
				t.Parallel()
				f := newReturnURLFixture(t, gomock.NewController(t))

				login := f.serve(f.sso.Login(), http.MethodGet, "/sso/login?organization=org_1&returnUrl="+url.QueryEscape(returnURL), nil, nil)
				if login.Code != http.StatusFound {
					t.Fatalf("Login() = %d, want 302", login.Code)
				}
				f.expectSignIn(ccc.Must(ccc.NewUUID()), nil, func(req *sessioninfo.NewSessionRequest) error {
					req.UserID, req.Username = ccc.Must(ccc.NewUUID()), "pat"

					return nil
				})

				rr := f.callback(t, returnURL)

				if rr.Code != http.StatusFound || rr.Header().Get("Location") != returnURL {
					t.Errorf("Callback() = %d %q, want 302 exactly %q", rr.Code, rr.Header().Get("Location"), returnURL)
				}
			})

			t.Run("a pending sign-in carries it", func(t *testing.T) {
				t.Parallel()
				f := newReturnURLFixture(t, gomock.NewController(t))
				f.expectSignIn(ccc.Must(ccc.NewUUID()), nil, func(*sessioninfo.NewSessionRequest) error {
					return &signin.PendingSignInError{Reason: sessioninfo.PendingMFA, UserID: ccc.NullUUIDFromUUID(ccc.Must(ccc.NewUUID())), Username: "pat"}
				})
				f.expectHold("pat")

				rr := f.callback(t, returnURL)

				want := "/login?" + url.Values{"pending": {"mfa"}, "returnUrl": {returnURL}}.Encode()
				if rr.Code != http.StatusFound || rr.Header().Get("Location") != want {
					t.Errorf("Callback() = %d %q, want 302 exactly %q", rr.Code, rr.Header().Get("Location"), want)
				}
				status := f.serve(f.auth.Pending().Status(), http.MethodGet, "/pending", nil, rr.Result().Cookies())
				var body struct {
					ReturnURL string `json:"returnUrl"`
				}
				if err := json.Unmarshal(status.Body.Bytes(), &body); err != nil || body.ReturnURL != returnURL {
					t.Errorf("Status() = %d %s, want returnUrl %q", status.Code, status.Body.String(), returnURL)
				}
			})
		})
	}
}
