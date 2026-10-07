package workossso

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/cccteam/httpio"
	internalcookie "github.com/cccteam/session/internal/cookie"
	"github.com/cccteam/session/internal/oidctest"
	"github.com/cccteam/session/sessioninfo"
)

// fakeWorkOS answers POST /sso/token with status and body, recording the last request.
type fakeWorkOS struct {
	server      *httptest.Server
	status      int
	body        string
	contentType string
	request     map[string]string
}

func newFakeWorkOS(t *testing.T) *fakeWorkOS {
	t.Helper()

	f := &fakeWorkOS{status: http.StatusOK}
	f.server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost || r.URL.Path != "/sso/token" {
			http.NotFound(w, r)

			return
		}
		f.contentType = r.Header.Get("Content-Type")
		raw, _ := io.ReadAll(r.Body)
		_ = json.Unmarshal(raw, &f.request)
		w.WriteHeader(f.status)
		_, _ = io.WriteString(w, f.body)
	}))
	t.Cleanup(f.server.Close)

	return f
}

const profileJSON = `{"id":"prof_1","idp_id":"pat@idp","connection_id":"conn_1","connection_type":"GenericSAML","organization_id":"org_1",` +
	`"email":"pat@lakeside.edu","first_name":"Pat","last_name":"Lee","raw_attributes":{"eduPersonPrincipalName":"pat@lakeside.edu"}}`

// started is a client against f and the callback request of a login it started with
// returnURL, carrying the state cookie; state is the state the login sent to WorkOS.
func started(t *testing.T, f *fakeWorkOS, returnURL string) (c *Client, callback func(query string) *http.Request, state string) {
	t.Helper()

	c = New(oidctest.NewCookieClient(t), "sk_test", "client_1", "https://app.example/sso/callback")
	c.SetBaseURL(f.server.URL + "/")

	rr := httptest.NewRecorder()
	authURL, err := c.AuthorizationURL(context.Background(), rr, "org_1", returnURL)
	if err != nil {
		t.Fatalf("AuthorizationURL() error = %v", err)
	}
	u, err := url.Parse(authURL)
	if err != nil {
		t.Fatalf("url.Parse() error = %v", err)
	}
	state = u.Query().Get("state")

	return c, func(query string) *http.Request {
		r := httptest.NewRequestWithContext(context.Background(), http.MethodGet, "/sso/callback?"+query, http.NoBody)
		for _, ck := range rr.Result().Cookies() {
			r.AddCookie(ck)
		}

		return r
	}, state
}

func TestClient_AuthorizationURL(t *testing.T) {
	t.Parallel()

	c := New(oidctest.NewCookieClient(t), "sk_test", "client_1", "https://app.example/sso/callback")

	if _, err := c.AuthorizationURL(context.Background(), httptest.NewRecorder(), " ", "/"); !httpio.HasBadRequest(err) {
		t.Errorf("AuthorizationURL() without an organization error = %v, want BadRequest", err)
	}

	states := map[string]bool{}
	for range 2 {
		rr := httptest.NewRecorder()
		authURL, err := c.AuthorizationURL(context.Background(), rr, "org_1", "/next")
		if err != nil {
			t.Fatalf("AuthorizationURL() error = %v", err)
		}
		u, err := url.Parse(authURL)
		if err != nil {
			t.Fatalf("url.Parse() error = %v", err)
		}
		q := u.Query()
		if u.Scheme+"://"+u.Host != DefaultBaseURL || u.Path != "/sso/authorize" || q.Get("client_id") != "client_1" || q.Get("organization") != "org_1" ||
			q.Get("response_type") != "code" || q.Get("redirect_uri") != "https://app.example/sso/callback" {
			t.Errorf("authorization URL = %s", authURL)
		}
		states[q.Get("state")] = true

		var stateCookie bool
		for _, ck := range rr.Result().Cookies() {
			stateCookie = stateCookie || ck.Name == internalcookie.WorkOSStateCookieName
		}
		if !stateCookie {
			t.Errorf("no %s state cookie written", internalcookie.WorkOSStateCookieName)
		}
	}
	if len(states) != 2 || states[""] {
		t.Errorf("states = %v, want a fresh one per login", states)
	}
}

func TestClient_Verify(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name          string
		returnURL     string
		query         func(state string) string
		noCookie      bool
		status        int
		body          string
		wantCode      sessioninfo.LoginRefusalCode
		wantReturnURL string
	}{
		{
			name:     "a callback without the login's state cookie is refused",
			query:    func(state string) string { return "code=c&state=" + state },
			noCookie: true,
			wantCode: sessioninfo.RefusedNoOIDCCookie,
		},
		{
			name:     "a callback whose state is not the login's is refused",
			query:    func(string) string { return "code=c&state=forged" },
			wantCode: sessioninfo.RefusedInvalidState,
		},
		{
			name:     "a callback reporting a failed upstream sign-in is refused",
			query:    func(state string) string { return "error=access_denied&error_description=nope&state=" + state },
			wantCode: sessioninfo.RefusedTokenExchange,
		},
		{
			name:     "a callback without a code is refused",
			query:    func(state string) string { return "state=" + state },
			wantCode: sessioninfo.RefusedTokenExchange,
		},
		{
			name:     "a code WorkOS will not exchange is refused",
			query:    func(state string) string { return "code=c&state=" + state },
			status:   http.StatusBadRequest,
			body:     `{"error":"invalid_grant"}`,
			wantCode: sessioninfo.RefusedTokenExchange,
		},
		{
			name:     "a profile without its identity key is refused",
			query:    func(state string) string { return "code=c&state=" + state },
			body:     `{"profile":{"id":"prof_1","connection_id":"conn_1"}}`,
			wantCode: sessioninfo.RefusedClaimsParse,
		},
		{
			name:          "a valid callback yields the profile, and an off-site return URL becomes the root",
			returnURL:     "//evil.example/",
			query:         func(state string) string { return "code=c&state=" + state },
			body:          `{"access_token":"at","profile":` + profileJSON + `}`,
			wantReturnURL: "/",
		},
		{
			name:          "a valid callback keeps a local return URL",
			returnURL:     "/dashboard?tab=1",
			query:         func(state string) string { return "code=c&state=" + state },
			body:          `{"access_token":"at","profile":` + profileJSON + `}`,
			wantReturnURL: "/dashboard?tab=1",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			f := newFakeWorkOS(t)
			if tt.status != 0 {
				f.status = tt.status
			}
			f.body = tt.body
			c, callback, state := started(t, f, tt.returnURL)
			r := callback(tt.query(state))
			if tt.noCookie {
				r = httptest.NewRequestWithContext(context.Background(), http.MethodGet, "/sso/callback?"+tt.query(state), http.NoBody)
			}

			rr := httptest.NewRecorder()
			returnURL, profile, raw, err := c.Verify(context.Background(), rr, r)

			if tt.wantCode != "" {
				if got := sessioninfo.LoginRefusalCodeOf(err); err == nil || got != tt.wantCode {
					t.Fatalf("Verify() error = %v (code %q), want code %q", err, got, tt.wantCode)
				}

				return
			}
			if err != nil {
				t.Fatalf("Verify() error = %v", err)
			}
			if returnURL != tt.wantReturnURL {
				t.Errorf("returnURL = %q, want %q", returnURL, tt.wantReturnURL)
			}
			if profile.ConnectionID != "conn_1" || profile.IdpID != "pat@idp" || profile.Email != "pat@lakeside.edu" {
				t.Errorf("profile = %+v", profile)
			}
			if !strings.Contains(string(raw), "eduPersonPrincipalName") {
				t.Errorf("raw profile = %s, want it whole, raw_attributes included", raw)
			}
			want := map[string]string{"client_id": "client_1", "client_secret": "sk_test", "grant_type": "authorization_code", "code": "c"}
			if f.contentType != "application/json" || len(f.request) != len(want) {
				t.Errorf("token request = %s %v, want a JSON body %v", f.contentType, f.request, want)
			}
			for k, v := range want {
				if f.request[k] != v {
					t.Errorf("token request %s = %q, want %q", k, f.request[k], v)
				}
			}
			var deleted bool
			for _, ck := range rr.Result().Cookies() {
				deleted = deleted || (ck.Name == internalcookie.WorkOSStateCookieName && ck.Value == "" && ck.Expires.Before(time.Now()))
			}
			if !deleted {
				t.Error("the state cookie was not deleted: it must be single-use")
			}
		})
	}
}
