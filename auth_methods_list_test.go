package session

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/cccteam/session/azure"
	"github.com/cccteam/session/google"
	"github.com/cccteam/session/mail"
	"github.com/cccteam/session/signin"
	"github.com/google/go-cmp/cmp"
	gomock "go.uber.org/mock/gomock"
)

// registerThree registers the password method and a Google and an Azure registration
// on a bare Auth.
func registerThree(t *testing.T) *Auth[NoCustomData, NoCustomData, mockTx] {
	t.Helper()

	a := newBareAuth(t, gomock.NewController(t))
	PasswordSignIn(a)
	google.SignIn(a, "google", resolveAll[google.Identity](), &google.Config{RoleSync: google.DisableRoleSync(), ClientID: "client", ClientSecret: "secret", RedirectURL: "https://app/google/callback", Workspaces: google.Workspace("example", "example.com")})
	azure.SignIn(a, "lakeside-entra", resolveAll[azure.Identity](), &azure.Config{RoleSync: signin.DisableRoleSync(), Authority: testAuthority, Tenants: azure.Tenant(tenantLake), ClientID: "client", ClientSecret: "secret", RedirectURL: "https://app/entra/callback"})

	return a
}

func TestAuth_Methods(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		list *MethodList
		want map[string]any
	}{
		{
			name: "every listed method in the list's order, the password one a form, the external ones redirects, with the pending routes",
			list: &MethodList{
				Methods: []AdvertisedMethod{
					{Name: "google", Label: "Google", Path: "/api/user/google/login"},
					{Name: "password", Label: "Password", Path: "/api/user/password/login"},
					{Name: "lakeside-entra", Label: "Lakeside", Path: "/api/user/lakeside-entra/login"},
				},
				Pending:        PendingRoutes{Status: "/api/user/pending", Confirm: "/api/user/pending/confirm", Cancel: "/api/user/pending/cancel"},
				ChangePassword: "/api/user/password",
			},
			want: map[string]any{
				"methods": []any{
					map[string]any{"name": "google", "method": "google", "kind": "redirect", "label": "Google", "path": "/api/user/google/login"},
					map[string]any{"name": "password", "method": "password", "kind": "password", "label": "Password", "path": "/api/user/password/login"},
					map[string]any{"name": "lakeside-entra", "method": "azure", "kind": "redirect", "label": "Lakeside", "path": "/api/user/lakeside-entra/login"},
				},
				"pending":        map[string]any{"status": "/api/user/pending", "confirm": "/api/user/pending/confirm", "cancel": "/api/user/pending/cancel"},
				"changePassword": "/api/user/password",
			},
		},
		{
			name: "a registered method that is not listed is not offered, and no pending routes means no pending block",
			list: &MethodList{Methods: []AdvertisedMethod{{Name: "password", Label: "Sign in", Path: "/login"}}, ChangePassword: "/password"},
			want: map[string]any{
				"methods":        []any{map[string]any{"name": "password", "method": "password", "kind": "password", "label": "Sign in", "path": "/login"}},
				"changePassword": "/password",
			},
		},
		{
			name: "external methods alone are offered without a password change route",
			list: &MethodList{Methods: []AdvertisedMethod{{Name: "google", Label: "Google", Path: "/api/user/google/login"}}},
			want: map[string]any{
				"methods": []any{map[string]any{"name": "google", "method": "google", "kind": "redirect", "label": "Google", "path": "/api/user/google/login"}},
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			a := registerThree(t)

			rr := httptest.NewRecorder()
			a.Methods(tt.list).ServeHTTP(rr, httptest.NewRequestWithContext(t.Context(), http.MethodGet, "/api/user/methods", http.NoBody))
			if rr.Code != http.StatusOK {
				t.Fatalf("Methods() status = %d, want 200: %s", rr.Code, rr.Body.String())
			}
			var got map[string]any
			if err := json.Unmarshal(rr.Body.Bytes(), &got); err != nil {
				t.Fatalf("json.Unmarshal() error = %v", err)
			}
			if diff := cmp.Diff(tt.want, got); diff != "" {
				t.Errorf("Methods() answer mismatch (-want +got):\n%s", diff)
			}
		})
	}
}

func TestAuth_MethodsRefused(t *testing.T) {
	t.Parallel()

	pending := PendingRoutes{Status: "/api/user/pending", Confirm: "/api/user/pending/confirm", Cancel: "/api/user/pending/cancel"}
	tests := []struct {
		name string
		list *MethodList
		want string
	}{
		{name: "no list", list: nil, want: "given no sign-in method"},
		{name: "an empty list", list: &MethodList{}, want: "given no sign-in method"},
		{name: "a method without a name", list: &MethodList{Methods: []AdvertisedMethod{{Label: "x", Path: "/login"}}}, want: "without a name"},
		{name: "a method that is not registered", list: &MethodList{Methods: []AdvertisedMethod{{Name: "workos", Label: "SSO", Path: "/sso"}}}, want: `"workos", which is not registered on this Auth`},
		{name: "a method listed twice", list: &MethodList{Methods: []AdvertisedMethod{{Name: "password", Label: "a", Path: "/a"}, {Name: "password", Label: "b", Path: "/b"}}, ChangePassword: "/password"}, want: `"password" twice`},
		{name: "a method without a label", list: &MethodList{Methods: []AdvertisedMethod{{Name: "password", Path: "/login"}}}, want: "without a label"},
		{name: "a relative path", list: &MethodList{Methods: []AdvertisedMethod{{Name: "password", Label: "x", Path: "api/user/login"}}}, want: "not a canonical path"},
		{name: "a scheme-relative path", list: &MethodList{Methods: []AdvertisedMethod{{Name: "google", Label: "x", Path: "//evil.example/login"}}}, want: "not a canonical path"},
		{name: "a dot segment", list: &MethodList{Methods: []AdvertisedMethod{{Name: "google", Label: "x", Path: "/api/../login"}}}, want: "not a canonical path"},
		{name: "the root", list: &MethodList{Methods: []AdvertisedMethod{{Name: "google", Label: "x", Path: "/"}}}, want: "not a canonical path"},
		{name: "some of the pending routes", list: &MethodList{Methods: []AdvertisedMethod{{Name: "password", Label: "x", Path: "/login"}}, Pending: PendingRoutes{Status: "/api/user/pending"}, ChangePassword: "/password"}, want: "name the status, confirm and cancel paths together"},
		{name: "a pending route off-site", list: &MethodList{Methods: []AdvertisedMethod{{Name: "password", Label: "x", Path: "/login"}}, Pending: PendingRoutes{Status: pending.Status, Confirm: "https://evil.example/confirm", Cancel: pending.Cancel}, ChangePassword: "/password"}, want: "name the status, confirm and cancel paths together"},
		{name: "the password method without the password change route", list: &MethodList{Methods: []AdvertisedMethod{{Name: "password", Label: "x", Path: "/login"}}}, want: "lists the password method with the password change route \"\""},
		{name: "a password change route off-site", list: &MethodList{Methods: []AdvertisedMethod{{Name: "password", Label: "x", Path: "/login"}}, ChangePassword: "https://evil.example/password"}, want: "lists the password method with the password change route"},
		{name: "a password change route without the password method", list: &MethodList{Methods: []AdvertisedMethod{{Name: "google", Label: "x", Path: "/login"}}, ChangePassword: "/password"}, want: "lists no password method"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			a := registerThree(t)

			recovered := registrationPanic(func() { a.Methods(tt.list) })
			if recovered == nil {
				t.Fatal("Methods() did not panic")
			}
			if msg, _ := recovered.(string); !strings.Contains(msg, tt.want) {
				t.Errorf("Methods() panic = %v, want it to contain %q", recovered, tt.want)
			}
		})
	}

	t.Run("a valid list leaves registration open until the first request", func(t *testing.T) {
		t.Parallel()
		a := registerThree(t)

		h := a.Methods(&MethodList{Methods: []AdvertisedMethod{{Name: "password", Label: "Password", Path: "/login"}}, Pending: pending, ChangePassword: "/password"})
		if a.methods.inUse.Load() {
			t.Fatal("Methods() closed registration at wiring")
		}
		h.ServeHTTP(httptest.NewRecorder(), httptest.NewRequestWithContext(t.Context(), http.MethodGet, "/methods", http.NoBody))
		if !a.methods.inUse.Load() {
			t.Error("the first request through Methods() did not close registration")
		}
	})
}

// invitationList is a list naming the password method and the invitation routes.
var invitationList = &MethodList{
	Methods:        []AdvertisedMethod{{Name: "password", Label: "Password", Path: "/api/user/password/login"}},
	ChangePassword: "/api/user/password",
	Invitation:     InvitationRoutes{Open: "/api/user/invitation", Accept: "/api/user/invitation/accept", SignUp: "/api/user/invitation/sign-up"},
}

// openedInvitation invites pat into lakeside and opens the invitation in the browser,
// returning the cookies the browser then carries.
func openedInvitation(t *testing.T, f *authFixture, links *mailLinks) []*http.Cookie {
	t.Helper()

	recorder, ok := f.auth.settings.mail.sender.(*mail.Recorder)
	if !ok {
		t.Fatal("the fixture's mail is not a recorder")
	}
	if _, err := f.auth.API().Invite(context.Background(), &InvitationRequest{Email: "pat@lakeside.edu", Tenant: "lakeside", RoleNames: []string{"Teacher"}}); err != nil {
		t.Fatalf("Invite() error = %v", err)
	}

	return invitationCookies(t, f, links, tokenIn(t, recorder.Messages()[0].Text, "invitation"))
}

// invitationBlock serves the methods listing to a browser carrying cookies, through
// StartSession as the application routes it, and returns the answer's invitation block.
func invitationBlock(t *testing.T, f *authFixture, list *MethodList, cookies []*http.Cookie) map[string]any {
	t.Helper()

	rr := f.serve(f.auth.Methods(list), http.MethodGet, "/api/user/methods", nil, cookies)
	if rr.Code != http.StatusOK {
		t.Fatalf("Methods() status = %d, want 200: %s", rr.Code, rr.Body.String())
	}
	block, _ := decoded(t, rr)["invitation"].(map[string]any)

	return block
}

func TestAuth_MethodsStandingInvitation(t *testing.T) {
	t.Parallel()

	t.Run("a browser without the invitation cookie gets the invitation block without a standing invitation", func(t *testing.T) {
		t.Parallel()
		f, _, _ := newMailFixture(t, gomock.NewController(t))

		want := map[string]any{"open": "/api/user/invitation", "accept": "/api/user/invitation/accept", "signUp": "/api/user/invitation/sign-up"}
		if diff := cmp.Diff(want, invitationBlock(t, f, invitationList, nil)); diff != "" {
			t.Errorf("invitation block mismatch (-want +got):\n%s", diff)
		}
	})

	t.Run("a browser carrying a live invitation is told it: the address, the tenant, when it expires and whether the username is the address", func(t *testing.T) {
		t.Parallel()
		f, _, links := newMailFixture(t, gomock.NewController(t))
		cookies := openedInvitation(t, f, links)

		want := map[string]any{
			"open": "/api/user/invitation", "accept": "/api/user/invitation/accept", "signUp": "/api/user/invitation/sign-up",
			"standing": map[string]any{"email": "pat@lakeside.edu", "tenant": "lakeside", "expiresAt": links.last(t).ExpiresAt.Format(time.RFC3339Nano), "usernameIsEmail": false, "methods": []any{}},
		}
		if diff := cmp.Diff(want, invitationBlock(t, f, invitationList, cookies)); diff != "" {
			t.Errorf("invitation block mismatch (-want +got):\n%s", diff)
		}
		if got := invitationBlock(t, f, invitationList, nil); got["standing"] != nil {
			t.Errorf("a request without the cookie after one with it got %v, want no standing invitation: the answer is not shared between requests", got["standing"])
		}
	})

	t.Run("where the password method declares the username as the address, the standing invitation says so, as Open() does", func(t *testing.T) {
		t.Parallel()
		f, _, links := newMailFixture(t, gomock.NewController(t), UsernameIsEmail())
		cookies := openedInvitation(t, f, links)

		standing, _ := invitationBlock(t, f, invitationList, cookies)["standing"].(map[string]any)
		if standing["usernameIsEmail"] != true {
			t.Errorf("standing = %v, want usernameIsEmail true", standing)
		}
	})

	t.Run("a browser whose invitation is dead gets the block without it", func(t *testing.T) {
		t.Parallel()
		f, _, links := newMailFixture(t, gomock.NewController(t))
		cookies := openedInvitation(t, f, links)
		if err := f.auth.API().RevokeInvitation(context.Background(), links.last(t).ID); err != nil {
			t.Fatalf("RevokeInvitation() error = %v", err)
		}

		if got := invitationBlock(t, f, invitationList, cookies); got["standing"] != nil {
			t.Errorf("invitation block = %v, want no standing invitation for a revoked one", got)
		}
	})

	t.Run("a listing without the invitation routes reports no invitation, cookie or not", func(t *testing.T) {
		t.Parallel()
		f, _, links := newMailFixture(t, gomock.NewController(t))
		cookies := openedInvitation(t, f, links)
		list := &MethodList{Methods: invitationList.Methods, ChangePassword: invitationList.ChangePassword}

		if got := invitationBlock(t, f, list, cookies); got != nil {
			t.Errorf("invitation block = %v, want none", got)
		}
	})

	t.Run("the standing invitation names the listed registrations that could admit its address, as Open() does", func(t *testing.T) {
		t.Parallel()
		for _, tt := range []struct {
			email string
			want  []any
		}{
			{email: "pat@lakeside.edu", want: []any{"google-lakeside"}},
			{email: "pat@elsewhere.example", want: []any{}},
		} {
			f, recorder, links := newDirectoryFixture(t)
			if _, err := f.auth.API().Invite(context.Background(), &InvitationRequest{Email: tt.email}); err != nil {
				t.Fatalf("Invite(%s) error = %v", tt.email, err)
			}
			cookies := invitationCookies(t, f, links, tokenIn(t, recorder.Messages()[0].Text, "invitation"))

			standing, _ := invitationBlock(t, f, directoryList, cookies)["standing"].(map[string]any)
			if diff := cmp.Diff(tt.want, standing["methods"]); diff != "" {
				t.Errorf("standing.methods for %s mismatch (-want +got):\n%s", tt.email, diff)
			}
		}
	})

	t.Run("the listing reads the cookie itself when it is routed without StartSession", func(t *testing.T) {
		t.Parallel()
		f, _, links := newMailFixture(t, gomock.NewController(t))
		cookies := openedInvitation(t, f, links)

		r := httptest.NewRequestWithContext(context.Background(), http.MethodGet, "/api/user/methods", http.NoBody)
		for _, c := range cookies {
			r.AddCookie(c)
		}
		rr := httptest.NewRecorder()
		f.auth.Methods(invitationList).ServeHTTP(rr, r)
		if rr.Code != http.StatusOK {
			t.Fatalf("Methods() status = %d, want 200: %s", rr.Code, rr.Body.String())
		}
		block, _ := decoded(t, rr)["invitation"].(map[string]any)
		standing, _ := block["standing"].(map[string]any)
		if standing["email"] != "pat@lakeside.edu" {
			t.Errorf("standing = %v, want pat's invitation", standing)
		}
	})
}
