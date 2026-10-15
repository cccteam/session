package session

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/cccteam/session/azure"
	"github.com/cccteam/session/google"
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
				Pending: PendingRoutes{Status: "/api/user/pending", Confirm: "/api/user/pending/confirm", Cancel: "/api/user/pending/cancel"},
			},
			want: map[string]any{
				"methods": []any{
					map[string]any{"name": "google", "method": "google", "kind": "redirect", "label": "Google", "path": "/api/user/google/login"},
					map[string]any{"name": "password", "method": "password", "kind": "password", "label": "Password", "path": "/api/user/password/login"},
					map[string]any{"name": "lakeside-entra", "method": "azure", "kind": "redirect", "label": "Lakeside", "path": "/api/user/lakeside-entra/login"},
				},
				"pending": map[string]any{"status": "/api/user/pending", "confirm": "/api/user/pending/confirm", "cancel": "/api/user/pending/cancel"},
			},
		},
		{
			name: "a registered method that is not listed is not offered, and no pending routes means no pending block",
			list: &MethodList{Methods: []AdvertisedMethod{{Name: "password", Label: "Sign in", Path: "/login"}}},
			want: map[string]any{
				"methods": []any{map[string]any{"name": "password", "method": "password", "kind": "password", "label": "Sign in", "path": "/login"}},
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
		{name: "a method listed twice", list: &MethodList{Methods: []AdvertisedMethod{{Name: "password", Label: "a", Path: "/a"}, {Name: "password", Label: "b", Path: "/b"}}}, want: `"password" twice`},
		{name: "a method without a label", list: &MethodList{Methods: []AdvertisedMethod{{Name: "password", Path: "/login"}}}, want: "without a label"},
		{name: "a relative path", list: &MethodList{Methods: []AdvertisedMethod{{Name: "password", Label: "x", Path: "api/user/login"}}}, want: "not a canonical path"},
		{name: "a scheme-relative path", list: &MethodList{Methods: []AdvertisedMethod{{Name: "google", Label: "x", Path: "//evil.example/login"}}}, want: "not a canonical path"},
		{name: "a dot segment", list: &MethodList{Methods: []AdvertisedMethod{{Name: "google", Label: "x", Path: "/api/../login"}}}, want: "not a canonical path"},
		{name: "the root", list: &MethodList{Methods: []AdvertisedMethod{{Name: "google", Label: "x", Path: "/"}}}, want: "not a canonical path"},
		{name: "some of the pending routes", list: &MethodList{Methods: []AdvertisedMethod{{Name: "password", Label: "x", Path: "/login"}}, Pending: PendingRoutes{Status: "/api/user/pending"}}, want: "name the status, confirm and cancel paths together"},
		{name: "a pending route off-site", list: &MethodList{Methods: []AdvertisedMethod{{Name: "password", Label: "x", Path: "/login"}}, Pending: PendingRoutes{Status: pending.Status, Confirm: "https://evil.example/confirm", Cancel: pending.Cancel}}, want: "name the status, confirm and cancel paths together"},
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

		h := a.Methods(&MethodList{Methods: []AdvertisedMethod{{Name: "password", Label: "Password", Path: "/login"}}, Pending: pending})
		if a.methods.inUse.Load() {
			t.Fatal("Methods() closed registration at wiring")
		}
		h.ServeHTTP(httptest.NewRecorder(), httptest.NewRequestWithContext(t.Context(), http.MethodGet, "/methods", http.NoBody))
		if !a.methods.inUse.Load() {
			t.Error("the first request through Methods() did not close registration")
		}
	})
}
