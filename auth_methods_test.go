package session

import (
	"net/http"
	"testing"

	"github.com/cccteam/session/azure"
	"github.com/cccteam/session/google"
	"github.com/cccteam/session/internal/workos"
	"github.com/cccteam/session/sessioninfo"
	"github.com/cccteam/session/signin"
	gomock "go.uber.org/mock/gomock"
)

// The handler sets of the sign-in method types. Each method type carries only its own
// handlers, so a route can only be wired to a handler the method has.
type (
	loginHandler              interface{ Login() http.HandlerFunc }
	callbackHandler           interface{ Callback() http.HandlerFunc }
	frontChannelLogoutHandler interface{ FrontChannelLogout() http.HandlerFunc }
	changePasswordHandler     interface{ ChangeUserPassword() http.HandlerFunc }
)

// Compile-time: each method type has the handlers its method serves.
var (
	_ interface {
		loginHandler
		changePasswordHandler
	} = (*PasswordMethod)(nil)
	_ interface {
		loginHandler
		callbackHandler
		frontChannelLogoutHandler
	} = (*azure.Method)(nil)
	_ interface {
		loginHandler
		callbackHandler
	} = (*google.Method)(nil)
	_ interface {
		loginHandler
		callbackHandler
	} = (*workos.Method)(nil)
)

// TestSignInMethodTypes_HandlerSets proves the other half, which a compile-time
// assertion cannot state: no method type has a handler that belongs to another method.
// FrontChannelLogout exists only on *azure.Method, ChangeUserPassword only on
// *PasswordMethod, and the password method has no Callback.
func TestSignInMethodTypes_HandlerSets(t *testing.T) {
	t.Parallel()

	type handlerSet struct {
		callback, frontChannelLogout, changePassword bool
	}
	tests := []struct {
		name   string
		method any
		want   handlerSet
	}{
		{name: "*PasswordMethod", method: (*PasswordMethod)(nil), want: handlerSet{changePassword: true}},
		{name: "*azure.Method", method: (*azure.Method)(nil), want: handlerSet{callback: true, frontChannelLogout: true}},
		{name: "*google.Method", method: (*google.Method)(nil), want: handlerSet{callback: true}},
		{name: "*workos.Method", method: (*workos.Method)(nil), want: handlerSet{callback: true}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			_, callback := tt.method.(callbackHandler)
			_, frontChannelLogout := tt.method.(frontChannelLogoutHandler)
			_, changePassword := tt.method.(changePasswordHandler)
			if got := (handlerSet{callback: callback, frontChannelLogout: frontChannelLogout, changePassword: changePassword}); got != tt.want {
				t.Errorf("%s handlers = %+v, want %+v", tt.name, got, tt.want)
			}
		})
	}
}

func TestAuth_couldAdmitAddress(t *testing.T) {
	t.Parallel()

	type auth = *Auth[NoCustomData, NoCustomData, mockTx]
	googleWith := func(workspaces google.WorkspaceSet) func(a auth) {
		return func(a auth) {
			google.SignIn(a, "google", resolveAll[google.Identity](), &google.Config{RoleSync: google.DisableRoleSync(), ClientID: "client", ClientSecret: "secret", RedirectURL: "https://app/google/callback", Workspaces: workspaces})
		}
	}
	entraWith := func(tenants azure.TenantSet) func(a auth) {
		return func(a auth) {
			azure.SignIn(a, "entra", resolveAll[azure.Identity](), &azure.Config{RoleSync: signin.DisableRoleSync(), Authority: testAuthority, Tenants: tenants, ClientID: "client", ClientSecret: "secret", RedirectURL: "https://app/entra/callback"})
		}
	}
	password := func(a auth) { PasswordSignIn(a) }
	// bare is an external method that cannot tell which addresses it admits.
	bare := func(a auth) {
		a.RegisterExternal(&signin.Registration[mockTx]{
			Name: "bare", Method: sessioninfo.AuthMethod("bare"), StandardRule: signin.InvitedUsersOnly,
			Build: func(signin.StateCookies) (*signin.Method, error) { return &signin.Method{Name: "bare"}, nil },
		})
	}
	listing := func(names ...string) *MethodList {
		list := &MethodList{}
		for _, name := range names {
			list.Methods = append(list.Methods, AdvertisedMethod{Name: name, Label: name, Path: "/api/user/" + name + "/login"})
			if name == "password" {
				list.ChangePassword = "/api/user/password"
			}
		}

		return list
	}

	tests := []struct {
		name     string
		register []func(a auth)
		list     *MethodList
		email    string
		want     bool
	}{
		{name: "an Auth with no method admits, having nothing to judge by", email: "pat@elsewhere.example", want: true},
		{name: "the password method offered admits any address: the person creates an account", register: []func(a auth){password, googleWith(google.Workspace("lakeside", "lakeside.edu"))}, list: listing("password", "google"), email: "pat@elsewhere.example", want: true},
		{name: "the password method registered, the page wired without a listing, counts as offered", register: []func(a auth){password}, email: "pat@elsewhere.example", want: true},
		{name: "the password method registered but not listed does not admit", register: []func(a auth){password, googleWith(google.Workspace("lakeside", "lakeside.edu"))}, list: listing("google"), email: "pat@elsewhere.example"},
		{name: "Google with a named Workspace admits its domain", register: []func(a auth){googleWith(google.Workspace("lakeside", "lakeside.edu"))}, email: "Pat@Lakeside.edu", want: true},
		{name: "Google with a named Workspace refuses another domain", register: []func(a auth){googleWith(google.Workspace("lakeside", "lakeside.edu"))}, email: "pat@elsewhere.example"},
		{name: "Google with any Workspace admits a domain outside the named ones", register: []func(a auth){googleWith(google.AnyWorkspace())}, email: "pat@elsewhere.example", want: true},
		{name: "Google with any Workspace refuses a personal account", register: []func(a auth){googleWith(google.AnyWorkspace())}, email: "pat@gmail.com"},
		{name: "Google with any Google account admits a personal account", register: []func(a auth){googleWith(google.AnyGoogleAccount())}, email: "pat@gmail.com", want: true},
		{name: "Entra with one tenant admits a work address", register: []func(a auth){entraWith(azure.Tenant(tenantLake))}, email: "pat@lakeside.edu", want: true},
		{name: "Entra with one tenant refuses a personal account", register: []func(a auth){entraWith(azure.Tenant(tenantLake))}, email: "pat@outlook.com"},
		{name: "Entra with personal accounts admits one", register: []func(a auth){entraWith(azure.PersonalAccounts())}, email: "pat@outlook.com", want: true},
		{name: "a method that cannot tell admits", register: []func(a auth){bare}, email: "pat@gmail.com", want: true},
		{name: "two methods that both refuse refuse", register: []func(a auth){googleWith(google.Workspace("lakeside", "lakeside.edu")), entraWith(azure.Tenant(tenantLake))}, email: "pat@outlook.com"},
		{name: "one method admitting is enough", register: []func(a auth){googleWith(google.Workspace("lakeside", "lakeside.edu")), entraWith(azure.Tenant(tenantLake))}, email: "pat@riverside.edu", want: true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			a := newBareAuth(t, gomock.NewController(t))
			for _, register := range tt.register {
				register(a)
			}
			if tt.list != nil {
				a.Methods(tt.list)
			}

			if got := a.couldAdmitAddress(tt.email); got != tt.want {
				t.Errorf("couldAdmitAddress(%q) = %v, want %v", tt.email, got, tt.want)
			}
		})
	}
}
