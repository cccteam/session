package session

import (
	"net/http"
	"testing"
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
	} = (*AzureMethod)(nil)
	_ interface {
		loginHandler
		callbackHandler
	} = (*GoogleMethod)(nil)
	_ interface {
		loginHandler
		callbackHandler
	} = (*WorkOSMethod)(nil)
)

// TestSignInMethodTypes_HandlerSets proves the other half, which a compile-time
// assertion cannot state: no method type has a handler that belongs to another method.
// FrontChannelLogout exists only on *AzureMethod, ChangeUserPassword only on
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
		{name: "*AzureMethod", method: (*AzureMethod)(nil), want: handlerSet{callback: true, frontChannelLogout: true}},
		{name: "*GoogleMethod", method: (*GoogleMethod)(nil), want: handlerSet{callback: true}},
		{name: "*WorkOSMethod", method: (*WorkOSMethod)(nil), want: handlerSet{callback: true}},
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
