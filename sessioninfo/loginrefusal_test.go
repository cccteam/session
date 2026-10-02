package sessioninfo

import (
	"testing"

	"github.com/cccteam/httpio"
	"github.com/go-playground/errors/v5"
)

func TestLoginRefusalCodeOf(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		err  error
		want LoginRefusalCode
	}{
		{
			name: "a coded refusal answers its code",
			err:  NewLoginRefusal(RefusedNoRoles, httpio.NewUnauthorizedMessage("Unauthorized: user has no roles")),
			want: RefusedNoRoles,
		},
		{
			name: "a coded refusal wrapped by the handler chain still answers its code",
			err:  errors.Wrap(errors.Wrap(NewLoginRefusal(RefusedInvalidState, httpio.NewForbiddenMessage("Invalid 'state' parameter value")), "Verify()"), "CallbackOIDC()"),
			want: RefusedInvalidState,
		},
		{
			name: "an application's own code rides through the storage chain",
			err:  errors.Wrap(NewLoginRefusal(LoginRefusalCode("not_provisioned"), httpio.NewBadRequestMessage("user is not provisioned")), "NewSession()"),
			want: LoginRefusalCode("not_provisioned"),
		},
		{
			name: "a coded refusal with no cause answers its code",
			err:  NewLoginRefusal(RefusedNoIDToken, nil),
			want: RefusedNoIDToken,
		},
		{
			name: "an uncoded client message answers login_refused",
			err:  errors.Wrap(httpio.NewBadRequestMessage("user is not provisioned"), "NewSession()"),
			want: RefusedByApplication,
		},
		{
			name: "a bare error answers internal_error",
			err:  errors.Wrap(errors.New("store blip"), "NewSession()"),
			want: RefusedInternalError,
		},
		{
			name: "nil answers internal_error",
			err:  nil,
			want: RefusedInternalError,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			if got := LoginRefusalCodeOf(tt.err); got != tt.want {
				t.Errorf("LoginRefusalCodeOf() = %q, want %q", got, tt.want)
			}
		})
	}
}

func TestLoginRefusal(t *testing.T) {
	t.Parallel()

	cause := httpio.NewForbiddenMessage("No OIDC cookie")
	tests := []struct {
		name          string
		err           error
		wantCode      LoginRefusalCode
		wantError     string
		wantMessage   string
		wantForbidden bool
	}{
		{
			name:          "the cause stays visible to httpio through Unwrap",
			err:           NewLoginRefusal(RefusedNoOIDCCookie, cause),
			wantCode:      RefusedNoOIDCCookie,
			wantError:     "login refused: no_oidc_cookie: " + cause.Error(),
			wantMessage:   "No OIDC cookie",
			wantForbidden: true,
		},
		{
			name:      "no cause names the code alone",
			err:       NewLoginRefusal(RefusedNoRoles, nil),
			wantCode:  RefusedNoRoles,
			wantError: "login refused: no_roles",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			var refusal *LoginRefusal
			if !errors.As(tt.err, &refusal) {
				t.Fatalf("errors.As(%T) found no LoginRefusal", tt.err)
			}
			if got := refusal.Code(); got != tt.wantCode {
				t.Errorf("Code() = %q, want %q", got, tt.wantCode)
			}
			if got := tt.err.Error(); got != tt.wantError {
				t.Errorf("Error() = %q, want %q", got, tt.wantError)
			}
			if got := httpio.Message(tt.err); got != tt.wantMessage {
				t.Errorf("httpio.Message() = %q, want %q", got, tt.wantMessage)
			}
			if got := httpio.HasForbidden(tt.err); got != tt.wantForbidden {
				t.Errorf("httpio.HasForbidden() = %v, want %v", got, tt.wantForbidden)
			}
		})
	}
}
