package sessioninfo

import (
	"fmt"

	"github.com/cccteam/httpio"
	"github.com/go-playground/errors/v5"
)

// LoginRefusalCode names why a login was refused. It is the wire contract between the
// session module and a login page: a refused OIDC login redirects the browser to
// LoginURL?code=<code>, and the page maps the code to text it holds itself, showing
// nothing for a code it does not know. No text travels in the URL. The library's codes
// are the constants below; an application's custom session data resolver may refuse with
// a code of its own through NewLoginRefusal. See the "Login refusal codes" section of
// the README.
type LoginRefusalCode string

const (
	// RefusedInternalError is the code for a fault the module does not classify: a
	// store error, a role-store error, a claims payload that would not decode, a
	// resolver error that is neither a LoginRefusal nor a client message.
	RefusedInternalError LoginRefusalCode = "internal_error"
	// RefusedByApplication is the code for a custom session data resolver that refused
	// the login with an httpio client message and no code. The message stays in the
	// log; the page shows its own sentence.
	RefusedByApplication LoginRefusalCode = "login_refused"
	// RefusedNoOIDCCookie is the code for a callback that arrived without the cookie the
	// login route set.
	RefusedNoOIDCCookie LoginRefusalCode = "no_oidc_cookie"
	// RefusedInvalidState is the code for a callback whose state parameter does not match
	// the login this browser started.
	RefusedInvalidState LoginRefusalCode = "invalid_state"
	// RefusedInvalidPKCE is the code for a login cookie that carries no usable PKCE
	// verifier.
	RefusedInvalidPKCE LoginRefusalCode = "invalid_pkce"
	// RefusedTokenExchange is the code for a provider that refused to exchange the
	// authorization code for tokens.
	RefusedTokenExchange LoginRefusalCode = "token_exchange_failed"
	// RefusedNoIDToken is the code for a token response that carried no id_token.
	RefusedNoIDToken LoginRefusalCode = "no_id_token"
	// RefusedIDTokenVerification is the code for an ID token that failed signature,
	// issuer, audience, or expiry verification.
	RefusedIDTokenVerification LoginRefusalCode = "verify_id_token_failed"
	// RefusedClaimsParse is the code for a verified ID token whose claims would not
	// decode.
	RefusedClaimsParse LoginRefusalCode = "parse_claims_failed"
	// RefusedNotWorkspaceMember is the code for a Google account outside the Workspace
	// domain the application restricts logins to.
	RefusedNotWorkspaceMember LoginRefusalCode = "not_workspace_member"
	// RefusedEmailNotVerified is the code for a Google account whose email address is
	// not verified.
	RefusedEmailNotVerified LoginRefusalCode = "email_not_verified"
	// RefusedNoRoles is the code for a login that role synchronization left with no
	// recognized role.
	RefusedNoRoles LoginRefusalCode = "no_roles"
	// RefusedNoEmailClaim is the code for a Google ID token that carries no email claim.
	RefusedNoEmailClaim LoginRefusalCode = "no_email_claim"
)

// LoginRefusal is a refused login: the code the login page receives and the cause the
// log receives. Unwrap returns the cause, so an httpio client message in it still
// answers httpio.Message and the log handler's status, and errors.Is and errors.As see
// the same chain as before the code was attached.
type LoginRefusal struct {
	code  LoginRefusalCode
	cause error
}

// NewLoginRefusal attaches code to cause. A custom session data resolver returns it to
// refuse a login with a code the application's login page holds text for; cause may be
// an httpio client message, any other error, or nil when the code says enough.
func NewLoginRefusal(code LoginRefusalCode, cause error) error {
	return &LoginRefusal{code: code, cause: cause}
}

// Code is the code the login page receives.
func (r *LoginRefusal) Code() LoginRefusalCode {
	return r.code
}

// Error names the code and the cause.
func (r *LoginRefusal) Error() string {
	if r.cause == nil {
		return fmt.Sprintf("login refused: %s", r.code)
	}

	return fmt.Sprintf("login refused: %s: %s", r.code, r.cause.Error())
}

// Unwrap returns the cause.
func (r *LoginRefusal) Unwrap() error {
	return r.cause
}

// LoginRefusalCodeOf answers the code a refused login redirects with. A LoginRefusal in
// err's chain answers its code. Otherwise an httpio client message in the chain answers
// RefusedByApplication: the application refused on purpose, and its text stays in the
// log. Otherwise RefusedInternalError.
func LoginRefusalCodeOf(err error) LoginRefusalCode {
	var refusal *LoginRefusal
	if errors.As(err, &refusal) {
		return refusal.code
	}

	var clientMessage *httpio.ClientMessage
	if errors.As(err, &clientMessage) {
		return RefusedByApplication
	}

	return RefusedInternalError
}
