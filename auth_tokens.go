package session

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"net/http"
	"regexp"
	"strings"
	"time"

	"github.com/cccteam/ccc"
	"github.com/cccteam/ccc/tracer"
	"github.com/cccteam/httpio"
	internalcookie "github.com/cccteam/session/internal/cookie"
	"github.com/cccteam/session/sessioninfo"
	"github.com/cccteam/session/sessionstorage"
	"github.com/go-playground/errors/v5"
	"go.opentelemetry.io/otel/trace"
)

// A machine outlet is a URL space of the application whose requests carry a bearer
// token the Auth issued for it, never a session cookie: the surface a command-line
// tool or an integration calls. The Auth issues the tokens two ways, an application
// token a signed-in person creates for a program of their own (ApplicationTokens(),
// AuthAPI.CreateApplicationToken) and the access and refresh tokens of a device grant
// a command-line client obtains with the person's approval (Device(), RFC 8628), and
// its ValidateToken middleware binds each request on the outlet to the token's person
// the way ValidateSession binds a browser request to its user. See the README's
// "Machine outlets and bearer tokens".

// Default token settings.
const (
	defaultAccessTokenLifetime      = time.Hour
	defaultRefreshTokenLifetime     = 30 * 24 * time.Hour
	defaultApplicationTokenLifetime = 365 * 24 * time.Hour
	defaultDeviceCodeLifetime       = 10 * time.Minute
	defaultDevicePollInterval       = 5 * time.Second
	defaultDeviceVerificationURL    = "/device"
	// tokenTouchInterval is how often a token's LastUsedAt is moved while it is in use.
	tokenTouchInterval = time.Minute
	// tokenSecretSize is a token secret's size in bytes.
	tokenSecretSize = 32
	// userCodeLength is the length of the code a person types to approve a device.
	userCodeLength = 8
	// userCodeAlphabet is the alphabet of a user code: twenty consonants, so a code
	// spells nothing and no letter is mistaken for another (RFC 8628, 6.1).
	userCodeAlphabet = "BCDFGHJKLMNPQRSTVWXZ"
	// userCodeParam is the query parameter the verification URL carries the user code
	// in (verification_uri_complete).
	userCodeParam = "userCode"
)

// tokenSettings are an Auth's token settings.
type tokenSettings struct {
	// access, refresh and applicationMax are how long an access token, a refresh
	// token and, at most, an application token live.
	access, refresh, applicationMax time.Duration
	// deviceCode is how long a device authorization waits for the person, and
	// pollInterval how often the client may poll it.
	deviceCode, pollInterval time.Duration
	// verificationURL is the application's page where a person approves a device.
	verificationURL string
}

func defaultTokenSettings() tokenSettings {
	return tokenSettings{
		access: defaultAccessTokenLifetime, refresh: defaultRefreshTokenLifetime, applicationMax: defaultApplicationTokenLifetime,
		deviceCode: defaultDeviceCodeLifetime, pollInterval: defaultDevicePollInterval, verificationURL: defaultDeviceVerificationURL,
	}
}

func (s *tokenSettings) validate() error {
	for _, d := range []struct {
		name  string
		value time.Duration
	}{
		{name: "the access token lifetime", value: s.access},
		{name: "the refresh token lifetime", value: s.refresh},
		{name: "the application token lifetime", value: s.applicationMax},
		{name: "the device code lifetime", value: s.deviceCode},
		{name: "the device poll interval", value: s.pollInterval},
	} {
		if d.value <= 0 {
			return errors.Newf("%s must be positive", d.name)
		}
	}
	if s.refresh < s.access {
		return errors.New("the refresh token lifetime must be at least the access token lifetime")
	}
	if internalcookie.SanitizeReturnURL(s.verificationURL) != s.verificationURL || s.verificationURL == "/" {
		return errors.Newf("the device verification URL %q must be a path in the application", s.verificationURL)
	}

	return nil
}

// WithTokenLifetimes sets how long the tokens live: an access token for access, a
// refresh token for refresh (at least access), and an application token for at most
// applicationMax, the default an application token is issued with. (default: an
// hour, thirty days, a year)
func WithTokenLifetimes(access, refresh, applicationMax time.Duration) AuthOption {
	return authOption{apply: func(s *authSettings) {
		s.tokens.access, s.tokens.refresh, s.tokens.applicationMax = access, refresh, applicationMax
	}}
}

// WithDeviceCodeLifetime sets how long a device authorization waits for the person's
// decision, and the interval a client is held to between polls. (default: ten
// minutes, five seconds)
func WithDeviceCodeLifetime(lifetime, pollInterval time.Duration) AuthOption {
	return authOption{apply: func(s *authSettings) { s.tokens.deviceCode, s.tokens.pollInterval = lifetime, pollInterval }}
}

// WithDeviceVerificationURL sets the path of the application's page where a signed-in
// person approves a device, as the device authorization tells the client
// (verification_uri). It must be a path in the application. (default: /device)
func WithDeviceVerificationURL(path string) AuthOption {
	return authOption{apply: func(s *authSettings) { s.tokens.verificationURL = path }}
}

// WithTokensTableName sets the name of the group's tokens table. (default:
// SessionTokens)
func WithTokensTableName(name string) AuthOption {
	return authOption{apply: func(s *authSettings) { s.tokensTable = &name }}
}

// WithDeviceCodesTableName sets the name of the group's device codes table. (default:
// SessionDeviceCodes)
func WithDeviceCodesTableName(name string) AuthOption {
	return authOption{apply: func(s *authSettings) { s.deviceCodesTable = &name }}
}

// outletName is the shape of a machine outlet's name: letters, digits, hyphens and
// underscores, as the generated router names its outlets.
var outletName = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9_-]*$`)

// outletRegistry is the Auth a machine outlet is registered on. It lets
// RegisterMachineOutlet accept an Auth of any type parameters and return an outlet
// type that is not generic.
type outletRegistry interface {
	registerOutlet(name string) func(next http.Handler) http.Handler
}

var _ outletRegistry = (*Auth[NoCustomData, NoCustomData, struct{}])(nil)

// MachineOutlet is a machine outlet registered on an Auth: the tokens the Auth issues
// for it are the credentials its requests carry.
type MachineOutlet struct {
	name     string
	validate func(next http.Handler) http.Handler
}

// RegisterMachineOutlet registers the machine outlet name on auth and returns it.
// Tokens are issued only for registered outlets, and a token is accepted only on the
// outlet it was issued for. Register every outlet after NewAuth and before serving
// the first request; a name that is empty or not an identifier of letters, digits,
// hyphens and underscores, a name registered twice, or an outlet registered once the
// Auth is in use is a wiring mistake and panics, as a misregistered sign-in method
// does.
func RegisterMachineOutlet(auth outletRegistry, name string) *MachineOutlet {
	return &MachineOutlet{name: name, validate: auth.registerOutlet(name)}
}

// Name is the outlet's name.
func (o *MachineOutlet) Name() string { return o.name }

// ValidateToken authenticates a request on the outlet by the bearer token it carries
// (Authorization: Bearer <token>) and binds it to the token's person the way
// ValidateSession binds a browser request to its user: the session read, the user
// (sessioninfo.UserFromCtx), the principal and the evidence are the token's, and
// sessioninfo.TokenFromCtx names the token. A request without a bearer token, or with
// one that is unknown, expired, revoked, not a bearer kind, issued for another outlet,
// or whose person is missing or disabled, is refused with 401 and a WWW-Authenticate
// challenge; a person who must change a password an operator set is refused with 403
// and {"message", "code": "password_change_required"}, as everywhere. No cookie is
// read or written and no XSRF token is checked: a bearer token is nothing a browser
// sends on its own.
func (o *MachineOutlet) ValidateToken(next http.Handler) http.Handler { return o.validate(next) }

// registerOutlet registers name under the methods lock and returns its middleware.
func (a *Auth[S, U, Tx]) registerOutlet(name string) func(next http.Handler) http.Handler {
	a.methods.mu.Lock()
	defer a.methods.mu.Unlock()

	switch {
	case a.methods.inUse.Load():
		panic(fmt.Sprintf("session: the machine outlet %q is registered after the Auth is in use: register every outlet before serving", name))
	case !outletName.MatchString(name):
		panic(fmt.Sprintf("session: the machine outlet name %q is not an identifier: use letters, digits, hyphens and underscores, such as \"droids\"", name))
	case a.methods.outlets[name]:
		panic(fmt.Sprintf("session: the machine outlet %q is registered twice: one outlet, one registration", name))
	}
	a.methods.outlets[name] = true

	return a.validateTokenMiddleware(name)
}

// requireOutlet refuses an outlet that is not registered, as a bad request: a token
// can only be issued for an outlet that will accept it.
func (a *Auth[S, U, Tx]) requireOutlet(name string) error {
	if !a.registered().outlets[name] {
		return httpio.NewBadRequestMessagef("%q is not a machine outlet of this application", name)
	}

	return nil
}

// errNoBearer is the refusal of a request that carries no bearer token.
var errNoBearer = httpio.NewUnauthorizedMessage("a bearer token is required")

// validateTokenMiddleware is the bearer middleware of the outlet name.
func (a *Auth[S, U, Tx]) validateTokenMiddleware(outlet string) func(next http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return a.serving(a.baseSession.Handle(func(w http.ResponseWriter, r *http.Request) error {
			evidence := trace.SpanFromContext(r.Context())

			ctx, span := tracer.Start(r.Context())
			defer span.End()

			ctx, err := a.validateToken(ctx, evidence, r, outlet)
			if err != nil {
				return writeTokenError(ctx, w, outlet, err)
			}

			next.ServeHTTP(w, r.WithContext(ctx))

			return nil
		}))
	}
}

// writeTokenError answers a refused request on a machine outlet: an unauthorized
// refusal carries the bearer challenge, naming the outlet as the realm and, when a
// token was presented, that it is invalid (RFC 6750, 3); the password change mark is
// the coded 403 of every validated request; anything else is the usual client
// message.
func writeTokenError(ctx context.Context, w http.ResponseWriter, outlet string, err error) error {
	var refusal *sessioninfo.LoginRefusal
	if errors.As(err, &refusal) {
		return writeSignInError(ctx, w, err)
	}
	if httpio.HasUnauthorized(err) {
		challenge := fmt.Sprintf("Bearer realm=%q", outlet)
		if !errors.Is(err, errNoBearer) {
			challenge += `, error="invalid_token"`
		}
		w.Header().Set("WWW-Authenticate", challenge)
	}
	if werr := httpio.NewEncoder(w).ClientMessage(ctx, err); werr != nil {
		return errors.Wrap(werr, "httpio.Encoder.ClientMessage()")
	}

	return nil
}

// bearerToken is the token the request's Authorization header carries under the
// Bearer scheme, and whether it carries one.
func bearerToken(r *http.Request) (string, bool) {
	scheme, token, ok := strings.Cut(strings.TrimSpace(r.Header.Get("Authorization")), " ")
	if !ok || !strings.EqualFold(scheme, "Bearer") {
		return "", false
	}
	token = strings.TrimSpace(token)

	return token, token != ""
}

// validateToken authenticates the request by its bearer token for the outlet and
// returns the context the request runs in: the session the token stands in for, its
// user, the principal and the evidence, as validateRequest gives a browser request.
func (a *Auth[S, U, Tx]) validateToken(ctx context.Context, evidence trace.Span, r *http.Request, outlet string) (context.Context, error) {
	secret, ok := bearerToken(r)
	if !ok {
		return ctx, errNoBearer
	}
	tok, err := a.storage.Token(ctx, hashToken(secret))
	if err != nil {
		if httpio.HasNotFound(err) {
			return ctx, httpio.NewUnauthorizedMessageWithError(err, "invalid token")
		}

		return ctx, errors.Wrap(err, "sessionstorage.AuthStore.Token()")
	}
	if !tok.Kind.Bearer() || tok.Outlet != outlet {
		return ctx, httpio.NewUnauthorizedMessagef("invalid token: the token is a %s token for the %q outlet", tok.Kind, tok.Outlet)
	}
	user, err := a.storage.User(ctx, tok.UserID)
	if err != nil {
		if httpio.HasNotFound(err) {
			return ctx, httpio.NewUnauthorizedMessageWithError(err, "invalid token")
		}

		return ctx, errors.Wrap(err, "sessionstorage.AuthStore.User()")
	}
	info, err := enabledUser(user)
	if err != nil {
		return ctx, err
	}
	if info.PasswordChangeRequired {
		return ctx, errPasswordChangeRequired()
	}
	if tok.LastUsedAt == nil || time.Since(*tok.LastUsedAt) > tokenTouchInterval {
		if err := a.storage.TouchToken(ctx, tok.ID); err != nil {
			return ctx, errors.Wrap(err, "sessionstorage.AuthStore.TouchToken()")
		}
	}

	ctx = context.WithValue(ctx, sessioninfo.CTXSessionID, tok.ID)
	ctx, err = a.baseSession.Establish(ctx, evidence, tokenSession(tok, info))
	if err != nil {
		return ctx, errors.Wrap(err, "basesession.BaseSession.Establish()")
	}

	return context.WithValue(ctx, sessioninfo.CtxUserInfo, info), nil
}

// tokenSession is the session a token stands in for: the token's id as the session
// id, its person as the user, its issue as the authentication, recorded as one auth
// event of the token method whose connection is the token's kind.
func tokenSession(tok *sessionstorage.Token, user *sessioninfo.UserInfo) *sessioninfo.SessionData {
	return &sessioninfo.SessionData{
		SessionInfo:     &sessioninfo.SessionInfo{ID: tok.ID, Username: user.Username, CreatedAt: tok.CreatedAt, UpdatedAt: time.Now()},
		UserID:          ccc.NullUUIDFromUUID(user.ID),
		AuthenticatedAt: tok.CreatedAt,
		AuthEvents:      []sessioninfo.AuthEvent{{Method: sessioninfo.MethodToken, Connection: string(tok.Kind), At: tok.CreatedAt}},
		Token:           &sessioninfo.TokenInfo{ID: tok.ID, Kind: string(tok.Kind), Name: tok.Name, ClientID: tok.ClientID, Outlet: tok.Outlet},
	}
}

// newSecret mints a token secret as the client carries it, and its hash as the store
// keeps it.
func newSecret() (secret string, hash []byte, err error) {
	raw := make([]byte, tokenSecretSize)
	if _, err := rand.Read(raw); err != nil {
		return "", nil, errors.Wrap(err, "rand.Read()")
	}
	secret = base64.RawURLEncoding.EncodeToString(raw)

	return secret, hashToken(secret), nil
}

// hashToken is the hash the store keeps of a token secret.
func hashToken(secret string) []byte {
	sum := sha256.Sum256([]byte(secret))

	return sum[:]
}

// newUserCode mints the code a person types to approve a device, normalized: eight
// letters of the user code alphabet, drawn uniformly.
func newUserCode() (string, error) {
	code := make([]byte, 0, userCodeLength)
	raw := make([]byte, 2*userCodeLength)
	for len(code) < userCodeLength {
		if _, err := rand.Read(raw); err != nil {
			return "", errors.Wrap(err, "rand.Read()")
		}
		for _, b := range raw {
			// 240 is the largest multiple of the alphabet's size below 256: a byte at or
			// above it is thrown away, so every letter is equally likely.
			if b >= 240 || len(code) == userCodeLength {
				continue
			}
			code = append(code, userCodeAlphabet[int(b)%len(userCodeAlphabet)])
		}
	}

	return string(code), nil
}

// formatUserCode renders a normalized user code for the person: two groups of four
// with a hyphen between.
func formatUserCode(code string) string {
	if len(code) != userCodeLength {
		return code
	}

	return code[:4] + "-" + code[4:]
}

// normalizeUserCode renders what the person typed as the store keeps it: upper case,
// letters and digits only.
func normalizeUserCode(typed string) string {
	var b strings.Builder
	for _, r := range strings.ToUpper(typed) {
		if (r >= 'A' && r <= 'Z') || (r >= '0' && r <= '9') {
			b.WriteRune(r)
		}
	}

	return b.String()
}
