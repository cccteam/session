package session

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"math/big"
	"net/http"
	"slices"
	"strings"
	"time"

	"github.com/cccteam/ccc"
	"github.com/cccteam/ccc/tracer"
	"github.com/cccteam/httpio"
	"github.com/cccteam/logger"
	"github.com/cccteam/session/cookie"
	"github.com/cccteam/session/internal/sessioncore"
	"github.com/cccteam/session/sessioninfo"
	"github.com/cccteam/session/sessionstorage"
	"github.com/go-playground/errors/v5"
)

// The second factor the library runs. A sign-in the policy holds for MFA
// (signin.RequireMFA) waits as a pending identity; when the policy accepts the
// library's email code (no factor named, or sessioninfo.MethodEmailCode among them),
// the pending handlers mail the user a one-time code and complete the sign-in when the
// person enters it, recording an email-code event. A sign-in whose connection attests
// to a second factor (sessioninfo.Attestation), or whose browser is a trusted device of
// the user, is never held: the attestation or the trusted-device event stands in for
// the step. The code goes to the address the user holds, verified or not: an address
// an operator entered is proven by the code as a verification link would prove it,
// and a user without one gives one at the step (EnrollEmail). An administrator's
// reset (AuthAPI.ResetFactors) forgets the person's trusted devices; with the email
// code there is nothing else to reset, and a lost mailbox is answered by an operator
// setting a new address. See "The second factor" in the README.

// factorSettings are the settings of the library's second factor.
type factorSettings struct {
	// codeTimeout is how long a mailed code is accepted.
	codeTimeout time.Duration
	// trustedPeriod is how long a remembered browser stands in for the factor.
	trustedPeriod time.Duration
	// trustedCookie names the cookie that carries the trusted device's token.
	trustedCookie string
}

// The defaults of the second factor.
const (
	defaultEmailCodeTimeout    = 10 * time.Minute
	defaultTrustedDevicePeriod = 30 * 24 * time.Hour
	defaultTrustedDeviceCookie = "auth-trusted"
	// emailCodeLength is the digits of a code: six, a million codes, guessed at most
	// emailCodeAttempts times before the code dies.
	emailCodeLength = 6
	// emailCodeAttempts is how many wrong codes kill the code sent.
	emailCodeAttempts = 5
	// trustedTokenSize is the trusted device token's size in bytes.
	trustedTokenSize = 32
)

var defaultFactorSettings = factorSettings{codeTimeout: defaultEmailCodeTimeout, trustedPeriod: defaultTrustedDevicePeriod, trustedCookie: defaultTrustedDeviceCookie}

// validate refuses settings the factor cannot run with.
func (f *factorSettings) validate() error {
	if f.codeTimeout <= 0 {
		return errors.New("WithEmailCodeTimeout: the timeout must be positive")
	}
	if f.trustedPeriod <= 0 {
		return errors.New("WithTrustedDevicePeriod: the period must be positive")
	}

	return nil
}

// WithEmailCodeTimeout sets how long a mailed sign-in code is accepted. (default: 10m)
func WithEmailCodeTimeout(d time.Duration) AuthOption {
	return authOption{apply: func(s *authSettings) { s.factors.codeTimeout = d }}
}

// WithTrustedDevicePeriod sets how long a browser the person asked to be remembered
// after a second factor stands in for it. (default: 30 days)
func WithTrustedDevicePeriod(d time.Duration) AuthOption {
	return authOption{apply: func(s *authSettings) { s.factors.trustedPeriod = d }}
}

// WithTrustedDeviceCookieName sets the name of the cookie that carries a trusted
// device's token. (default: "auth-trusted")
func WithTrustedDeviceCookieName(name string) AuthOption {
	return authOption{apply: func(s *authSettings) { s.factors.trustedCookie = name }}
}

// offersEmailCode reports whether a RequireMFA answer naming factors takes the
// library's email code: no factor named, or the code among them.
func offersEmailCode(factors []sessioninfo.AuthMethod) bool {
	return len(factors) == 0 || slices.Contains(factors, sessioninfo.MethodEmailCode)
}

// emailCodeAnswer is the email code's state as the pending status reports it.
type emailCodeAnswer struct {
	// CodeEmail is the masked address the code goes to, "" when the user holds none.
	CodeEmail string `json:"codeEmail,omitempty"`
	// EnrollEmail says the user holds no address: the page asks for one and posts it
	// to EnrollEmail().
	EnrollEmail bool `json:"enrollEmail,omitempty"`
	// CodeSent says a code stands, and CodeExpiresAt when it stops being accepted.
	CodeSent      bool       `json:"codeSent"`
	CodeExpiresAt *time.Time `json:"codeExpiresAt,omitempty"`
}

// emailCodeState is the email code's state for the pending MFA wait p.
func (a *Auth[S, U, Tx]) emailCodeState(ctx context.Context, p *pendingState) (*emailCodeAnswer, error) {
	code, err := a.storage.FactorCode(ctx, p.ID)
	if err != nil && !httpio.HasNotFound(err) {
		return nil, errors.Wrap(err, "sessionstorage.AuthStore.FactorCode()")
	}
	answer := &emailCodeAnswer{}
	if code != nil {
		answer.CodeSent, answer.CodeExpiresAt, answer.CodeEmail = true, &code.ExpiresAt, maskAddress(code.Email)

		return answer, nil
	}
	email, err := a.factorAddress(ctx, p)
	if err != nil {
		return nil, err
	}
	if email == "" {
		answer.EnrollEmail = true
	} else {
		answer.CodeEmail = maskAddress(email)
	}

	return answer, nil
}

// factorAddress is the address the pending MFA wait's code goes to: the one the user
// holds, verified or not, "" when they hold none.
func (a *Auth[S, U, Tx]) factorAddress(ctx context.Context, p *pendingState) (string, error) {
	if !p.UserID.Valid {
		return "", errors.New("a pending MFA wait names its user")
	}
	user, err := a.storage.User(ctx, p.UserID.UUID)
	if err != nil {
		return "", errors.Wrap(err, "sessionstorage.AuthStore.User()")
	}
	if user.Email == nil {
		return "", nil
	}

	return *user.Email, nil
}

// maskAddress renders an address for a screen that must not spell it out: the first
// character of the local part, then dots, then the domain (p•••@lakeside.edu).
func maskAddress(email string) string {
	local, domain, ok := strings.Cut(email, "@")
	if !ok || local == "" {
		return "•••"
	}

	return local[:1] + "•••@" + domain
}

// mfaWait returns the browser's pending identity when it waits for MFA and the policy
// accepts the email code; otherwise the refusal the handlers answer.
func (a *Auth[S, U, Tx]) mfaWait(ctx context.Context) (*pendingState, error) {
	p, err := a.pending(ctx)
	if err != nil {
		return nil, err
	}
	if p.Step != sessioninfo.PendingMFA {
		return nil, httpio.NewConflictMessage("the pending sign-in waits for a password confirmation, not a second factor")
	}
	if !offersEmailCode(p.Factors) {
		return nil, httpio.NewConflictMessagef("the sign-in policy accepts %v for the MFA step, not the email code", p.Factors)
	}

	return p, nil
}

// newEmailCode returns a fresh code of emailCodeLength digits.
func newEmailCode() (string, error) {
	limit := big.NewInt(1)
	for range emailCodeLength {
		limit.Mul(limit, big.NewInt(10))
	}
	n, err := rand.Int(rand.Reader, limit)
	if err != nil {
		return "", errors.Wrap(err, "rand.Int()")
	}
	code := n.String()
	for len(code) < emailCodeLength {
		code = "0" + code
	}

	return code, nil
}

// hashEmailCode is the hash the code row keeps: the code under the pending sign-in it
// belongs to, so a hash tells nothing about another pending sign-in's code.
func hashEmailCode(pendingID ccc.UUID, code string) []byte {
	sum := sha256.Sum256([]byte(pendingID.String() + ":" + code))

	return sum[:]
}

// sendEmailCode mails a fresh code for p to email and records it, replacing the code
// standing. The address's mail is limited as a link's is.
func (a *Auth[S, U, Tx]) sendEmailCode(ctx context.Context, p *pendingState, email string) (*emailCodeAnswer, error) {
	m, err := a.mailOf()
	if err != nil {
		return nil, err
	}
	if err := a.limitMail(ctx, email); err != nil {
		return nil, err
	}
	code, err := newEmailCode()
	if err != nil {
		return nil, err
	}
	lifetime := a.settings.factors.codeTimeout
	row := &sessionstorage.FactorCode{PendingID: p.ID, Email: email, CodeHash: hashEmailCode(p.ID, code), ExpiresAt: time.Now().Add(lifetime)}
	if err := a.storage.InsertFactorCode(ctx, row); err != nil {
		return nil, errors.Wrap(err, "sessionstorage.AuthStore.InsertFactorCode()")
	}
	if err := a.send(ctx, m.codeMessage(email, code, lifetime)); err != nil {
		if cerr := a.storage.ConsumeFactorCode(ctx, row.ID); cerr != nil && !httpio.HasNotFound(cerr) {
			logger.FromCtx(ctx).Error(errors.Wrap(cerr, "sessionstorage.AuthStore.ConsumeFactorCode()"))
		}

		return nil, err
	}

	return &emailCodeAnswer{CodeEmail: maskAddress(email), CodeSent: true, CodeExpiresAt: &row.ExpiresAt}, nil
}

// errNoAddress is the answer of a code asked for a user who holds no address.
func errNoAddress() error {
	return httpio.NewConflictMessage("the user holds no email address: give one to send the code to")
}

// sendCodeToUser mails the pending wait's user the code at the address they hold.
func (a *Auth[S, U, Tx]) sendCodeToUser(ctx context.Context, p *pendingState) (*emailCodeAnswer, error) {
	email, err := a.factorAddress(ctx, p)
	if err != nil {
		return nil, err
	}
	if email == "" {
		return nil, errNoAddress()
	}

	return a.sendEmailCode(ctx, p, email)
}

// enrollEmail mails the code to the address a user without one gives. An address
// another account holds is told so by mail, and the screen is answered as sent.
func (a *Auth[S, U, Tx]) enrollEmail(ctx context.Context, p *pendingState, email string) (*emailCodeAnswer, error) {
	m, err := a.mailOf()
	if err != nil {
		return nil, err
	}
	bare, err := address(email)
	if err != nil {
		return nil, err
	}
	held, err := a.factorAddress(ctx, p)
	if err != nil {
		return nil, err
	}
	if held != "" {
		return nil, httpio.NewConflictMessage("the user already holds an email address: the code goes there")
	}
	holder, err := a.storage.UserByEmail(ctx, bare)
	if err != nil && !httpio.HasNotFound(err) {
		return nil, errors.Wrap(err, "sessionstorage.AuthStore.UserByEmail()")
	}
	if holder != nil && holder.ID != p.UserID.UUID {
		if err := a.limitMail(ctx, bare); err != nil {
			return nil, err
		}
		if err := a.send(ctx, m.addressHeldMessage(bare)); err != nil {
			return nil, err
		}

		return &emailCodeAnswer{CodeEmail: maskAddress(bare), CodeSent: true}, nil
	}

	return a.sendEmailCode(ctx, p, bare)
}

// errInvalidCode and errCodeExpired are the refusals of a code that is not the one
// sent, and of a code entered once the one sent died.
func errInvalidCode() error {
	return sessioninfo.NewLoginRefusal(sessioninfo.RefusedInvalidCode, httpio.NewUnauthorizedMessage("the code is not the one sent"))
}

func errCodeExpired() error {
	return sessioninfo.NewLoginRefusal(sessioninfo.RefusedCodeExpired, httpio.NewUnauthorizedMessage("no sign-in code stands: ask for a new one"))
}

// verifyEmailCode checks code against the one standing for p and consumes it: a wrong
// code counts, and the code that took its last attempt is consumed. A code entered
// while none stands, because none was sent or the one sent expired or died, is
// refused as expired. It returns the address the code went to.
func (a *Auth[S, U, Tx]) verifyEmailCode(ctx context.Context, p *pendingState, code string) (string, error) {
	standing, err := a.storage.FactorCode(ctx, p.ID)
	if err != nil {
		if httpio.HasNotFound(err) {
			return "", errCodeExpired()
		}

		return "", errors.Wrap(err, "sessionstorage.AuthStore.FactorCode()")
	}
	code = strings.ReplaceAll(strings.TrimSpace(code), " ", "")
	if subtle.ConstantTimeCompare(standing.CodeHash, hashEmailCode(p.ID, code)) != 1 {
		attempts, err := a.storage.RecordFactorCodeAttempt(ctx, standing.ID)
		if err != nil {
			if httpio.HasNotFound(err) {
				return "", errCodeExpired()
			}

			return "", errors.Wrap(err, "sessionstorage.AuthStore.RecordFactorCodeAttempt()")
		}
		if attempts >= emailCodeAttempts {
			if err := a.storage.ConsumeFactorCode(ctx, standing.ID); err != nil && !httpio.HasNotFound(err) {
				return "", errors.Wrap(err, "sessionstorage.AuthStore.ConsumeFactorCode()")
			}

			return "", errCodeExpired()
		}

		return "", errInvalidCode()
	}
	if err := a.storage.ConsumeFactorCode(ctx, standing.ID); err != nil {
		if httpio.HasNotFound(err) {
			return "", errCodeExpired()
		}

		return "", errors.Wrap(err, "sessionstorage.AuthStore.ConsumeFactorCode()")
	}

	return standing.Email, nil
}

// completeWithEmailCode completes the pending MFA wait p once code proved the person
// reads email: the pending identity is consumed, the address is written on the user
// verified when it was not, and the session starts with an email-code event. With
// remember, a session that starts makes the browser a trusted device of the user.
func (a *Auth[S, U, Tx]) completeWithEmailCode(ctx context.Context, w http.ResponseWriter, p *pendingState, code string, remember bool) (*signInOutcome, error) {
	email, err := a.verifyEmailCode(ctx, p, code)
	if err != nil {
		return nil, err
	}
	if err := a.consumePending(ctx, p); err != nil {
		return nil, err
	}
	a.claimCodeAddress(ctx, p.UserID.UUID, email)

	outcome, err := a.completePending(ctx, w, p, sessioninfo.ReasonStepUp, sessioninfo.AuthEvent{Method: sessioninfo.MethodEmailCode})
	if err != nil {
		return nil, err
	}
	if outcome.pending == nil {
		// The person proved who they are: the name's failed attempts are reset.
		a.clearAttempts(ctx, p.Username)
		if remember {
			a.rememberDevice(ctx, w, outcome.userID)
		}
	}

	return outcome, nil
}

// claimCodeAddress writes the address a code proved onto the user, verified, when the
// user does not hold it verified already. It is bookkeeping after the proof: a failure
// is logged, and the sign-in goes on.
func (a *Auth[S, U, Tx]) claimCodeAddress(ctx context.Context, userID ccc.UUID, email string) {
	user, err := a.storage.User(ctx, userID)
	if err != nil {
		logger.FromCtx(ctx).Error(errors.Wrap(err, "sessionstorage.AuthStore.User()"))

		return
	}
	if user.EmailVerified() && strings.EqualFold(*user.Email, email) {
		return
	}
	if err := a.storage.VerifyUserEmail(ctx, userID, email); err != nil {
		logger.FromCtx(ctx).Error(errors.Wrap(err, "sessionstorage.AuthStore.VerifyUserEmail()"))

		return
	}
	logger.FromCtx(ctx).Infof("user %s verified the email address %s by the sign-in code", userID, email)
	if a.registered().usernameIsEmail() && !strings.EqualFold(user.Username, email) && a.userRenamed != nil {
		if err := a.userRenamed(ctx, userID, user.Username, email); err != nil {
			logger.FromCtx(ctx).Errorf("user %s was renamed from %q to %q by the sign-in code, and the rename hook failed; run the hook's work by hand: %v", userID, user.Username, email, err)
		}
	}
}

// trustedCookieKey is the trusted device cookie's value holding the token.
const trustedCookieKey cookie.Key = "trusted"

// trustedCtxKey is the context key for the hash of the browser's trusted device
// token, set by StartSession.
type trustedCtxKey struct{}

// withTrustedDeviceCookie returns ctx with the hash of the trusted device token from
// the trusted device cookie, if the browser carries one.
func (a *Auth[S, U, Tx]) withTrustedDeviceCookie(ctx context.Context, r *http.Request) context.Context {
	cval, found, err := a.trustedCookies.Cookie().Read(r, a.settings.factors.trustedCookie)
	if err != nil || !found {
		return ctx
	}
	token, err := cval.GetString(trustedCookieKey)
	if err != nil {
		return ctx
	}
	raw, err := base64.RawURLEncoding.DecodeString(token)
	if err != nil || len(raw) != trustedTokenSize {
		logger.FromCtx(ctx).Warn("trusted device cookie ignored: not a device token")

		return ctx
	}

	return context.WithValue(ctx, trustedCtxKey{}, hashPendingToken(raw))
}

// trustedTokenHash returns the hash of the browser's trusted device token from ctx.
func trustedTokenHash(ctx context.Context) ([]byte, bool) {
	hash, ok := ctx.Value(trustedCtxKey{}).([]byte)

	return hash, ok
}

// trustedDeviceOf is the sign-in flow's trusted device check: whether the browser
// carries the token of a live trusted device of userID. A cookie naming a dead device,
// or another user's, is no device.
func (a *Auth[S, U, Tx]) trustedDeviceOf(ctx context.Context, userID ccc.UUID) (bool, error) {
	hash, ok := trustedTokenHash(ctx)
	if !ok {
		return false, nil
	}
	device, err := a.storage.TrustedDevice(ctx, hash)
	if err != nil {
		if httpio.HasNotFound(err) {
			return false, nil
		}

		return false, errors.Wrap(err, "sessionstorage.AuthStore.TrustedDevice()")
	}

	return device.UserID == userID, nil
}

// touchTrustedDevice moves the last use of the browser's trusted device once it stood
// in for the factor (events carry a trusted-device event). It is bookkeeping: a
// failure is logged.
func (a *Auth[S, U, Tx]) touchTrustedDevice(ctx context.Context, events []sessioninfo.AuthEvent) {
	hash, ok := trustedTokenHash(ctx)
	if !ok || !slices.ContainsFunc(events, func(e sessioninfo.AuthEvent) bool { return e.Method == sessioninfo.MethodTrustedDevice }) {
		return
	}
	device, err := a.storage.TrustedDevice(ctx, hash)
	if err != nil {
		logger.FromCtx(ctx).Error(errors.Wrap(err, "sessionstorage.AuthStore.TrustedDevice()"))

		return
	}
	if err := a.storage.TouchTrustedDevice(ctx, device.ID); err != nil {
		logger.FromCtx(ctx).Error(errors.Wrap(err, "sessionstorage.AuthStore.TouchTrustedDevice()"))
	}
}

// rememberDevice makes the browser a trusted device of userID for the trusted device
// period: a row with the token's hash, and the cookie with the token. A failure is
// logged; the session stands and the next sign-in asks for the factor again.
func (a *Auth[S, U, Tx]) rememberDevice(ctx context.Context, w http.ResponseWriter, userID ccc.UUID) {
	raw := make([]byte, trustedTokenSize)
	if _, err := rand.Read(raw); err != nil {
		logger.FromCtx(ctx).Error(errors.Wrap(err, "rand.Read()"))

		return
	}
	period := a.settings.factors.trustedPeriod
	device := &sessionstorage.TrustedDevice{UserID: userID, TokenHash: hashPendingToken(raw), ExpiresAt: time.Now().Add(period)}
	if err := a.storage.InsertTrustedDevice(ctx, device); err != nil {
		logger.FromCtx(ctx).Error(errors.Wrap(err, "sessionstorage.AuthStore.InsertTrustedDevice()"))

		return
	}
	// Lax, so the cookie reaches the callback an external sign-in's provider
	// redirects the browser to, where the sign-in is decided.
	cval := cookie.NewValues().SetString(trustedCookieKey, base64.RawURLEncoding.EncodeToString(raw))
	a.trustedCookies.Cookie().WritePersistentCookie(w, a.settings.factors.trustedCookie, a.trustedCookies.Domain, true, http.SameSiteLaxMode, period, cval)
}

// forgetTrustedCookie deletes the trusted device cookie the browser carries, if any.
func (a *Auth[S, U, Tx]) forgetTrustedCookie(ctx context.Context, w http.ResponseWriter) {
	if _, ok := trustedTokenHash(ctx); !ok {
		return
	}
	a.trustedCookies.Cookie().Delete(w, a.settings.factors.trustedCookie, a.trustedCookies.Domain)
}

// pendingSendCode is Pending().SendCode().
func (a *Auth[S, U, Tx]) pendingSendCode() http.HandlerFunc {
	return a.baseSession.Handle(func(w http.ResponseWriter, r *http.Request) error {
		ctx, span := tracer.Start(r.Context())
		defer span.End()

		p, err := a.mfaWait(ctx)
		if err != nil {
			return writeSignInError(ctx, w, err)
		}
		answer, err := a.sendCodeToUser(ctx, p)
		if err != nil {
			return writeSignInError(ctx, w, err)
		}

		return httpio.NewEncoder(w).Ok(answer)
	})
}

// pendingEnrollEmail is Pending().EnrollEmail().
func (a *Auth[S, U, Tx]) pendingEnrollEmail() http.HandlerFunc {
	return a.baseSession.Handle(func(w http.ResponseWriter, r *http.Request) error {
		ctx, span := tracer.Start(r.Context())
		defer span.End()

		p, err := a.mfaWait(ctx)
		if err != nil {
			return writeSignInError(ctx, w, err)
		}
		req, err := emailDecoder.Decode(r)
		if err != nil {
			return httpio.NewEncoder(w).ClientMessage(ctx, err)
		}
		answer, err := a.enrollEmail(ctx, p, req.Email)
		if err != nil {
			return writeSignInError(ctx, w, err)
		}

		return httpio.NewEncoder(w).Ok(answer)
	})
}

// pendingVerifyCode is Pending().VerifyCode().
func (a *Auth[S, U, Tx]) pendingVerifyCode() http.HandlerFunc {
	type request struct {
		Code           string `json:"code"`
		RememberDevice bool   `json:"rememberDevice"`
	}
	decoder := sessioncore.NewDecoder[request]()

	return a.baseSession.Handle(func(w http.ResponseWriter, r *http.Request) error {
		ctx, span := tracer.Start(r.Context())
		defer span.End()

		p, err := a.mfaWait(ctx)
		if err != nil {
			return writeSignInError(ctx, w, err)
		}
		req, err := decoder.Decode(r)
		if err != nil {
			return httpio.NewEncoder(w).ClientMessage(ctx, err)
		}
		outcome, err := a.completeWithEmailCode(ctx, w, p, req.Code, req.RememberDevice)
		if err != nil {
			return writeSignInError(ctx, w, err)
		}

		return a.answerSignIn(ctx, w, r, outcome)
	})
}

// SendEmailCode mails the pending identity's user a one-time code for the second
// factor, to the address the user holds, replacing a code standing, and returns the
// masked address and when the code stops being accepted. The pending identity must
// wait for MFA and the policy accept the email code (Conflict otherwise), and the user
// must hold an address (Conflict: EnrollEmail takes one). It reads the pending
// identity StartSession found, and needs mail (WithMail).
func (p *AuthAPI[S, U, Tx]) SendEmailCode(ctx context.Context) (codeEmail string, expiresAt time.Time, err error) {
	ctx, span := tracer.Start(ctx)
	defer span.End()

	if _, err := p.auth.mailOf(); err != nil {
		return "", time.Time{}, err
	}
	pending, err := p.auth.mfaWait(ctx)
	if err != nil {
		return "", time.Time{}, err
	}
	answer, err := p.auth.sendCodeToUser(ctx, pending)
	if err != nil {
		return "", time.Time{}, err
	}

	return answer.CodeEmail, *answer.CodeExpiresAt, nil
}

// EnrollEmail mails the code to email for a pending identity whose user holds no
// address; the address is written on the user, verified, when the code is entered. A
// user who holds an address is refused (Conflict). An address another account holds
// is told so by mail, and the call returns as if sent. See SendEmailCode.
func (p *AuthAPI[S, U, Tx]) EnrollEmail(ctx context.Context, email string) error {
	ctx, span := tracer.Start(ctx)
	defer span.End()

	if _, err := p.auth.mailOf(); err != nil {
		return err
	}
	pending, err := p.auth.mfaWait(ctx)
	if err != nil {
		return err
	}
	if _, err := p.auth.enrollEmail(ctx, pending, email); err != nil {
		return err
	}

	return nil
}

// VerifyEmailCode completes the pending identity when code is the one sent, as
// CompletePending does with an email-code event, and returns the session's id; with
// rememberDevice the browser is remembered as a trusted device of the user. A wrong
// code is a *sessioninfo.LoginRefusal carrying RefusedInvalidCode and leaves the code
// standing with one fewer attempt; a code that expired, was used or took its last
// attempt, or entered before one was sent, is one carrying RefusedCodeExpired. If the
// sign-in must wait again, the error is a *signin.PendingSignInError.
func (p *AuthAPI[S, U, Tx]) VerifyEmailCode(ctx context.Context, w http.ResponseWriter, code string, rememberDevice bool) (ccc.UUID, error) {
	ctx, span := tracer.Start(ctx)
	defer span.End()

	pending, err := p.auth.mfaWait(ctx)
	if err != nil {
		return ccc.NilUUID, err
	}
	outcome, err := p.auth.completeWithEmailCode(ctx, w, pending, code, rememberDevice)
	if err != nil {
		return ccc.NilUUID, err
	}
	if outcome.pending != nil {
		return ccc.NilUUID, stillPending(outcome.pending)
	}

	return outcome.sessionID, nil
}

// ResetFactors is an administrator's reset of a user's second factor: every browser
// the person asked to be remembered is forgotten, so their next sign-in from any of
// them asks for the factor. The email code itself has nothing to reset: a person who
// lost their mailbox is given a new address (SetSessionUserEmail), unverified, and the
// next code proves it. Live sessions are not touched; DestroyUserSessions ends them.
func (p *AuthAPI[S, U, Tx]) ResetFactors(ctx context.Context, userID ccc.UUID) error {
	ctx, span := tracer.Start(ctx)
	defer span.End()

	if err := p.auth.storage.RevokeTrustedDevices(ctx, userID); err != nil {
		return errors.Wrap(err, "sessionstorage.AuthStore.RevokeTrustedDevices()")
	}

	return nil
}

// ForgetTrustedDevice forgets the browser of the current request as a trusted device:
// its device is revoked and its cookie deleted, so the next sign-in from it asks for
// the factor. A browser that is no trusted device is left as it is.
func (p *AuthAPI[S, U, Tx]) ForgetTrustedDevice(ctx context.Context, w http.ResponseWriter) error {
	ctx, span := tracer.Start(ctx)
	defer span.End()

	hash, ok := trustedTokenHash(ctx)
	if !ok {
		return nil
	}
	if err := p.auth.storage.RevokeTrustedDevice(ctx, hash); err != nil && !httpio.HasNotFound(err) {
		return errors.Wrap(err, "sessionstorage.AuthStore.RevokeTrustedDevice()")
	}
	p.auth.forgetTrustedCookie(ctx, w)

	return nil
}
