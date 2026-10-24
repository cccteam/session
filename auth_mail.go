package session

import (
	"context"
	"encoding/base64"
	"fmt"
	netmail "net/mail"
	"net/url"
	"strings"
	"time"

	"github.com/cccteam/ccc"
	"github.com/cccteam/ccc/tracer"
	"github.com/cccteam/httpio"
	"github.com/cccteam/logger"
	"github.com/cccteam/session/internal/sessioncore"
	"github.com/cccteam/session/mail"
	"github.com/cccteam/session/sessioninfo"
	"github.com/cccteam/session/sessionstorage"
	"github.com/go-playground/errors/v5"
)

// The mail the Auth sends: an invitation, the verification of an address a person
// adds, and the link a sign-up starts from. Each is one plain-text message with one
// link in it, to the login page with the link's token as a query parameter, which the
// page posts back to the route that completes the step. A message reads as
// instructions: what the person did, the link to open and how long it is good for,
// then, under headings of their own, what to do if it was not them and a word to keep
// the link to themselves. The library writes to the mail.Sender interface and knows
// nothing of the mail system behind it; see "Sending mail" in the README.

// MailSettings is how the Auth sends mail: through sender, as the application, with
// links to its login page.
type MailSettings struct {
	// Application is the application's name as the messages say it ("Harbor").
	Application string
	// LoginURL is the absolute URL of the application's login page
	// (https://harbor.example.com/login), where every mailed link leads: with
	// ?invitation=<token> for an invitation, ?verify=<token> for an address
	// verification and ?signUp=<token> for a sign-up. The page posts the token to the
	// matching route.
	LoginURL string
	// InvitationTimeout is how long an invitation stands; zero is seven days.
	InvitationTimeout time.Duration
	// LinkTimeout is how long a verification or sign-up link stands; zero is a day.
	LinkTimeout time.Duration
}

// Default mail link lifetimes.
const (
	defaultInvitationTimeout = 7 * 24 * time.Hour
	defaultLinkTimeout       = 24 * time.Hour
)

// mailLimit bounds the links one address is sent: three within fifteen minutes, then
// none for fifteen minutes. It is kept in the sign-in attempts table under the
// address, as a name's failed attempts are.
var mailLimit = sessionstorage.SignInAttemptLimit{Failures: 3, Window: 15 * time.Minute, Lock: 15 * time.Minute}

// mailSettings are the Auth's mail settings once validated.
type mailSettings struct {
	sender   mail.Sender
	settings MailSettings
}

// WithMail gives the Auth the means to send mail: sender delivers the messages
// (mail/workspace is the Google Workspace relay), and settings say as whom and where
// the links lead. It is needed by invitations (AuthAPI.Invite, Invitation()), the
// add-address step (Email()) and sign-up (SignUp(), with OpenSignUp on the password
// method); an Auth without it offers none of them. NewAuth refuses a nil sender, an
// empty application name and a login URL that is not an absolute http or https URL.
func WithMail(sender mail.Sender, settings MailSettings) AuthOption {
	return authOption{apply: func(s *authSettings) { s.mail = &mailSettings{sender: sender, settings: settings} }}
}

// validate refuses settings the Auth cannot send with and fills the defaults.
func (m *mailSettings) validate() error {
	if m.sender == nil {
		return errors.New("WithMail: the sender is nil: pass a mail.Sender, such as workspace.New")
	}
	if strings.TrimSpace(m.settings.Application) == "" {
		return errors.New("WithMail: the application name is empty: the messages name the application")
	}
	u, err := url.Parse(m.settings.LoginURL)
	if err != nil || (u.Scheme != "https" && u.Scheme != "http") || u.Host == "" || u.Fragment != "" {
		return errors.Newf("WithMail: the login URL %q is not an absolute http or https URL without a fragment: the mailed links lead to the login page", m.settings.LoginURL)
	}
	if m.settings.InvitationTimeout <= 0 {
		m.settings.InvitationTimeout = defaultInvitationTimeout
	}
	if m.settings.LinkTimeout <= 0 {
		m.settings.LinkTimeout = defaultLinkTimeout
	}

	return nil
}

// link renders the login page URL that carries token under param.
func (m *mailSettings) link(param, token string) string {
	sep := "?"
	if strings.Contains(m.settings.LoginURL, "?") {
		sep = "&"
	}

	return m.settings.LoginURL + sep + param + "=" + url.QueryEscape(token)
}

// goodFor renders how long a link is good for in everyday words: minutes under an
// hour, whole hours under two days, days from there. A part of a unit is dropped, so
// the message never promises more than the link gives; under a minute reads as one. A
// person knows when the message reached them, so a duration tells them whether the
// link still stands where a deadline in UTC would not.
func goodFor(d time.Duration) string {
	const day = 24 * time.Hour
	switch {
	case d < time.Hour:
		return count(int(max(d, time.Minute)/time.Minute), "minute")
	case d < 2*day:
		return count(int(d/time.Hour), "hour")
	default:
		return count(int(d/day), "day")
	}
}

// count renders n of unit in words: "1 hour", "6 hours".
func count(n int, unit string) string {
	if n == 1 {
		return "1 " + unit
	}

	return fmt.Sprintf("%d %ss", n, unit)
}

// invitationMessage is the mail an invitation sends: the invitation, the link that
// accepts it and how long the link is good for (lifetime), then what to do if no
// invitation was expected and a word to keep the link to oneself.
func (m *mailSettings) invitationMessage(to, token string, lifetime time.Duration) mail.Message {
	app := m.settings.Application

	return mail.Message{
		To:      to,
		Subject: fmt.Sprintf("You are invited to %s", app),
		Text: fmt.Sprintf(`You are invited to %s.

To accept the invitation, open this link:
%s

The link is good for %s.

Didn't expect this?
If you were not expecting an invitation, ignore this message. Nothing changes.

Keep the link to yourself
Anyone who opens the link can accept the invitation in your place. Don't forward it.
`, app, m.link("invitation", token), goodFor(lifetime)),
	}
}

// verificationMessage is the mail that confirms an address a signed-in person adds. It
// takes for granted that they added it: open the link (the page asks for the sign-in
// itself when none stands), and the link is good for lifetime; then what to do if it
// was not them. The link works only for the account that added the address, so there
// is no word about keeping it private.
func (m *mailSettings) verificationMessage(to, token string, lifetime time.Duration) mail.Message {
	app := m.settings.Application

	return mail.Message{
		To:      to,
		Subject: fmt.Sprintf("Confirm your email address for %s", app),
		Text: fmt.Sprintf(`You added this address to your %s account.

To confirm it, open this link:
%s

The link is good for %s.

Didn't do this?
If you did not add this address, ignore this message. Nothing changes.
`, app, m.link("verify", token), goodFor(lifetime)),
	}
}

// addressHeldMessage is the mail sent when a signed-in person adds an address that
// another account already holds: the screen says nothing, the mailbox's owner learns
// and is pointed at the account that has the address, then told what to do if it was
// not them.
func (m *mailSettings) addressHeldMessage(to string) mail.Message {
	app := m.settings.Application

	return mail.Message{
		To:      to,
		Subject: fmt.Sprintf("Your email address and %s", app),
		Text: fmt.Sprintf(`Someone tried to add this address to another %s account, but it already belongs to an account.

If that was you, sign in to the account that has it.

Didn't do this?
If you did not try to add this address, ignore this message. Nothing changes.
`, app),
	}
}

// signUpMessage is the mail a sign-up starts from: the link to open and choose a
// password at and how long it is good for (lifetime), then what to do if no account
// was asked for and a word to keep the link to oneself.
func (m *mailSettings) signUpMessage(to, token string, lifetime time.Duration) mail.Message {
	app := m.settings.Application

	return mail.Message{
		To:      to,
		Subject: fmt.Sprintf("Finish creating your %s account", app),
		Text: fmt.Sprintf(`You asked to create a %s account with this address.

To finish, open this link and choose your password:
%s

The link is good for %s.

Didn't do this?
If you did not ask for an account, ignore this message. Nothing changes.

Keep the link to yourself
Anyone who opens the link can create the account in your place. Don't forward it.
`, app, m.link("signUp", token), goodFor(lifetime)),
	}
}

// accountExistsMessage is the mail sent when a sign-up names an address an account
// already holds: the person is pointed at their account by mail and told what to do if
// it was not them, and the screen says nothing.
func (m *mailSettings) accountExistsMessage(to string) mail.Message {
	app := m.settings.Application

	return mail.Message{
		To:      to,
		Subject: fmt.Sprintf("You already have a %s account", app),
		Text: fmt.Sprintf(`You asked to create a %s account with this address, but there is already an account for it.

Sign in to %s to use it. If you forgot how, ask your administrator.

Didn't do this?
If you did not ask for an account, ignore this message. Nothing changes.
`, app, app),
	}
}

// mailOf returns the Auth's mail settings, or an error for an Auth without mail.
func (a *Auth[S, U, Tx]) mailOf() (*mailSettings, error) {
	if a.settings.mail == nil {
		return nil, errors.New("the Auth sends no mail: pass WithMail to NewAuth")
	}

	return a.settings.mail, nil
}

// requireMail is mailOf for the handler groups that need mail: a wiring mistake
// panics, as a misregistered method does.
func (a *Auth[S, U, Tx]) requireMail(group string) {
	if a.settings.mail == nil {
		panic(fmt.Sprintf("session: %s needs mail, which this Auth does not send: pass WithMail to NewAuth", group))
	}
}

// send delivers msg through the configured sender. A failure is reported to the person
// as the message not having been sent, never with the mail system's words.
func (a *Auth[S, U, Tx]) send(ctx context.Context, msg mail.Message) error {
	ctx, span := tracer.Start(ctx)
	defer span.End()

	m, err := a.mailOf()
	if err != nil {
		return err
	}
	if err := m.sender.Send(ctx, msg); err != nil {
		return httpio.NewInternalServerErrorMessageWithError(errors.Wrap(err, "mail.Sender.Send()"), "the message could not be sent")
	}

	return nil
}

// address validates an address a person or an operator gave and returns it bare: the
// part a message is sent to, without a display name.
func address(email string) (string, error) {
	parsed, err := netmail.ParseAddress(strings.TrimSpace(email))
	if err != nil || !strings.Contains(parsed.Address, "@") {
		return "", httpio.NewBadRequestMessagef("%q is not an email address", email)
	}

	return parsed.Address, nil
}

// optionalAddress is address for a value that may be absent.
func optionalAddress(email *string) (*string, error) {
	if email == nil {
		return nil, nil
	}
	bare, err := address(*email)
	if err != nil {
		return nil, err
	}

	return &bare, nil
}

// limitMail bounds the links sent to an address (mailLimit): the address's record in
// the sign-in attempts table counts each one, and an address at the limit is refused
// with too_many_attempts and the wait, as a locked name is.
func (a *Auth[S, U, Tx]) limitMail(ctx context.Context, email string) error {
	key := "mail:" + strings.ToLower(email)
	record, err := a.storage.SignInAttempts(ctx, key)
	if err != nil && !httpio.HasNotFound(err) {
		return errors.Wrap(err, "sessionstorage.AuthStore.SignInAttempts()")
	}
	if wait, locked := record.Locked(time.Now()); locked {
		return sessioninfo.NewTooManyAttemptsRefusal(wait)
	}
	if _, err := a.storage.RecordSignInFailure(ctx, key, mailLimit); err != nil {
		return errors.Wrap(err, "sessionstorage.AuthStore.RecordSignInFailure()")
	}

	return nil
}

// minPasswordLength is the shortest password a sign-up accepts.
const minPasswordLength = 8

// acceptedPassword refuses a password a sign-up may not set: shorter than eight
// characters. The rules beyond that are the application's, on its page.
func acceptedPassword(password string) error {
	if len(password) < minPasswordLength {
		return httpio.NewBadRequestMessagef("the password is at least %d characters", minPasswordLength)
	}

	return nil
}

// claimVerifiedEmail writes the address a sign-in method asserts as verified (Google
// verifies the address itself, and the person has just proven they hold the account)
// onto the user as verified, when the user holds no verified address and no other user
// holds it. It is bookkeeping after the session stands: a failure is logged.
func (a *Auth[S, U, Tx]) claimVerifiedEmail(ctx context.Context, userID ccc.UUID, identity *sessioninfo.Identity) {
	if identity == nil || !identity.EmailVerified || identity.Email == "" {
		return
	}
	if _, err := a.storage.ClaimVerifiedEmail(ctx, userID, identity.Email); err != nil {
		logger.FromCtx(ctx).Error(errors.Wrap(err, "sessionstorage.AuthStore.ClaimVerifiedEmail()"))
	}
}

// linkToken is a mailed link's token as the mail carries it and its hash as the row
// keeps it; it is the pending identity's token, made the same way.
func linkToken() (token string, hash []byte, err error) {
	return newPendingToken()
}

// linkTokenHash is the hash of a token a person posted back, or false when it is not
// a token.
func linkTokenHash(token string) ([]byte, bool) {
	raw, err := base64.RawURLEncoding.DecodeString(token)
	if err != nil || len(raw) != pendingTokenSize {
		return nil, false
	}

	return hashPendingToken(raw), true
}

// decodeToken is the decoder of a request that carries a token.
type tokenRequest struct {
	Token string `json:"token"`
}

var tokenDecoder = sessioncore.NewDecoder[tokenRequest]()

// errLinkDead is the answer for a token whose link is no longer live.
func errLinkDead() error {
	return httpio.NewNotFoundMessage("the link has expired or was already used")
}
