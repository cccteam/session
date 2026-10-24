// Package workspace sends the session library's mail through the Google Workspace SMTP
// relay: a plain mail submission to smtp-relay.gmail.com on port 587 over TLS, which
// Google Cloud's compute products allow (they block port 25, the port a mail server of
// our own would need), authenticated as one mailbox of the organization's Workspace
// domain with an app password. Google carries delivery, reputation and signing from
// there. The mailbox is the From address of every message unless the settings name
// another: an organization sends as one dedicated address, a no-reply mailbox as a rule,
// and that address may be an alias of the account that logs in, since the relay accepts
// any From in the organization's domains once the login is a real account, while an
// alias cannot log in itself.
//
// What the Workspace side needs, once per organization: the mailbox, with two-step
// verification turned on and an app password generated for it (Google issues app
// passwords only to accounts with two-step verification, and the password stands in for
// the account's at the relay's login, with no second step); and the SMTP relay service
// in the admin console, under Gmail routing, accepting mail from addresses in the
// organization's domains with authentication and TLS required. The app password is a
// secret the deployment carries as a pinned version; rotating it is generating a new one
// and pinning it, with nothing to change in the application. The relay allows a sending
// address ten thousand messages a day, far beyond what invitations and verification
// links need.
package workspace

import (
	"context"
	"crypto/rand"
	"crypto/tls"
	"encoding/hex"
	"fmt"
	"io"
	"mime"
	"mime/quotedprintable"
	"net"
	netmail "net/mail"
	"net/smtp"
	"strings"
	"time"

	"github.com/go-playground/errors/v5"

	"github.com/cccteam/session/mail"
)

// DefaultRelay is the Workspace SMTP relay, on the submission port Google Cloud allows.
const DefaultRelay = "smtp-relay.gmail.com:587"

// DefaultTimeout is how long one send may take, dialing included.
const DefaultTimeout = 30 * time.Second

// Settings configures the driver.
type Settings struct {
	// Mailbox is the Workspace account the driver logs in to the relay as, and, unless
	// From names another address, the address every message is from:
	// no-reply@example.com.
	Mailbox string
	// From is the address every message is from when it is not the mailbox: an alias of
	// the mailbox, or another address of the organization's domains, which the relay
	// accepts with the mailbox's login. Empty sends from the mailbox.
	From string
	// AppPassword is the mailbox's app password. It is a secret; the deployment reads it
	// from its secret store, never from a file in the repository.
	AppPassword string
	// Name is the display name beside the address on From ("Harbor"); empty sends the
	// bare address.
	Name string
	// Relay is the relay's host and port; empty is DefaultRelay. Tests point it at a
	// server of their own.
	Relay string
	// Timeout is how long one send may take; zero is DefaultTimeout.
	Timeout time.Duration
}

// Sender sends through the relay.
type Sender struct {
	settings Settings
	host     string
	// hello is the name the driver introduces itself with (EHLO): the mailbox's domain.
	// Google's relay closes the connection on a generic name such as "localhost", the Go
	// client's default, and asks for the sender's domain or mail server's name instead.
	hello string
	tls   *tls.Config
	dial  func(ctx context.Context, address string) (net.Conn, error)
}

// New builds the driver from a copy of the settings, refusing settings it cannot send
// with: a mailbox or a From that is not an address, no app password, a relay that is not
// host:port.
func New(given *Settings) (*Sender, error) {
	if given == nil {
		return nil, errors.New("workspace: no settings")
	}
	settings := *given
	if _, err := netmail.ParseAddress(settings.Mailbox); err != nil {
		return nil, errors.Wrapf(err, "workspace: the mailbox %q is not an address", settings.Mailbox)
	}
	if settings.From == "" {
		settings.From = settings.Mailbox
	}
	if _, err := netmail.ParseAddress(settings.From); err != nil {
		return nil, errors.Wrapf(err, "workspace: the From address %q is not an address", settings.From)
	}
	if strings.TrimSpace(settings.AppPassword) == "" {
		return nil, errors.New("workspace: no app password: the relay's login needs the mailbox's app password (two-step verification on the mailbox, then an app password generated for it)")
	}
	if settings.Relay == "" {
		settings.Relay = DefaultRelay
	}
	host, _, err := net.SplitHostPort(settings.Relay)
	if err != nil {
		return nil, errors.Wrapf(err, "workspace: the relay %q is not host:port", settings.Relay)
	}
	if settings.Timeout <= 0 {
		settings.Timeout = DefaultTimeout
	}
	dialer := &net.Dialer{}

	return &Sender{
		settings: settings,
		host:     host,
		hello:    settings.Mailbox[strings.LastIndex(settings.Mailbox, "@")+1:],
		tls:      &tls.Config{ServerName: host, MinVersion: tls.VersionTLS12},
		dial: func(ctx context.Context, address string) (net.Conn, error) {
			return dialer.DialContext(ctx, "tcp", address)
		},
	}, nil
}

// Send submits one message to the relay: dial, introduce the mailbox's domain, STARTTLS,
// log in as the mailbox, name the From address as the sender, and hand the message over. The relay's refusals come back in its words, after the step that
// drew them.
func (s *Sender) Send(ctx context.Context, msg mail.Message) error {
	if err := msg.Validate(); err != nil {
		return errors.Wrap(err, "mail.Message.Validate()")
	}
	ctx, cancel := context.WithTimeout(ctx, s.settings.Timeout)
	defer cancel()
	conn, err := s.dial(ctx, s.settings.Relay)
	if err != nil {
		return errors.Wrapf(err, "workspace: dialing the relay %s", s.settings.Relay)
	}
	defer conn.Close()
	if deadline, ok := ctx.Deadline(); ok {
		if err := conn.SetDeadline(deadline); err != nil {
			return errors.Wrap(err, "net.Conn.SetDeadline()")
		}
	}
	stop := context.AfterFunc(ctx, func() { _ = conn.Close() })
	defer stop()

	client, err := smtp.NewClient(conn, s.host)
	if err != nil {
		return errors.Wrapf(err, "workspace: the relay %s did not greet", s.settings.Relay)
	}
	defer client.Close()
	if err := client.Hello(s.hello); err != nil {
		return errors.Wrapf(err, "workspace: the relay %s refused the introduction as %s", s.settings.Relay, s.hello)
	}
	if err := client.StartTLS(s.tls); err != nil {
		return errors.Wrapf(err, "workspace: STARTTLS with the relay %s", s.settings.Relay)
	}
	if err := client.Auth(smtp.PlainAuth("", s.settings.Mailbox, s.settings.AppPassword, s.host)); err != nil {
		return errors.Wrapf(err, "workspace: the relay refused the login as %s (two-step verification on the mailbox and its app password are what it takes)", s.settings.Mailbox)
	}
	to, err := netmail.ParseAddress(msg.To)
	if err != nil {
		return errors.Wrapf(err, "workspace: the recipient %q is not an address", msg.To)
	}
	if err := client.Mail(s.settings.From); err != nil {
		return errors.Wrapf(err, "workspace: the relay refused the sender %s", s.settings.From)
	}
	if err := client.Rcpt(to.Address); err != nil {
		return errors.Wrapf(err, "workspace: the relay refused the recipient %s", to.Address)
	}
	w, err := client.Data()
	if err != nil {
		return errors.Wrap(err, "workspace: the relay refused the message")
	}
	if err := s.write(w, to, &msg); err != nil {
		return err
	}
	if err := w.Close(); err != nil {
		return errors.Wrap(err, "workspace: the relay refused the message")
	}
	if err := client.Quit(); err != nil {
		return errors.Wrap(err, "workspace: the relay did not close the session cleanly")
	}

	return nil
}

// write renders the message in RFC 5322 form: the headers, with the subject and the
// display names encoded for any language, and the body as quoted-printable UTF-8.
func (s *Sender) write(w io.Writer, to *netmail.Address, msg *mail.Message) error {
	from := netmail.Address{Name: s.settings.Name, Address: s.settings.From}
	id := make([]byte, 16)
	if _, err := rand.Read(id); err != nil {
		return errors.Wrap(err, "rand.Read()")
	}
	domain := s.settings.From[strings.LastIndex(s.settings.From, "@")+1:]
	headers := []string{
		"From: " + from.String(),
		"To: " + to.String(),
		"Subject: " + mime.QEncoding.Encode("utf-8", msg.Subject),
		"Date: " + time.Now().UTC().Format(time.RFC1123Z),
		"Message-ID: <" + hex.EncodeToString(id) + "@" + domain + ">",
		"MIME-Version: 1.0",
		"Content-Type: text/plain; charset=utf-8",
		"Content-Transfer-Encoding: quoted-printable",
	}
	if _, err := io.WriteString(w, strings.Join(headers, "\r\n")+"\r\n\r\n"); err != nil {
		return errors.Wrap(err, "io.WriteString()")
	}
	qp := quotedprintable.NewWriter(w)
	if _, err := io.WriteString(qp, strings.ReplaceAll(msg.Text, "\r\n", "\n")); err != nil {
		return errors.Wrap(err, "quotedprintable.Writer.Write()")
	}
	if err := qp.Close(); err != nil {
		return errors.Wrap(err, "quotedprintable.Writer.Close()")
	}

	return nil
}

// Describe says where the driver sends and as whom, with the From address when it is
// not the mailbox, for a startup log; the app password is never part of it.
func (s *Sender) Describe() string {
	if s.settings.From != s.settings.Mailbox {
		return fmt.Sprintf("Google Workspace SMTP relay %s as %s, from %s", s.settings.Relay, s.settings.Mailbox, s.settings.From)
	}

	return fmt.Sprintf("Google Workspace SMTP relay %s as %s", s.settings.Relay, s.settings.Mailbox)
}
