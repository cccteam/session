// Package mail is how the session library sends mail: the invitation a tenant's
// administrator sends to an address, the link that verifies an address a person adds or
// changes, and the link a password sign-up starts from. The library writes to the Sender
// interface and knows nothing of the mail system behind it; an application configures a
// driver, the Google Workspace SMTP relay in mail/workspace, and hands it to the Auth.
// Every message is plain text with one link in it, from the one address the driver is
// configured to send as.
package mail

import (
	"context"
	netmail "net/mail"
	"strings"
	"sync"

	"github.com/cccteam/logger"
	"github.com/go-playground/errors/v5"
)

// Message is one message to send: the recipient, the subject and the plain-text body.
// The sender's address and display name are the driver's settings, not the message's,
// so every message an application sends comes from the one address it is configured
// with.
type Message struct {
	// To is the recipient's address, one address with or without a display name
	// ("Ada Lovelace <ada@example.com>").
	To string
	// Subject is the subject line, in any language; the driver encodes it.
	Subject string
	// Text is the plain-text body, in any language.
	Text string
}

// Validate refuses a message that cannot be sent: no recipient or one that is not an
// address, no subject, or no body.
func (m *Message) Validate() error {
	switch {
	case strings.TrimSpace(m.To) == "":
		return errors.New("mail: the message has no recipient")
	case strings.TrimSpace(m.Subject) == "":
		return errors.New("mail: the message has no subject")
	case strings.TrimSpace(m.Text) == "":
		return errors.New("mail: the message has no body")
	}
	if _, err := netmail.ParseAddress(m.To); err != nil {
		return errors.Wrapf(err, "mail: the recipient %q is not an address", m.To)
	}

	return nil
}

// Sender sends one message. A driver implements it over a mail system; the library
// calls it from the flows that send mail and reports its error to the person as the
// mail not having been sent, never with the system's own words.
type Sender interface {
	Send(ctx context.Context, msg Message) error
}

// Recorder is a Sender for tests: it keeps every message it was asked to send, in
// order, and answers Err when one is set. It is safe for concurrent use.
type Recorder struct {
	mu sync.Mutex
	// Sent holds the messages sent so far, in order.
	Sent []Message
	// Err, when set, is what Send answers after recording the message.
	Err error
}

// Send records the message and answers Err.
func (r *Recorder) Send(_ context.Context, msg Message) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.Sent = append(r.Sent, msg)

	return r.Err
}

// Messages answers a copy of what was sent so far.
func (r *Recorder) Messages() []Message {
	r.mu.Lock()
	defer r.mu.Unlock()

	return append([]Message(nil), r.Sent...)
}

// Log is a Sender for development: it writes each message to the request's logger, link
// included, and sends nothing, so a developer follows the link from the log. Never for a
// deployed environment, where the links are secrets: there the application configures a
// driver.
type Log struct{}

// Send logs the message at Info.
func (Log) Send(ctx context.Context, msg Message) error {
	if err := msg.Validate(); err != nil {
		return errors.Wrap(err, "mail.Message.Validate()")
	}
	logger.FromCtx(ctx).Infof("mail (not sent) to %s, subject %q:\n%s", msg.To, msg.Subject, msg.Text)

	return nil
}
