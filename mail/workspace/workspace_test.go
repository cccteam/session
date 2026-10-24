package workspace

import (
	"bufio"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"io"
	"math/big"
	"mime/quotedprintable"
	"net"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/cccteam/session/mail"
)

// relay is a test SMTP relay: it speaks the dialog the driver expects (greeting, EHLO,
// STARTTLS, EHLO again, AUTH PLAIN, MAIL, RCPT, DATA, QUIT) over a self-signed
// certificate, records what it was told, and refuses what the test tells it to.
type relay struct {
	addr      string
	cert      tls.Certificate
	pool      *x509.CertPool
	loginOK   func(user, pass string) bool
	rcptOK    func(addr string) bool
	mu        sync.Mutex
	from      string
	rcpt      string
	message   string
	loginUser string
}

func newRelay(t *testing.T, loginOK func(user, pass string) bool, rcptOK func(addr string) bool) *relay {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	template := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "127.0.0.1"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
		IPAddresses:  []net.IP{net.ParseIP("127.0.0.1")},
		KeyUsage:     x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	pool := x509.NewCertPool()
	pool.AddCert(cert)
	ln, err := (&net.ListenConfig{}).Listen(context.Background(), "tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	r := &relay{addr: ln.Addr().String(), cert: tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key}, pool: pool, loginOK: loginOK, rcptOK: rcptOK}
	t.Cleanup(func() { _ = ln.Close() })
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			go r.serve(conn)
		}
	}()

	return r
}

func (r *relay) serve(conn net.Conn) {
	defer conn.Close()
	rw := bufio.NewReadWriter(bufio.NewReader(conn), bufio.NewWriter(conn))
	say := func(line string) { _, _ = rw.WriteString(line + "\r\n"); _ = rw.Flush() }
	say("220 relay.test ESMTP")
	secure := false
	for {
		line, err := rw.ReadString('\n')
		if err != nil {
			return
		}
		line = strings.TrimRight(line, "\r\n")
		verb, arg, _ := strings.Cut(line, " ")
		switch strings.ToUpper(verb) {
		case "EHLO":
			if secure {
				say("250-relay.test")
				say("250 AUTH PLAIN LOGIN")
			} else {
				say("250-relay.test")
				say("250 STARTTLS")
			}
		case "STARTTLS":
			say("220 Ready to start TLS")
			tlsConn := tls.Server(conn, &tls.Config{Certificates: []tls.Certificate{r.cert}, MinVersion: tls.VersionTLS12})
			if err := tlsConn.HandshakeContext(context.Background()); err != nil {
				return
			}
			conn = tlsConn
			rw = bufio.NewReadWriter(bufio.NewReader(conn), bufio.NewWriter(conn))
			secure = true
		case "AUTH":
			_, creds, _ := strings.Cut(arg, " ")
			decoded, _ := base64.StdEncoding.DecodeString(creds)
			parts := strings.Split(string(decoded), "\x00")
			if len(parts) != 3 || !r.loginOK(parts[1], parts[2]) {
				say("535-5.7.8 Username and Password not accepted.")
				say("535 5.7.8 https://support.google.com/mail/?p=BadCredentials")

				continue
			}
			r.mu.Lock()
			r.loginUser = parts[1]
			r.mu.Unlock()
			say("235 2.7.0 Accepted")
		case "MAIL":
			r.mu.Lock()
			r.from = strings.TrimSuffix(strings.TrimPrefix(arg, "FROM:<"), ">")
			r.mu.Unlock()
			say("250 2.1.0 OK")
		case "RCPT":
			addr := strings.TrimSuffix(strings.TrimPrefix(arg, "TO:<"), ">")
			if !r.rcptOK(addr) {
				say("550 5.1.1 The email account that you tried to reach does not exist.")

				continue
			}
			r.mu.Lock()
			r.rcpt = addr
			r.mu.Unlock()
			say("250 2.1.5 OK")
		case "DATA":
			say("354 Go ahead")
			var b strings.Builder
			for {
				l, err := rw.ReadString('\n')
				if err != nil {
					return
				}
				if l == ".\r\n" {
					break
				}
				b.WriteString(l)
			}
			r.mu.Lock()
			r.message = b.String()
			r.mu.Unlock()
			say("250 2.0.0 OK queued")
		case "QUIT":
			say("221 2.0.0 closing connection")

			return
		default:
			say("502 5.5.1 Unrecognized command")
		}
	}
}

func (r *relay) sender(t *testing.T, settings Settings) *Sender {
	t.Helper()
	settings.Relay = r.addr
	s, err := New(&settings)
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	s.tls.RootCAs = r.pool
	s.tls.ServerName = "127.0.0.1"

	return s
}

func accept(string, string) bool { return true }

func anyRecipient(string) bool { return true }

func TestNew(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name     string
		settings Settings
		wantErr  string
	}{
		{name: "the defaults fill in", settings: Settings{Mailbox: "no-reply@example.com", AppPassword: "abcd efgh ijkl mnop"}},
		{name: "a mailbox that is not an address", settings: Settings{Mailbox: "no-reply", AppPassword: "x"}, wantErr: `the mailbox "no-reply" is not an address`},
		{name: "a From that is not an address", settings: Settings{Mailbox: "ops@example.com", AppPassword: "x", From: "no-reply"}, wantErr: `the From address "no-reply" is not an address`},
		{name: "no settings", wantErr: "no settings"},
		{name: "no app password", settings: Settings{Mailbox: "no-reply@example.com"}, wantErr: "no app password"},
		{name: "a relay without a port", settings: Settings{Mailbox: "no-reply@example.com", AppPassword: "x", Relay: "smtp-relay.gmail.com"}, wantErr: `the relay "smtp-relay.gmail.com" is not host:port`},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			given := &tt.settings
			if tt.name == "no settings" {
				given = nil
			}
			s, err := New(given)
			if tt.wantErr != "" {
				if err == nil || !strings.Contains(err.Error(), tt.wantErr) {
					t.Fatalf("New() error = %v, want %q", err, tt.wantErr)
				}

				return
			}
			if err != nil {
				t.Fatalf("New() error = %v", err)
			}
			if s.settings.Relay != DefaultRelay || s.settings.Timeout != DefaultTimeout || s.host != "smtp-relay.gmail.com" {
				t.Errorf("defaults = relay %q timeout %v host %q", s.settings.Relay, s.settings.Timeout, s.host)
			}
			if got := s.Describe(); got != "Google Workspace SMTP relay smtp-relay.gmail.com:587 as no-reply@example.com" {
				t.Errorf("Describe() = %q", got)
			}
		})
	}
}

func TestSender_Send(t *testing.T) {
	t.Parallel()

	r := newRelay(t, func(user, pass string) bool { return user == "no-reply@example.com" && pass == "abcd efgh ijkl mnop" }, func(addr string) bool { return addr != "nobody@example.net" })
	s := r.sender(t, Settings{Mailbox: "no-reply@example.com", AppPassword: "abcd efgh ijkl mnop", Name: "Harbor"})
	msg := mail.Message{To: "Ada Lovelace <ada@example.net>", Subject: "You are invited to Acme — Sie sind eingeladen", Text: "Hello Ada,\n\nFollow https://harbor.example.com/invitations/abc to join Acme.\n\n— Harbor"}
	if err := s.Send(t.Context(), msg); err != nil {
		t.Fatalf("Send() error = %v", err)
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.loginUser != "no-reply@example.com" || r.from != "no-reply@example.com" || r.rcpt != "ada@example.net" {
		t.Errorf("relay saw login %q, from %q, rcpt %q", r.loginUser, r.from, r.rcpt)
	}
	for _, want := range []string{
		"From: \"Harbor\" <no-reply@example.com>\r\n",
		"To: \"Ada Lovelace\" <ada@example.net>\r\n",
		"Subject: =?utf-8?q?You_are_invited_to_Acme_=E2=80=94_Sie_sind_eingeladen?=\r\n",
		"MIME-Version: 1.0\r\n",
		"Content-Type: text/plain; charset=utf-8\r\n",
		"Content-Transfer-Encoding: quoted-printable\r\n",
		"Message-ID: <",
		"@example.com>\r\n",
	} {
		if !strings.Contains(r.message, want) {
			t.Errorf("the message lacks %q:\n%s", want, r.message)
		}
	}
	_, body, ok := strings.Cut(r.message, "\r\n\r\n")
	if !ok {
		t.Fatalf("the message has no body:\n%s", r.message)
	}
	decoded, err := io.ReadAll(quotedprintable.NewReader(strings.NewReader(body)))
	if err != nil {
		t.Fatal(err)
	}
	if want := "Hello Ada,\n\nFollow https://harbor.example.com/invitations/abc to join Acme.\n\n— Harbor"; strings.TrimRight(strings.ReplaceAll(string(decoded), "\r\n", "\n"), "\n") != want {
		t.Errorf("body = %q, want %q", decoded, want)
	}
}

func TestSender_Send_refusals(t *testing.T) {
	t.Parallel()

	r := newRelay(t, func(_, pass string) bool { return pass == "right" }, func(addr string) bool { return addr != "nobody@example.net" })
	tests := []struct {
		name     string
		settings Settings
		msg      mail.Message
		ctx      func(t *testing.T) context.Context
		wantErr  []string
	}{
		{
			name:     "the relay refuses the login in its words, and the driver says what it takes",
			settings: Settings{Mailbox: "no-reply@example.com", AppPassword: "wrong"},
			msg:      mail.Message{To: "ada@example.net", Subject: "s", Text: "t"},
			wantErr:  []string{"the relay refused the login as no-reply@example.com (two-step verification on the mailbox and its app password are what it takes)", "535", "Username and Password not accepted"},
		},
		{
			name:     "the relay refuses a recipient",
			settings: Settings{Mailbox: "no-reply@example.com", AppPassword: "right"},
			msg:      mail.Message{To: "nobody@example.net", Subject: "s", Text: "t"},
			wantErr:  []string{"the relay refused the recipient nobody@example.net", "550", "The email account that you tried to reach does not exist"},
		},
		{
			name:     "a message that cannot be sent is refused before the relay is dialed",
			settings: Settings{Mailbox: "no-reply@example.com", AppPassword: "right"},
			msg:      mail.Message{To: "ada@example.net", Subject: "s"},
			wantErr:  []string{"the message has no body"},
		},
		{
			name:     "a context already done is an error, not a hang",
			settings: Settings{Mailbox: "no-reply@example.com", AppPassword: "right"},
			msg:      mail.Message{To: "ada@example.net", Subject: "s", Text: "t"},
			ctx: func(t *testing.T) context.Context {
				t.Helper()
				ctx, cancel := context.WithCancel(t.Context())
				cancel()

				return ctx
			},
			wantErr: []string{"dialing the relay"},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			s := r.sender(t, tt.settings)
			ctx := t.Context()
			if tt.ctx != nil {
				ctx = tt.ctx(t)
			}
			err := s.Send(ctx, tt.msg)
			if err == nil {
				t.Fatalf("Send() error = nil, want %q", tt.wantErr)
			}
			for _, want := range tt.wantErr {
				if !strings.Contains(err.Error(), want) {
					t.Errorf("Send() error = %v, want it to carry %q", err, want)
				}
			}
		})
	}
}

func TestNew_from(t *testing.T) {
	t.Parallel()

	s, err := New(&Settings{Mailbox: "ops@example.com", AppPassword: "abcd efgh ijkl mnop", From: "no-reply@example.com"})
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	if got := s.Describe(); got != "Google Workspace SMTP relay smtp-relay.gmail.com:587 as ops@example.com, from no-reply@example.com" {
		t.Errorf("Describe() = %q", got)
	}
}

// The From address differs from the mailbox: the relay sees the mailbox at the login and the
// From address as the sender, and the message carries the From address, its domain on the id.
func TestSender_Send_from(t *testing.T) {
	t.Parallel()

	r := newRelay(t, func(user, pass string) bool { return user == "ops@example.com" && pass == "abcd efgh ijkl mnop" }, func(addr string) bool { return true })
	s := r.sender(t, Settings{Mailbox: "ops@example.com", AppPassword: "abcd efgh ijkl mnop", From: "no-reply@example.org", Name: "Harbor"})
	if err := s.Send(t.Context(), mail.Message{To: "ada@example.net", Subject: "Hello", Text: "Hello Ada"}); err != nil {
		t.Fatalf("Send() error = %v", err)
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.loginUser != "ops@example.com" || r.from != "no-reply@example.org" || r.rcpt != "ada@example.net" {
		t.Errorf("relay saw login %q, from %q, rcpt %q", r.loginUser, r.from, r.rcpt)
	}
	for _, want := range []string{"From: \"Harbor\" <no-reply@example.org>\r\n", "@example.org>\r\n"} {
		if !strings.Contains(r.message, want) {
			t.Errorf("the message lacks %q:\n%s", want, r.message)
		}
	}
}
