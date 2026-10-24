package session

import (
	"context"
	"net/http"
	"time"

	"github.com/cccteam/ccc/tracer"
	"github.com/cccteam/httpio"
	"github.com/cccteam/session/internal/sessioncore"
	"github.com/cccteam/session/sessionstorage"
	"github.com/go-playground/errors/v5"
)

// A sign-up is how a person creates their own account with a password, when the
// password method offers it (OpenSignUp): they give their address, follow the link
// mailed to it, and set a password; the account is created with the address
// verified, since the person just proved they read it. An address an account already
// holds is pointed at that account by mail, and the screen says nothing. See
// "Sign-up" in the README.

// SignUpHandlers are the HTTP handlers of sign-up.
type SignUpHandlers struct {
	start    http.HandlerFunc
	open     http.HandlerFunc
	complete http.HandlerFunc
}

// Start accepts {"email"} and mails that address a link to finish the sign-up. It
// answers {} whatever the address's state, so the screen reveals nothing: an address
// an account already holds is told so by mail. An address that is not one is 400; a
// mailbox sent three links within fifteen minutes is refused with too_many_attempts
// and the wait; 404 when sign-up is not offered. Route it behind StartSession and
// ValidateXSRFToken.
func (h *SignUpHandlers) Start() http.HandlerFunc { return h.start }

// Open accepts {"token"}, the token the mailed link carried, and answers {"email",
// "usernameIsEmail"}: the address, and whether the account's username is the address
// or the person chooses one. A token whose link is no longer live is 404.
func (h *SignUpHandlers) Open() http.HandlerFunc { return h.open }

// Complete accepts {"token", "password", "username"}, creates the account with the
// address verified, and signs the person in, answering as the password login does
// ({"mfaIsRequired"}). username is the address when the password method declares the
// username as the email address, and chosen otherwise. A taken username or address is
// 409, a password under eight characters 400, a token whose link is no longer live
// 404. Route it beside the password login, behind ValidateXSRFToken.
func (h *SignUpHandlers) Complete() http.HandlerFunc { return h.complete }

// SignUp returns the sign-up handlers. It panics on an Auth without mail, as a wiring
// mistake; whether sign-up is offered is the password method's (OpenSignUp), checked
// as each request arrives.
func (a *Auth[S, U, Tx]) SignUp() *SignUpHandlers {
	a.requireMail("SignUp()")

	return &SignUpHandlers{
		start:    a.serving(a.signUpStart()),
		open:     a.serving(a.signUpOpen()),
		complete: a.serving(a.signUpComplete()),
	}
}

// errNoSignUp is the answer when the password method does not offer sign-up.
func errNoSignUp() error {
	return httpio.NewNotFoundMessage("sign-up is not offered here")
}

// signUpStart is SignUp().Start().
func (a *Auth[S, U, Tx]) signUpStart() http.HandlerFunc {
	return a.baseSession.Handle(func(w http.ResponseWriter, r *http.Request) error {
		ctx, span := tracer.Start(r.Context())
		defer span.End()

		if !a.registered().openSignUp() {
			return httpio.NewEncoder(w).ClientMessage(ctx, errNoSignUp())
		}
		req, err := emailDecoder.Decode(r)
		if err != nil {
			return httpio.NewEncoder(w).ClientMessage(ctx, err)
		}
		if err := a.startSignUp(ctx, req.Email); err != nil {
			return writeSignInError(ctx, w, err)
		}

		return httpio.NewEncoder(w).Ok(struct{}{})
	})
}

// startSignUp mails email its sign-up link, or the notice that an account already
// holds it.
func (a *Auth[S, U, Tx]) startSignUp(ctx context.Context, email string) error {
	m, err := a.mailOf()
	if err != nil {
		return err
	}
	bare, err := address(email)
	if err != nil {
		return err
	}
	if err := a.limitMail(ctx, bare); err != nil {
		return err
	}
	if _, err := a.storage.UserByEmail(ctx, bare); err == nil {
		return a.send(ctx, m.accountExistsMessage(bare))
	} else if !httpio.HasNotFound(err) {
		return errors.Wrap(err, "sessionstorage.AuthStore.UserByEmail()")
	}
	token, hash, err := linkToken()
	if err != nil {
		return err
	}
	lifetime := m.settings.LinkTimeout
	link := &sessionstorage.MailLink{TokenHash: hash, Kind: sessionstorage.MailLinkSignUp, Email: bare, ExpiresAt: time.Now().Add(lifetime)}
	if err := a.storage.InsertMailLink(ctx, link); err != nil {
		return errors.Wrap(err, "sessionstorage.AuthStore.InsertMailLink()")
	}

	return a.send(ctx, m.signUpMessage(bare, token, lifetime))
}

// signUpOpen is SignUp().Open().
func (a *Auth[S, U, Tx]) signUpOpen() http.HandlerFunc {
	type response struct {
		Email           string `json:"email"`
		UsernameIsEmail bool   `json:"usernameIsEmail"`
	}

	return a.baseSession.Handle(func(w http.ResponseWriter, r *http.Request) error {
		ctx, span := tracer.Start(r.Context())
		defer span.End()

		methods := a.registered()
		if !methods.openSignUp() {
			return httpio.NewEncoder(w).ClientMessage(ctx, errNoSignUp())
		}
		req, err := tokenDecoder.Decode(r)
		if err != nil {
			return httpio.NewEncoder(w).ClientMessage(ctx, err)
		}
		link, err := a.liveLink(ctx, req.Token, sessionstorage.MailLinkSignUp)
		if err != nil {
			return httpio.NewEncoder(w).ClientMessage(ctx, err)
		}

		return httpio.NewEncoder(w).Ok(response{Email: link.Email, UsernameIsEmail: methods.usernameIsEmail()})
	})
}

// signUpComplete is SignUp().Complete().
func (a *Auth[S, U, Tx]) signUpComplete() http.HandlerFunc {
	type request struct {
		Token    string `json:"token"`
		Password string `json:"password"`
		Username string `json:"username"`
	}
	decoder := sessioncore.NewDecoder[request]()

	return a.baseSession.Handle(func(w http.ResponseWriter, r *http.Request) error {
		ctx, span := tracer.Start(r.Context())
		defer span.End()

		if !a.registered().openSignUp() {
			return httpio.NewEncoder(w).ClientMessage(ctx, errNoSignUp())
		}
		req, err := decoder.Decode(r)
		if err != nil {
			return httpio.NewEncoder(w).ClientMessage(ctx, err)
		}
		user, err := a.completeSignUp(ctx, req.Token, req.Username, req.Password)
		if err != nil {
			return httpio.NewEncoder(w).ClientMessage(ctx, err)
		}

		outcome, err := a.signIn(ctx, w, a.passwordAttempt(user))
		if err != nil {
			return writeSignInError(ctx, w, err)
		}

		return a.answerSignIn(ctx, w, r, outcome)
	})
}

// completeSignUp creates the account a live sign-up link names and consumes the link.
// The account is created first: the address is unique among the users, so two
// completions of one link cannot both create one, and a link consumed meanwhile has
// nothing left to do.
func (a *Auth[S, U, Tx]) completeSignUp(ctx context.Context, token, username, password string) (*sessionstorage.SessionUser, error) {
	link, err := a.liveLink(ctx, token, sessionstorage.MailLinkSignUp)
	if err != nil {
		return nil, err
	}
	user, err := a.createAccount(ctx, link.Email, username, password)
	if err != nil {
		return nil, err
	}
	if err := a.storage.ConsumeMailLink(ctx, link.TokenHash); err != nil && !httpio.HasNotFound(err) {
		return nil, errors.Wrap(err, "sessionstorage.AuthStore.ConsumeMailLink()")
	}

	return user, nil
}
