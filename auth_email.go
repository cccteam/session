package session

import (
	"context"
	"net/http"
	"time"

	"github.com/cccteam/ccc"
	"github.com/cccteam/ccc/tracer"
	"github.com/cccteam/httpio"
	"github.com/cccteam/logger"
	"github.com/cccteam/session/internal/sessioncore"
	"github.com/cccteam/session/sessioninfo"
	"github.com/cccteam/session/sessionstorage"
	"github.com/go-playground/errors/v5"
)

// A user's email address is trusted for nothing until the person has proven they read
// it by following a link sent to it, and the user record carries the time that
// happened. The person adds and verifies their own address while signed in (Email()):
// nothing is written until the link is followed, and the link counts only for the
// account that asked, so an address never attaches to an account its follower does
// not control. An administrator may put an address on a user by hand, unverified,
// which reserves it (AuthAPI.SetSessionUserEmail). A Google sign-in writes the
// address Google verified. See "Users and their email address" in the README.

// EmailHandlers are the HTTP handlers of a user's email address.
type EmailHandlers struct {
	add    http.HandlerFunc
	verify http.HandlerFunc
}

// Add accepts {"email"} from the signed-in user and mails that address a link to
// confirm it; nothing is written until the link is followed. It answers {} whatever
// the address's state, so the screen reveals nothing: an address another account
// holds is told so by mail, and an address the user already holds verified gets no
// mail. An address that is not one is 400; a mailbox sent three links within fifteen
// minutes is refused with too_many_attempts and the wait. Route it behind
// ValidateSession.
func (h *EmailHandlers) Add() http.HandlerFunc { return h.add }

// Verify accepts {"token"}, the token the mailed link carried, and writes the address
// on the signed-in user as verified, replacing whatever they held; when the password
// method declares the username as the email address, the user is renamed to it with
// their live sessions. It answers {"email"}. A token whose link is not the user's own,
// or is no longer live, is 404; an address another user has taken meanwhile is 409.
// Route it behind ValidateSession.
func (h *EmailHandlers) Verify() http.HandlerFunc { return h.verify }

// Email returns the email address handlers. It panics on an Auth without mail, as a
// wiring mistake.
func (a *Auth[S, U, Tx]) Email() *EmailHandlers {
	a.requireMail("Email()")

	return &EmailHandlers{
		add:    a.serving(a.emailAdd()),
		verify: a.serving(a.emailVerify()),
	}
}

// emailRequest is a request that carries an address.
type emailRequest struct {
	Email string `json:"email"`
}

var emailDecoder = sessioncore.NewDecoder[emailRequest]()

// emailAdd is Email().Add().
func (a *Auth[S, U, Tx]) emailAdd() http.HandlerFunc {
	return a.baseSession.Handle(func(w http.ResponseWriter, r *http.Request) error {
		ctx, span := tracer.Start(r.Context())
		defer span.End()

		ctx, err := a.validateRequest(ctx)
		if err != nil {
			return httpio.NewEncoder(w).ClientMessage(ctx, err)
		}
		req, err := emailDecoder.Decode(r)
		if err != nil {
			return httpio.NewEncoder(w).ClientMessage(ctx, err)
		}
		if err := a.sendVerification(ctx, sessioninfo.UserFromCtx(ctx), req.Email); err != nil {
			return writeSignInError(ctx, w, err)
		}

		return httpio.NewEncoder(w).Ok(struct{}{})
	})
}

// sendVerification mails user's chosen address its verification link, or the notice
// that another account holds it; an address the user already holds verified gets
// nothing.
func (a *Auth[S, U, Tx]) sendVerification(ctx context.Context, user *sessioninfo.UserInfo, email string) error {
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
	holder, err := a.storage.UserByEmail(ctx, bare)
	if err != nil && !httpio.HasNotFound(err) {
		return errors.Wrap(err, "sessionstorage.AuthStore.UserByEmail()")
	}
	switch {
	case holder != nil && holder.ID != user.ID:
		return a.send(ctx, m.addressHeldMessage(bare))
	case holder != nil && holder.EmailVerified():
		return nil
	}
	token, hash, err := linkToken()
	if err != nil {
		return err
	}
	lifetime := m.settings.LinkTimeout
	link := &sessionstorage.MailLink{
		TokenHash: hash, Kind: sessionstorage.MailLinkVerification, Email: bare, UserID: ccc.NullUUIDFromUUID(user.ID),
		ExpiresAt: time.Now().Add(lifetime),
	}
	if err := a.storage.InsertMailLink(ctx, link); err != nil {
		return errors.Wrap(err, "sessionstorage.AuthStore.InsertMailLink()")
	}

	return a.send(ctx, m.verificationMessage(bare, token, lifetime))
}

// emailVerify is Email().Verify().
func (a *Auth[S, U, Tx]) emailVerify() http.HandlerFunc {
	type response struct {
		Email string `json:"email"`
	}

	return a.baseSession.Handle(func(w http.ResponseWriter, r *http.Request) error {
		ctx, span := tracer.Start(r.Context())
		defer span.End()

		ctx, err := a.validateRequest(ctx)
		if err != nil {
			return httpio.NewEncoder(w).ClientMessage(ctx, err)
		}
		req, err := tokenDecoder.Decode(r)
		if err != nil {
			return httpio.NewEncoder(w).ClientMessage(ctx, err)
		}
		user := sessioninfo.UserFromCtx(ctx)
		link, err := a.liveLink(ctx, req.Token, sessionstorage.MailLinkVerification)
		if err != nil {
			return httpio.NewEncoder(w).ClientMessage(ctx, err)
		}
		// A link counts only for the account that asked for it.
		if !link.UserID.Valid || link.UserID.UUID != user.ID {
			return httpio.NewEncoder(w).ClientMessage(ctx, errLinkDead())
		}
		if err := a.storage.ConsumeMailLink(ctx, link.TokenHash); err != nil {
			if httpio.HasNotFound(err) {
				err = errLinkDead()
			}

			return httpio.NewEncoder(w).ClientMessage(ctx, err)
		}
		if err := a.storage.VerifyUserEmail(ctx, user.ID, link.Email); err != nil {
			return httpio.NewEncoder(w).ClientMessage(ctx, err)
		}
		logger.FromCtx(ctx).Infof("user %s verified the email address %s", user.ID, link.Email)
		// Where the username is the address, the verification renamed the user: the
		// application moves what it keys by the old name.
		if a.registered().usernameIsEmail() && user.Username != link.Email && a.userRenamed != nil {
			if err := a.userRenamed(ctx, user.ID, user.Username, link.Email); err != nil {
				logger.FromCtx(ctx).Errorf("user %s was renamed from %q to %q by verifying the address, and the rename hook failed; run the hook's work by hand: %v", user.ID, user.Username, link.Email, err)

				return httpio.NewEncoder(w).ClientMessage(ctx, errors.Wrap(err, "session.UserRenamedHook()"))
			}
		}

		return httpio.NewEncoder(w).Ok(response{Email: link.Email})
	})
}

// emailHint is the address a directory asserted at one of the user's sign-ins, for a
// user who holds no address: the prefill of the add-address step, trusted for
// nothing. It is "" when the user holds an address or no identity asserted one.
func (a *Auth[S, U, Tx]) emailHint(ctx context.Context, user *sessioninfo.UserInfo) string {
	if user == nil || user.ID.IsNil() || user.Email != nil {
		return ""
	}
	identities, err := a.storage.IdentitiesByUser(ctx, user.ID)
	if err != nil {
		logger.FromCtx(ctx).Error(errors.Wrap(err, "sessionstorage.AuthStore.IdentitiesByUser()"))

		return ""
	}
	for _, identity := range identities {
		if identity.EmailAtLink != nil && *identity.EmailAtLink != "" {
			return *identity.EmailAtLink
		}
	}

	return ""
}

// SetSessionUserEmail puts an address on a user by hand, unverified, or takes it off
// (nil): an operator's entry for an invitation or a migration. The entry reserves the
// address: one another user holds, verified or not, is a Conflict, and a sign-up with
// it is pointed at this account by mail. The address is trusted for nothing until the
// person verifies it. When the password method declares the username as the email
// address the entry is refused (Conflict): the address is the username, set at
// creation and changed through a verified link.
func (p *AuthAPI[S, U, Tx]) SetSessionUserEmail(ctx context.Context, userID ccc.UUID, email *string) error {
	bare, err := optionalAddress(email)
	if err != nil {
		return err
	}
	if err := p.auth.storage.SetUserEmail(ctx, userID, bare); err != nil {
		return errors.Wrap(err, "sessionstorage.AuthStore.SetUserEmail()")
	}

	return nil
}

// UserByEmail returns the user holding the address, verified or not, matched without
// regard to case, or a NotFound error.
func (p *AuthAPI[S, U, Tx]) UserByEmail(ctx context.Context, email string) (*sessionstorage.SessionUser, error) {
	user, err := p.auth.storage.UserByEmail(ctx, email)
	if err != nil {
		return nil, errors.Wrap(err, "sessionstorage.AuthStore.UserByEmail()")
	}

	return user, nil
}
