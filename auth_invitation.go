package session

import (
	"context"
	"net/http"
	"time"

	"github.com/cccteam/ccc"
	"github.com/cccteam/ccc/tracer"
	"github.com/cccteam/httpio"
	"github.com/cccteam/logger"
	"github.com/cccteam/session/cookie"
	"github.com/cccteam/session/internal/sessioncore"
	"github.com/cccteam/session/sessioninfo"
	"github.com/cccteam/session/sessionstorage"
	"github.com/cccteam/session/signin"
	"github.com/go-playground/errors/v5"
)

// An invitation is a mailed link that brings a person into the application, or into
// one of its tenants, with the roles it carries. Whoever follows it and signs in, by
// any method, or signs up with a password, accepts it: the person proved they read
// the mailbox, and the account they sign in with is theirs. The login page opens the
// invitation (Invitation().Open()), which sets an encrypted cookie holding its token,
// so the sign-in that follows, external round trip included, carries it; the store
// accepts it once the user is known, and the application's hook grants the roles in
// the same transaction. A person already signed in accepts with Accept(). See
// "Invitations" in the README.

// invitationCookieKey is the invitation cookie's value holding the token.
const invitationCookieKey cookie.Key = "invitation"

// invitationCtxKey is the context key for the hash of the browser's invitation token,
// set by StartSession.
type invitationCtxKey struct{}

// withInvitationCookie returns ctx with the hash of the invitation token from the
// invitation cookie, if the browser carries one.
func (a *Auth[S, U, Tx]) withInvitationCookie(ctx context.Context, r *http.Request) context.Context {
	cval, found, err := a.invitationCookies.Cookie().Read(r, a.settings.invitationCookie)
	if err != nil || !found {
		return ctx
	}
	token, err := cval.GetString(invitationCookieKey)
	if err != nil {
		return ctx
	}
	hash, ok := linkTokenHash(token)
	if !ok {
		logger.FromCtx(ctx).Warn("invitation cookie ignored: not a link token")

		return ctx
	}

	return context.WithValue(ctx, invitationCtxKey{}, hash)
}

// invitationTokenHash returns the hash of the browser's invitation token from ctx.
func invitationTokenHash(ctx context.Context) ([]byte, bool) {
	hash, ok := ctx.Value(invitationCtxKey{}).([]byte)

	return hash, ok
}

// invitationOf returns the live invitation the browser carries, or nil when it
// carries none or its invitation is no longer live.
func (a *Auth[S, U, Tx]) invitationOf(ctx context.Context) (*sessioninfo.Invitation, error) {
	hash, ok := invitationTokenHash(ctx)
	if !ok {
		return nil, nil
	}
	link, err := a.storage.MailLink(ctx, hash)
	if err != nil {
		if httpio.HasNotFound(err) {
			return nil, nil
		}

		return nil, errors.Wrap(err, "sessionstorage.AuthStore.MailLink()")
	}
	if link.Kind != sessionstorage.MailLinkInvitation {
		return nil, nil
	}

	return invitationOf(link), nil
}

// invitationOf renders a mail link row as the invitation a sign-in carries.
func invitationOf(link *sessionstorage.MailLink) *sessioninfo.Invitation {
	return &sessioninfo.Invitation{
		ID: link.ID, Email: link.Email, Tenant: link.Tenant, RoleNames: link.RoleNames, InvitedBy: link.InvitedBy, CreatedAt: link.CreatedAt, ExpiresAt: link.ExpiresAt,
	}
}

// endInvitation deletes the invitation cookie once a session stands, whether the
// sign-in accepted the invitation or found it dead; the latter is logged.
func (a *Auth[S, U, Tx]) endInvitation(ctx context.Context, w http.ResponseWriter, inv *sessioninfo.Invitation) {
	if _, ok := invitationTokenHash(ctx); !ok {
		return
	}
	if inv != nil && !inv.Accepted {
		logger.FromCtx(ctx).Warnf("the invitation %s the sign-in carried had expired or was already used: nothing was granted", inv.ID)
	}
	a.invitationCookies.Cookie().Delete(w, a.settings.invitationCookie, a.invitationCookies.Domain)
}

// InvitationHandlers are the HTTP handlers of invitations.
type InvitationHandlers struct {
	open   http.HandlerFunc
	accept http.HandlerFunc
	signUp http.HandlerFunc
}

// Open accepts {"token"}, the token the mailed link carried, and answers {"email",
// "tenant", "expiresAt", "signUp", "usernameIsEmail"}: the address the invitation was
// sent to, the tenant it seats the person in ("" for the application's global
// surface), when it stops being accepted, whether the person may create an account
// with a password here (the password method is registered), and whether that
// account's username is the address. It sets the invitation cookie, so the sign-in
// that follows carries the invitation. A token whose invitation is no longer live is
// 404. Route it behind StartSession and ValidateXSRFToken.
func (h *InvitationHandlers) Open() http.HandlerFunc { return h.open }

// Accept accepts the invitation the browser carries for the signed-in user: the
// invitation is consumed, the user's address is set from it when they hold no verified
// address, and the application's hook grants what it names, in one transaction. It
// answers {"accepted": true}; 404 when the browser carries no live invitation. Route it
// behind ValidateSession.
func (h *InvitationHandlers) Accept() http.HandlerFunc { return h.accept }

// SignUp accepts {"password", "username"} and creates the invited person's account
// with a password, then signs them in and accepts the invitation: the address the
// invitation was sent to is the account's, verified. username is the address when the
// password method declares the username as the email address, and chosen otherwise.
// It answers as the password login does ({"mfaIsRequired"}); a taken username or
// address is 409, a password under eight characters 400, no password method or no
// live invitation 404. Route it beside the password login, behind ValidateXSRFToken.
func (h *InvitationHandlers) SignUp() http.HandlerFunc { return h.signUp }

// Invitation returns the invitation handlers.
func (a *Auth[S, U, Tx]) Invitation() *InvitationHandlers {
	return &InvitationHandlers{
		open:   a.serving(a.invitationOpen()),
		accept: a.serving(a.invitationAccept()),
		signUp: a.serving(a.invitationSignUp()),
	}
}

// invitationOpen is Invitation().Open().
func (a *Auth[S, U, Tx]) invitationOpen() http.HandlerFunc {
	type response struct {
		Email           string    `json:"email"`
		Tenant          string    `json:"tenant,omitempty"`
		ExpiresAt       time.Time `json:"expiresAt"`
		SignUp          bool      `json:"signUp"`
		UsernameIsEmail bool      `json:"usernameIsEmail"`
	}

	return a.baseSession.Handle(func(w http.ResponseWriter, r *http.Request) error {
		ctx, span := tracer.Start(r.Context())
		defer span.End()

		req, err := tokenDecoder.Decode(r)
		if err != nil {
			return httpio.NewEncoder(w).ClientMessage(ctx, err)
		}
		link, err := a.liveLink(ctx, req.Token, sessionstorage.MailLinkInvitation)
		if err != nil {
			return httpio.NewEncoder(w).ClientMessage(ctx, err)
		}

		// Lax, so the cookie also reaches the login page an external method's callback
		// redirects to; the sign-in it joins is behind the method's own checks.
		cval := cookie.NewValues().SetString(invitationCookieKey, req.Token)
		a.invitationCookies.Cookie().WritePersistentCookie(w, a.settings.invitationCookie, a.invitationCookies.Domain, true, http.SameSiteLaxMode,
			time.Until(link.ExpiresAt), cval)
		methods := a.registered()

		return httpio.NewEncoder(w).Ok(response{
			Email: link.Email, Tenant: link.Tenant, ExpiresAt: link.ExpiresAt, SignUp: methods.passwordRegistered(), UsernameIsEmail: methods.usernameIsEmail(),
		})
	})
}

// liveLink returns the live link of kind that token names, or a NotFound error.
func (a *Auth[S, U, Tx]) liveLink(ctx context.Context, token string, kind sessionstorage.MailLinkKind) (*sessionstorage.MailLink, error) {
	hash, ok := linkTokenHash(token)
	if !ok {
		return nil, errLinkDead()
	}
	link, err := a.storage.MailLink(ctx, hash)
	if err != nil {
		if httpio.HasNotFound(err) {
			return nil, errLinkDead()
		}

		return nil, errors.Wrap(err, "sessionstorage.AuthStore.MailLink()")
	}
	if link.Kind != kind {
		return nil, errLinkDead()
	}

	return link, nil
}

// invitationAccept is Invitation().Accept().
func (a *Auth[S, U, Tx]) invitationAccept() http.HandlerFunc {
	type response struct {
		Accepted bool `json:"accepted"`
	}

	return a.baseSession.Handle(func(w http.ResponseWriter, r *http.Request) error {
		ctx, span := tracer.Start(r.Context())
		defer span.End()

		ctx, err := a.validateRequest(ctx)
		if err != nil {
			return httpio.NewEncoder(w).ClientMessage(ctx, err)
		}
		inv, err := a.invitationOf(ctx)
		if err != nil {
			return httpio.NewEncoder(w).ClientMessage(ctx, err)
		}
		if inv == nil {
			return httpio.NewEncoder(w).ClientMessage(ctx, httpio.NewNotFoundMessage("the browser carries no live invitation"))
		}
		user := sessioninfo.UserFromCtx(ctx)
		if err := a.storage.AcceptInvitation(ctx, user.ID, user.Username, inv, a.acceptInvitation); err != nil {
			if httpio.HasNotFound(err) {
				a.invitationCookies.Cookie().Delete(w, a.settings.invitationCookie, a.invitationCookies.Domain)
			}

			return httpio.NewEncoder(w).ClientMessage(ctx, err)
		}
		a.invitationCookies.Cookie().Delete(w, a.settings.invitationCookie, a.invitationCookies.Domain)

		return httpio.NewEncoder(w).Ok(response{Accepted: true})
	})
}

// invitationSignUp is Invitation().SignUp().
func (a *Auth[S, U, Tx]) invitationSignUp() http.HandlerFunc {
	type request struct {
		Password string `json:"password"`
		Username string `json:"username"`
	}
	decoder := sessioncore.NewDecoder[request]()

	return a.baseSession.Handle(func(w http.ResponseWriter, r *http.Request) error {
		ctx, span := tracer.Start(r.Context())
		defer span.End()

		req, err := decoder.Decode(r)
		if err != nil {
			return httpio.NewEncoder(w).ClientMessage(ctx, err)
		}
		if !a.registered().passwordRegistered() {
			return httpio.NewEncoder(w).ClientMessage(ctx, httpio.NewNotFoundMessage("an account with a password is not offered here"))
		}
		inv, err := a.invitationOf(ctx)
		if err != nil {
			return httpio.NewEncoder(w).ClientMessage(ctx, err)
		}
		if inv == nil {
			return httpio.NewEncoder(w).ClientMessage(ctx, httpio.NewNotFoundMessage("the browser carries no live invitation"))
		}
		user, err := a.createAccount(ctx, inv.Email, req.Username, req.Password)
		if err != nil {
			return httpio.NewEncoder(w).ClientMessage(ctx, err)
		}

		// The sign-in carries the invitation from the cookie and accepts it.
		outcome, err := a.signIn(ctx, w, a.passwordAttempt(user))
		if err != nil {
			return writeSignInError(ctx, w, err)
		}

		return a.answerSignIn(ctx, w, r, outcome)
	})
}

// createAccount creates the account a sign-up or an invitation's sign-up makes: the
// password the person chose, the address they proved they read, verified, and the
// username, which is the address when the password method declares them one and the
// person's choice otherwise.
func (a *Auth[S, U, Tx]) createAccount(ctx context.Context, email, username, password string) (*sessionstorage.SessionUser, error) {
	if err := acceptedPassword(password); err != nil {
		return nil, err
	}
	methods := a.registered()
	switch {
	case methods.usernameIsEmail():
		username = email
	case username == "":
		return nil, httpio.NewBadRequestMessage("choose a username")
	}
	hash, err := methods.hasher.Hash(password)
	if err != nil {
		return nil, errors.Wrap(err, "securehash.SecureHasher.Hash()")
	}
	user, err := a.storage.CreateUser(ctx, &sessionstorage.InsertSessionUser{Username: username, PasswordHash: hash, Email: &email, EmailVerified: true}, nil)
	if err != nil {
		return nil, errors.Wrap(err, "sessionstorage.AuthStore.CreateUser()")
	}

	return user, nil
}

// passwordAttempt is the sign-in of a user who just set their password: a password
// identity naming the user.
func (a *Auth[S, U, Tx]) passwordAttempt(user *sessionstorage.SessionUser) *signInAttempt {
	return &signInAttempt{
		identity: &sessioninfo.Identity{Method: sessioninfo.MethodPassword, Subject: user.ID.String()},
		reason:   sessioninfo.ReasonLogin,
		userID:   user.ID,
		username: user.Username,
		sameSite: sessioncore.SameSiteStrict,
	}
}

// InvitationRequest is an invitation to send.
type InvitationRequest struct {
	// Email is the address to invite.
	Email string
	// Tenant is the tenant the invitation seats the person in, "" for the
	// application's global surface.
	Tenant string
	// RoleNames are the roles the acceptance grants, as the application's hook
	// understands them.
	RoleNames []string
	// InvitedBy is the user sending the invitation, null when unknown.
	InvitedBy ccc.NullUUID
}

// Invite sends an invitation to req.Email: a link to the login page that stands for
// MailSettings.InvitationTimeout, which whoever follows it accepts by signing in or
// signing up. The request is the same whether an account holds the address or not;
// only the invitee's path differs, and the caller does not learn which. An address
// that no sign-in method the login page offers could admit (an address outside the
// Google Workspaces a registration names, say, with no password method offered) is
// refused with a message naming its domain, and nothing is stored or mailed, so the
// sender learns now what the invitee would learn at the sign-in. The invitation is
// returned as stored; a message that could not be sent is an error and the invitation
// is withdrawn. It needs mail (WithMail).
func (p *AuthAPI[S, U, Tx]) Invite(ctx context.Context, req *InvitationRequest) (*sessioninfo.Invitation, error) {
	ctx, span := tracer.Start(ctx)
	defer span.End()

	m, err := p.auth.mailOf()
	if err != nil {
		return nil, err
	}
	email, err := address(req.Email)
	if err != nil {
		return nil, err
	}
	if !p.auth.couldAdmitAddress(email) {
		return nil, httpio.NewBadRequestMessagef("No sign-in method of this application accepts an address at %s.", signin.AddressDomain(email))
	}
	token, hash, err := linkToken()
	if err != nil {
		return nil, err
	}
	lifetime := m.settings.InvitationTimeout
	link := &sessionstorage.MailLink{
		TokenHash: hash, Kind: sessionstorage.MailLinkInvitation, Email: email, Tenant: req.Tenant, RoleNames: req.RoleNames, InvitedBy: req.InvitedBy,
		ExpiresAt: time.Now().Add(lifetime),
	}
	if err := p.auth.storage.InsertMailLink(ctx, link); err != nil {
		return nil, errors.Wrap(err, "sessionstorage.AuthStore.InsertMailLink()")
	}
	if err := p.auth.send(ctx, m.invitationMessage(email, token, lifetime)); err != nil {
		if rerr := p.auth.storage.RevokeMailLink(ctx, link.ID); rerr != nil {
			logger.FromCtx(ctx).Error(errors.Wrap(rerr, "sessionstorage.AuthStore.RevokeMailLink()"))
		}

		return nil, err
	}

	return invitationOf(link), nil
}

// Invitations lists the invitations that stand: sent, not accepted, not revoked and
// not expired, oldest first.
func (p *AuthAPI[S, U, Tx]) Invitations(ctx context.Context) ([]*sessioninfo.Invitation, error) {
	links, err := p.auth.storage.LiveMailLinks(ctx, sessionstorage.MailLinkInvitation)
	if err != nil {
		return nil, errors.Wrap(err, "sessionstorage.AuthStore.LiveMailLinks()")
	}
	invitations := make([]*sessioninfo.Invitation, len(links))
	for i, link := range links {
		invitations[i] = invitationOf(link)
	}

	return invitations, nil
}

// RevokeInvitation withdraws an invitation that stands; its link is then dead. One
// that no longer stands is NotFound.
func (p *AuthAPI[S, U, Tx]) RevokeInvitation(ctx context.Context, id ccc.UUID) error {
	if err := p.auth.storage.RevokeMailLink(ctx, id); err != nil {
		return errors.Wrap(err, "sessionstorage.AuthStore.RevokeMailLink()")
	}

	return nil
}
