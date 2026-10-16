package session

import (
	"context"
	"net/http"
	"slices"
	"time"

	"github.com/cccteam/ccc"
	"github.com/cccteam/ccc/tracer"
	"github.com/cccteam/httpio"
	"github.com/cccteam/logger"
	"github.com/cccteam/session/internal/sessioncore"
	"github.com/cccteam/session/internal/signinflow"
	"github.com/cccteam/session/sessioninfo"
	"github.com/cccteam/session/sessionstorage"
	"github.com/cccteam/session/signin"
	"github.com/go-playground/errors/v5"
)

// signInAttempt is a verified identity on its way to becoming a session.
type signInAttempt struct {
	identity *sessioninfo.Identity
	reason   sessioninfo.NewSessionReason
	// registration names the external registration the identity came through, whose
	// resolver resolves it and whose method reconciles its roles. It is empty for a
	// password identity.
	registration string
	// userID and username name a password identity's user. The drivers take it
	// from the request instead of resolving it.
	userID   ccc.UUID
	username string
	// expectUserID is the user a pending identity waited on. When valid, a
	// completion that now resolves to another user is refused.
	expectUserID ccc.NullUUID
	// providerSessionID is the provider's session id the sign-in carried, and
	// providerSessionIssuer the registration's issuer it belongs to; both or neither.
	providerSessionID     string
	providerSessionIssuer string
	// events are the auth events the session records. Nil records only the identity's
	// method.
	events []sessioninfo.AuthEvent
	// returnURL is where an external sign-in sends the browser afterwards.
	returnURL string
	// roleNames are the role names the method asserted, reconciled once the user is
	// known. They are nil when the method synchronizes no roles.
	roleNames []string
	sameSite  sessioncore.SameSite
	// fromPending reports a completion of the browser's pending identity, consumed
	// before the sign-in; only its cookie remains, to delete or replace.
	fromPending bool
}

// signInOutcome is a sign-in's result: a session, or a pending identity.
type signInOutcome struct {
	sessionID ccc.UUID
	userID    ccc.UUID
	pending   *pendingState
}

// signIn establishes a session for every sign-in method. One store call resolves the
// user, asks the sign-in policy and inserts the session with its auth events. Roles are then
// reconciled, and only after that are the cookies for the new session ID written, so a
// refusal writes no cookie. A sign-in that must wait becomes the browser's pending
// identity, replacing any earlier one. A sign-in that succeeds ends it.
func (a *Auth[S, U, Tx]) signIn(ctx context.Context, w http.ResponseWriter, at *signInAttempt) (*signInOutcome, error) {
	ctx, span := tracer.Start(ctx)
	defer span.End()

	req := &sessioninfo.NewSessionRequest{
		Reason:                at.reason,
		Username:              at.username,
		UserID:                at.userID,
		Claims:                at.identity.Claims,
		Identity:              at.identity,
		AuthEvents:            at.events,
		ProviderSessionID:     at.providerSessionID,
		ProviderSessionIssuer: at.providerSessionIssuer,
	}

	// An external identity is resolved by its registration's user resolver; a password
	// identity names its user and needs none.
	var resolve signin.UserResolver[Tx]
	if m, ok := a.registered().external[at.registration]; ok {
		resolve = m.resolve
	}
	id, err := sessioncore.EstablishSession(ctx, w, a.baseSession, at.sameSite, func(ctx context.Context) (ccc.UUID, error) {
		id, err := a.storage.SignIn(ctx, req, resolve, a.policy)
		if err != nil {
			return ccc.NilUUID, errors.Wrap(err, "sessionstorage.AuthStore.SignIn()")
		}
		if err := a.afterInsert(ctx, at, req); err != nil {
			if derr := a.storage.DestroySession(ctx, id); derr != nil {
				logger.FromCtx(ctx).Error(errors.Wrap(derr, "sessionstorage.AuthStore.DestroySession()"))
			}

			return ccc.NilUUID, err
		}

		return id, nil
	})
	// The storage commits a link before the policy decides, so the link is reported
	// whatever the outcome.
	if req.User.Linked() {
		a.notifyLinked(ctx, req.User.ID, at.identity)
	}

	var wait *signin.PendingSignInError
	if errors.As(err, &wait) {
		pending, err := a.holdPending(ctx, w, at, wait)
		if err != nil {
			return nil, err
		}

		return &signInOutcome{pending: pending}, nil
	}
	if err != nil {
		return nil, err
	}

	a.endPending(ctx, w, at)
	sessioncore.LogSessionStarted(ctx, req.Username, id)

	return &signInOutcome{sessionID: id, userID: req.UserID}, nil
}

// afterInsert runs once the session row exists and req carries the resolved user.
// It refuses a completion that resolved to a different user, and reconciles the
// method's roles.
func (a *Auth[S, U, Tx]) afterInsert(ctx context.Context, at *signInAttempt, req *sessioninfo.NewSessionRequest) error {
	if at.expectUserID.Valid && req.UserID != at.expectUserID.UUID {
		return signinflow.Refusal("", sessioninfo.RefusedIdentityRejected, signin.ErrIdentityRejected, "the identity no longer resolves to the user it was pending for")
	}
	if at.roleNames == nil {
		return nil
	}
	m, ok := a.registered().external[at.registration]
	if !ok || m.SyncRoles == nil {
		return nil
	}
	if err := m.SyncRoles(ctx, req.Username, at.roleNames); err != nil {
		return errors.Wrap(err, "role synchronization")
	}

	return nil
}

// notifyLinked calls the IdentityLinked hook. An error is logged, and the link stands.
func (a *Auth[S, U, Tx]) notifyLinked(ctx context.Context, userID ccc.UUID, identity *sessioninfo.Identity) {
	if a.settings.identityLinked == nil {
		return
	}
	if err := a.settings.identityLinked(ctx, userID, identity); err != nil {
		logger.FromCtx(ctx).Error(errors.Wrap(err, "IdentityLinkedHook()"))
	}
}

// validate validates the session in ctx and stores its user in the context.
func (a *Auth[S, U, Tx]) validate(ctx context.Context) (context.Context, error) {
	ctx, err := a.baseSession.ValidateSessionAPI(ctx)
	if err != nil {
		return ctx, errors.Wrap(err, "basesession.BaseSession.ValidateSessionAPI()")
	}

	sessData, ok := ctx.Value(sessioninfo.CtxSessionInfo).(*sessioninfo.SessionData)
	if !ok {
		return ctx, errors.New("no validated session in the context")
	}
	user, err := a.sessionUser(ctx, sessData)
	if err != nil {
		return ctx, err
	}

	return context.WithValue(ctx, sessioninfo.CtxUserInfo, user), nil
}

// sessionUser loads a validated session's user by UserId. A session with no
// user (a pending identity's row, a row from before the auth schema), or whose
// user is missing or disabled, is unauthorized. A role-principal impersonation has
// no user. A foreign actor's carries only its username. A local actor's is checked
// against the actor's own user.
func (a *Auth[S, U, Tx]) sessionUser(ctx context.Context, sessData *sessioninfo.SessionData) (*sessioninfo.UserInfo, error) {
	if imp := sessData.Impersonation; imp != nil && imp.Principal.IsRole() {
		if !imp.IsLocalActor() {
			return &sessioninfo.UserInfo{Username: sessData.Username}, nil
		}
		user, err := a.storage.UserByUserName(ctx, sessData.Username)
		if err != nil {
			return nil, httpio.NewUnauthorizedMessageWithError(err, "invalid session")
		}

		return enabledUser(user)
	}

	if !sessData.UserID.Valid {
		return nil, httpio.NewUnauthorizedMessage("invalid session")
	}
	user, err := a.storage.User(ctx, sessData.UserID.UUID)
	if err != nil {
		if httpio.HasNotFound(err) {
			return nil, httpio.NewUnauthorizedMessageWithError(err, "invalid session")
		}

		return nil, errors.Wrap(err, "sessionstorage.AuthStore.User()")
	}

	return enabledUser(user)
}

func enabledUser(user *sessionstorage.SessionUser) (*sessioninfo.UserInfo, error) {
	if user.Disabled {
		return nil, httpio.NewUnauthorizedMessage("Session Expired")
	}

	return &sessioninfo.UserInfo{ID: user.ID, Username: user.Username}, nil
}

// passwordSignIn checks username and password and signs the user in.
func (a *Auth[S, U, Tx]) passwordSignIn(ctx context.Context, w http.ResponseWriter, username, password string) (*signInOutcome, error) {
	user, err := a.checkCredentials(ctx, username, password)
	if err != nil {
		return nil, err
	}

	return a.signIn(ctx, w, &signInAttempt{
		identity: &sessioninfo.Identity{Method: sessioninfo.MethodPassword, Subject: user.ID.String()},
		reason:   sessioninfo.ReasonLogin,
		userID:   user.ID,
		username: user.Username,
		sameSite: sessioncore.SameSiteStrict,
	})
}

// checkCredentials returns the enabled user for username when password matches. A
// missing user, a wrong password and a password-less user are all invalid
// credentials. An outdated hash is upgraded when auto-upgrade is enabled.
func (a *Auth[S, U, Tx]) checkCredentials(ctx context.Context, username, password string) (*sessionstorage.SessionUser, error) {
	user, err := a.storage.UserByUserName(ctx, username)
	if err != nil {
		return nil, httpio.NewUnauthorizedMessageWithError(err, "Invalid Credentials")
	}
	methods := a.registered()
	upgrade, err := sessioncore.ComparePassword(methods.hasher, user.PasswordHash, password)
	if err != nil {
		return nil, httpio.NewUnauthorizedMessageWithError(err, "Invalid Credentials")
	}
	if upgrade && methods.autoUpgrade {
		if err := a.setPasswordHash(ctx, user.ID, password); err != nil {
			logger.FromCtx(ctx).Error(err)
		} else {
			logger.FromCtx(ctx).Infof("auto-upgraded password hash for user %s, from %s to %s", user.Username, user.PasswordHash.KeyType(), methods.hasher.KeyType())
		}
	}
	if user.Disabled {
		return nil, signinflow.Refusal("", sessioninfo.RefusedUserDisabled, signin.ErrUserDisabled, "User disabled")
	}

	return user, nil
}

func (a *Auth[S, U, Tx]) setPasswordHash(ctx context.Context, userID ccc.UUID, password string) error {
	hash, err := a.registered().hasher.Hash(password)
	if err != nil {
		return errors.Wrap(err, "securehash.SecureHasher.Hash()")
	}
	if err := a.storage.SetUserPasswordHash(ctx, userID, hash); err != nil {
		return errors.Wrap(err, "sessionstorage.AuthStore.SetUserPasswordHash()")
	}

	return nil
}

// passwordLogin is the password method's login handler.
func (a *Auth[S, U, Tx]) passwordLogin() http.HandlerFunc {
	type request struct {
		Username string `json:"username"`
		Password string `json:"password"`
	}
	decoder := sessioncore.NewDecoder[request]()

	return a.baseSession.Handle(func(w http.ResponseWriter, r *http.Request) error {
		ctx, span := tracer.Start(r.Context())
		defer span.End()

		req, err := decoder.Decode(r)
		if err != nil {
			return httpio.NewEncoder(w).ClientMessage(ctx, err)
		}

		outcome, err := a.passwordSignIn(ctx, w, req.Username, req.Password)
		if err != nil {
			return writeSignInError(ctx, w, err)
		}

		return a.answerSignIn(ctx, w, r, outcome)
	})
}

// answerSignIn writes a JSON sign-in handler's outcome. For a pending identity the
// PendingHook runs first.
func (a *Auth[S, U, Tx]) answerSignIn(ctx context.Context, w http.ResponseWriter, r *http.Request, outcome *signInOutcome) error {
	var body mfaResponse
	if outcome.pending != nil {
		redirectURL, handled, err := a.onPending(ctx, w, r, outcome.pending)
		switch {
		case handled:
			return err
		case err != nil:
			return writeSignInError(ctx, w, err)
		}
		body = mfaResponse{MFAIsRequired: true, RedirectURL: redirectURL}
	}
	if err := httpio.NewEncoder(w).Ok(body); err != nil {
		return errors.Wrap(err, "httpio.Encoder.Ok()")
	}

	return nil
}

// changeUserPasswordHandler is the password method's change-password handler.
func (a *Auth[S, U, Tx]) changeUserPasswordHandler() http.HandlerFunc {
	type request struct {
		OldPassword string `json:"oldPassword"`
		NewPassword string `json:"newPassword"`
	}
	decoder := sessioncore.NewDecoder[request]()

	return a.baseSession.Handle(func(w http.ResponseWriter, r *http.Request) error {
		ctx, span := tracer.Start(r.Context())
		defer span.End()

		if err := sessioncore.RefuseImpersonated(ctx, a.baseSession, "ChangeUserPassword", true); err != nil {
			return httpio.NewEncoder(w).ClientMessage(ctx, err)
		}

		req, err := decoder.Decode(r)
		if err != nil {
			return httpio.NewEncoder(w).ClientMessage(ctx, err)
		}

		change := &ChangeSessionUserPasswordRequest{OldPassword: req.OldPassword, NewPassword: req.NewPassword}
		if err := a.API().ChangeSessionUserPassword(ctx, w, sessioninfo.UserFromCtx(ctx).ID, change); err != nil {
			return httpio.NewEncoder(w).ClientMessage(ctx, err)
		}

		return httpio.NewEncoder(w).Ok(nil)
	})
}

// mfaResponse answers a sign-in step that may still wait for the application's MFA.
// RedirectURL is where a PendingHook sends the browser.
type mfaResponse struct {
	MFAIsRequired bool   `json:"mfaIsRequired"`
	RedirectURL   string `json:"redirectUrl,omitempty"`
}

// refusalResponse is a JSON sign-in handler's answer to a refused sign-in.
type refusalResponse struct {
	Message string                       `json:"message"`
	Code    sessioninfo.LoginRefusalCode `json:"code"`
}

// writeSignInError writes a JSON sign-in handler's error. A sessioninfo.LoginRefusal
// is answered with 401 (403 for a forbidden cause) and {"message", "code"}, so the
// page can map the code to its own text. Any other error is the usual client message.
func writeSignInError(ctx context.Context, w http.ResponseWriter, err error) error {
	var refusal *sessioninfo.LoginRefusal
	if !errors.As(err, &refusal) {
		if werr := httpio.NewEncoder(w).ClientMessage(ctx, err); werr != nil {
			return errors.Wrap(werr, "httpio.Encoder.ClientMessage()")
		}

		return nil
	}

	status := http.StatusUnauthorized
	if httpio.HasForbidden(err) {
		status = http.StatusForbidden
	}
	if werr := httpio.NewEncoder(w).StatusCodeWithBody(status, refusalResponse{Message: httpio.Message(err), Code: refusal.Code()}); werr != nil {
		return errors.Wrap(werr, "httpio.Encoder.StatusCodeWithBody()")
	}

	return err
}

// identityEvent returns the auth event of a sign-in with identity at time at.
func identityEvent(identity *sessioninfo.Identity, at time.Time) sessioninfo.AuthEvent {
	return sessioninfo.AuthEvent{Method: identity.Method, Connection: identity.Connection, IDPAMR: slices.Clone(identity.IDPAMR), At: at}
}

// validateEvents refuses an auth event without a method.
func validateEvents(events []sessioninfo.AuthEvent) error {
	for _, e := range events {
		if e.Method == "" {
			return httpio.NewBadRequestMessage("an auth event needs a method")
		}
	}

	return nil
}

// shared returns the API methods every session type shares, over this session's fields.
func (a *Auth[S, U, Tx]) shared() sessioncore.API[S, U] {
	return sessioncore.API[S, U]{Base: a.baseSession, Store: a.storage, Users: a.storage, StoreName: "AuthStore"}
}
