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
	"github.com/cccteam/session/internal/dbtype"
	"github.com/cccteam/session/sessioninfo"
	"github.com/cccteam/session/sessionstorage"
	"github.com/go-playground/errors/v5"
)

// signInAttempt is a verified identity on its way to becoming a session.
type signInAttempt struct {
	identity *sessioninfo.Identity
	reason   sessioninfo.NewSessionReason
	// userID and username name the account of a password identity, which the drivers
	// take from the request rather than resolving it.
	userID   ccc.UUID
	username string
	// expectUserID, when valid, is the account a completed pending identity resolved to
	// before: a completion that now resolves elsewhere is refused.
	expectUserID ccc.NullUUID
	// events are the auth events the session records; nil records the identity's
	// method alone.
	events []sessioninfo.AuthEvent
	// returnURL is where an external sign-in sends the browser afterwards.
	returnURL string
	// roleNames are the role names the method asserted, reconciled for the account once
	// it is known; nil when the method synchronizes no roles.
	roleNames []string
	sameSite  authCookieSameSite
}

// signInOutcome is a sign-in's result: a session, or a pending identity.
type signInOutcome struct {
	sessionID ccc.UUID
	userID    ccc.UUID
	pending   *pendingState
}

// signIn is how every sign-in method establishes a session: in one store call the
// account is resolved, the policy decides, and the session is inserted with its auth
// events; roles are reconciled for the resolved account; and only then are the auth and
// XSRF cookies for the new session ID written. A sign-in that must wait becomes the
// browser's pending identity, replacing any earlier one; a sign-in that succeeds
// consumes it. A refusal writes no cookie.
func (a *Auth[S, U]) signIn(ctx context.Context, w http.ResponseWriter, at *signInAttempt) (*signInOutcome, error) {
	ctx, span := tracer.Start(ctx)
	defer span.End()

	if at.identity.Method == sessioninfo.MethodPassword {
		// Without identities configured the drivers insert a password session as given,
		// so the account is checked here.
		user, err := a.storage.User(ctx, at.userID)
		if err != nil {
			return nil, errors.Wrap(err, "sessionstorage.AccountStore.User()")
		}
		if user.Disabled {
			return nil, dbtype.Refusal("", sessioninfo.RefusedAccountDisabled, sessionstorage.ErrAccountDisabled, "Account disabled")
		}
		at.username = user.Username
	}

	newLink := a.unlinked(ctx, at)
	req := &sessioninfo.NewSessionRequest{
		Reason:     at.reason,
		Username:   at.username,
		UserID:     at.userID,
		Claims:     at.identity.Claims,
		Identity:   at.identity,
		AuthEvents: at.events,
	}

	id, err := establishSession(ctx, w, a.baseSession, at.sameSite, func(ctx context.Context) (ccc.UUID, error) {
		id, err := a.storage.CreateSession(ctx, req)
		if err != nil {
			return ccc.NilUUID, errors.Wrap(err, "sessionstorage.AccountStore.CreateSession()")
		}
		if err := a.afterInsert(ctx, at, req); err != nil {
			if derr := a.storage.DestroySession(ctx, id); derr != nil {
				logger.FromCtx(ctx).Error(errors.Wrap(derr, "sessionstorage.AccountStore.DestroySession()"))
			}

			return ccc.NilUUID, err
		}

		return id, nil
	})

	var wait *sessionstorage.PendingSignInError
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

	if newLink {
		a.notifyLinked(ctx, req.UserID, at.identity)
	}
	a.dropPending(ctx, w)
	logSessionStarted(ctx, req.Username, id)

	return &signInOutcome{sessionID: id, userID: req.UserID}, nil
}

// afterInsert runs inside the establishing step once the session row exists and
// req carries the resolved account: it refuses a completion that resolved to another
// account than before, and reconciles the method's roles for the account.
func (a *Auth[S, U]) afterInsert(ctx context.Context, at *signInAttempt, req *sessioninfo.NewSessionRequest) error {
	if at.expectUserID.Valid && req.UserID != at.expectUserID.UUID {
		return dbtype.Refusal("", sessioninfo.RefusedIdentityRejected, sessionstorage.ErrIdentityRejected, "the identity no longer resolves to the account it was pending for")
	}
	if at.roleNames == nil {
		return nil
	}
	m, ok := a.external[at.identity.Method]
	if !ok || m.syncRoles == nil {
		return nil
	}
	if err := m.syncRoles(ctx, req.Username, at.roleNames); err != nil {
		return errors.Wrap(err, "role synchronization")
	}

	return nil
}

// unlinked reports whether at's identity is an external identity with no link yet, so
// a successful sign-in with it has just linked it (the account resolver linked or
// provisioned). It is only asked when an IdentityLinked hook is configured, and never
// after a confirmation, whose link was made and reported before.
func (a *Auth[S, U]) unlinked(ctx context.Context, at *signInAttempt) bool {
	identity := at.identity
	if a.settings.identityLinked == nil || !dbtype.IsExternal(identity) || at.reason == sessioninfo.ReasonIdentityLinked {
		return false
	}
	_, err := a.storage.Identity(ctx, identity.Method, identity.Connection, identity.Subject)

	return httpio.HasNotFound(err)
}

// notifyLinked calls the IdentityLinked hook, logging its error: the link stands.
func (a *Auth[S, U]) notifyLinked(ctx context.Context, userID ccc.UUID, identity *sessioninfo.Identity) {
	if a.settings.identityLinked == nil {
		return
	}
	if err := a.settings.identityLinked(ctx, userID, identity); err != nil {
		logger.FromCtx(ctx).Error(errors.Wrap(err, "IdentityLinkedHook()"))
	}
}

// validate validates the session in ctx and loads its account (see sessionAccount),
// storing the account in the context.
func (a *Auth[S, U]) validate(ctx context.Context) (context.Context, error) {
	ctx, err := a.baseSession.ValidateSessionAPI(ctx)
	if err != nil {
		return ctx, errors.Wrap(err, "basesession.BaseSession.ValidateSessionAPI()")
	}

	sessData, ok := ctx.Value(sessioninfo.CtxSessionInfo).(*sessioninfo.SessionData)
	if !ok {
		return ctx, errors.New("no validated session in the context")
	}
	user, err := a.sessionAccount(ctx, sessData)
	if err != nil {
		return ctx, err
	}

	return context.WithValue(ctx, sessioninfo.CtxUserInfo, user), nil
}

// sessionAccount loads the account a validated session belongs to, by UserId. A session
// with no account (a pending identity's stepping stone, a row from before the accounts
// schema) or whose account is missing or disabled is refused as unauthorized. A
// role-principal impersonation has no account: a foreign actor's carries only its
// username, and a local actor's is checked against the actor's own account.
func (a *Auth[S, U]) sessionAccount(ctx context.Context, sessData *sessioninfo.SessionData) (*sessioninfo.UserInfo, error) {
	if imp := sessData.Impersonation; imp != nil && imp.Principal.IsRole() {
		if !imp.IsLocalActor() {
			return &sessioninfo.UserInfo{Username: sessData.Username}, nil
		}
		user, err := a.storage.UserByUserName(ctx, sessData.Username)
		if err != nil {
			return nil, httpio.NewUnauthorizedMessageWithError(err, "invalid session")
		}

		return enabledAccount(user)
	}

	if !sessData.UserID.Valid {
		return nil, httpio.NewUnauthorizedMessage("invalid session")
	}
	user, err := a.storage.User(ctx, sessData.UserID.UUID)
	if err != nil {
		if httpio.HasNotFound(err) {
			return nil, httpio.NewUnauthorizedMessageWithError(err, "invalid session")
		}

		return nil, errors.Wrap(err, "sessionstorage.AccountStore.User()")
	}

	return enabledAccount(user)
}

func enabledAccount(user *sessionstorage.SessionUser) (*sessioninfo.UserInfo, error) {
	if user.Disabled {
		return nil, httpio.NewUnauthorizedMessage("Session Expired")
	}

	return &sessioninfo.UserInfo{ID: user.ID, Username: user.Username}, nil
}

// passwordSignIn checks username and password and signs the account in.
func (a *Auth[S, U]) passwordSignIn(ctx context.Context, w http.ResponseWriter, username, password string) (*signInOutcome, error) {
	user, err := a.checkCredentials(ctx, username, password)
	if err != nil {
		return nil, err
	}

	return a.signIn(ctx, w, &signInAttempt{
		identity: &sessioninfo.Identity{Method: sessioninfo.MethodPassword, Subject: user.ID.String()},
		reason:   sessioninfo.ReasonLogin,
		userID:   user.ID,
		username: user.Username,
		sameSite: sameSiteStrict,
	})
}

// checkCredentials returns the account for username when password is its password and
// it is enabled; a missing account, a wrong password and a password-less account are
// all invalid credentials. A hash on an outdated algorithm is upgraded when enabled.
func (a *Auth[S, U]) checkCredentials(ctx context.Context, username, password string) (*sessionstorage.SessionUser, error) {
	user, err := a.storage.UserByUserName(ctx, username)
	if err != nil {
		return nil, httpio.NewUnauthorizedMessageWithError(err, "Invalid Credentials")
	}
	upgrade, err := comparePassword(a.hasher, user.PasswordHash, password)
	if err != nil {
		return nil, httpio.NewUnauthorizedMessageWithError(err, "Invalid Credentials")
	}
	if upgrade && a.autoUpgrade {
		if err := a.setPasswordHash(ctx, user.ID, password); err != nil {
			logger.FromCtx(ctx).Error(err)
		} else {
			logger.FromCtx(ctx).Infof("auto-upgraded password hash for user %s, from %s to %s", user.Username, user.PasswordHash.KeyType(), a.hasher.KeyType())
		}
	}
	if user.Disabled {
		return nil, dbtype.Refusal("", sessioninfo.RefusedAccountDisabled, sessionstorage.ErrAccountDisabled, "Account disabled")
	}

	return user, nil
}

func (a *Auth[S, U]) setPasswordHash(ctx context.Context, userID ccc.UUID, password string) error {
	hash, err := a.hasher.Hash(password)
	if err != nil {
		return errors.Wrap(err, "securehash.SecureHasher.Hash()")
	}
	if err := a.storage.SetUserPasswordHash(ctx, userID, hash); err != nil {
		return errors.Wrap(err, "sessionstorage.AccountStore.SetUserPasswordHash()")
	}

	return nil
}

// passwordLogin is the password method's login handler.
func (a *Auth[S, U]) passwordLogin() http.HandlerFunc {
	type request struct {
		Username string `json:"username"`
		Password string `json:"password"`
	}
	decoder := newDecoder[request]()

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

		return httpio.NewEncoder(w).Ok(mfaResponse{MFAIsRequired: outcome.pending != nil})
	})
}

// changeUserPasswordHandler is the password method's change-password handler.
func (a *Auth[S, U]) changeUserPasswordHandler() http.HandlerFunc {
	type request struct {
		OldPassword string `json:"oldPassword"`
		NewPassword string `json:"newPassword"`
	}
	decoder := newDecoder[request]()

	return a.baseSession.Handle(func(w http.ResponseWriter, r *http.Request) error {
		ctx, span := tracer.Start(r.Context())
		defer span.End()

		if err := refuseImpersonated(ctx, a.baseSession, "ChangeUserPassword", true); err != nil {
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
type mfaResponse struct {
	MFAIsRequired bool `json:"mfaIsRequired"`
}

// refusalResponse is a JSON sign-in handler's answer to a refused sign-in.
type refusalResponse struct {
	Message string                       `json:"message"`
	Code    sessioninfo.LoginRefusalCode `json:"code"`
}

// writeSignInError answers a JSON sign-in handler's error: a refused sign-in (a
// sessioninfo.LoginRefusal) is its status (401, or 403 for a forbidden cause) with
// {"message", "code"}, so the page can map the code to its own text; anything else is
// the usual client message.
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

// identityEvent is the auth event of a sign-in with identity, at at.
func identityEvent(identity *sessioninfo.Identity, at time.Time) sessioninfo.AuthEvent {
	return sessioninfo.AuthEvent{Method: identity.Method, Connection: identity.Connection, IdPAMR: slices.Clone(identity.IdPAMR), At: at}
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
func (a *Auth[S, U]) shared() sharedAPI[S, U] {
	return sharedAPI[S, U]{base: a.baseSession, store: a.storage, users: a.storage, storeName: "AccountStore"}
}
