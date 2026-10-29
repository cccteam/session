package session

import (
	"context"
	"math"
	"net/http"
	"slices"
	"strconv"
	"time"

	"github.com/cccteam/ccc"
	"github.com/cccteam/ccc/securehash"
	"github.com/cccteam/ccc/tracer"
	"github.com/cccteam/httpio"
	"github.com/cccteam/logger"
	"github.com/cccteam/session/internal/attempts"
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
	// account rules decide it and whose method reconciles its roles. It is empty for a
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
	// customData is the per-call custom session data of an application-started
	// session, nil for none; the custom session data resolver is skipped when set.
	customData any
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

	// An identity whose connection attests to a second factor records the
	// attestation after the sign-in's own event, so the policy and the session see it.
	if at.events == nil && at.identity.Attestation != sessioninfo.NotAttested {
		at.events = identityEvents(at.identity)
	}
	req := &sessioninfo.NewSessionRequest{
		Reason:                at.reason,
		Username:              at.username,
		UserID:                at.userID,
		Claims:                at.identity.Claims,
		Identity:              at.identity,
		AuthEvents:            at.events,
		ProviderSessionID:     at.providerSessionID,
		ProviderSessionIssuer: at.providerSessionIssuer,
		RoleNames:             at.roleNames,
		CustomData:            at.customData,
	}

	// A sign-in the directory's roles admit nowhere is refused here, before the store
	// resolves, writes or consumes anything: a refused person keeps the invitation
	// they carried.
	if err := a.admitRoles(ctx, at); err != nil {
		return nil, err
	}

	// The invitation the browser opened, if any, goes with the sign-in: the store
	// accepts it once the user is known.
	inv, err := a.invitationOf(ctx)
	if err != nil {
		return nil, err
	}
	req.Invitation = inv

	// An external identity is decided by its registration's account rules; a password
	// identity, or the application's own, names its user and needs none.
	var (
		rule     signin.AccountRule[Tx]
		standard signin.StandardAccountRule
	)
	if m, ok := a.registered().external[at.registration]; ok {
		rule, standard = m.rule, m.standard
	}
	id, err := sessioncore.EstablishSession(ctx, w, a.baseSession, at.sameSite, func(ctx context.Context) (ccc.UUID, error) {
		id, err := a.storage.SignIn(ctx, req, sessionstorage.SignInRules[Tx]{
			Account: rule, Standard: standard, Policy: a.policy, Accept: a.acceptInvitation,
			Directories: a.directories, Roles: a.directoryRoles, Seat: a.directorySeated, TrustedDevice: a.trustedDeviceOf,
		})
		if err != nil {
			return ccc.NilUUID, errors.Wrap(err, "sessionstorage.AuthStore.SignIn()")
		}
		if err := a.afterInsert(ctx, at, req); err != nil {
			if derr := a.storage.DestroySession(ctx, id); derr != nil {
				logger.FromCtx(ctx).Error(errors.Wrap(derr, "sessionstorage.AuthStore.DestroySession()"))
			}

			return ccc.NilUUID, err
		}
		// The user's last sign-in and the address a method verified are bookkeeping,
		// written once the session stands: a failure is logged and the sign-in goes on.
		if err := a.storage.TouchUserSignIn(ctx, req.UserID); err != nil {
			logger.FromCtx(ctx).Error(errors.Wrap(err, "sessionstorage.AuthStore.TouchUserSignIn()"))
		}
		a.claimVerifiedEmail(ctx, req.UserID, at.identity)

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
		// A browser whose trusted device did not stand in for the factor carries a
		// dead one for this user: their entry goes, the other users' stay, and the
		// factor the person is about to give may set a new one.
		if wait.Reason == sessioninfo.PendingMFA {
			a.dropTrustedEntry(ctx, w, wait.UserID)
		}

		return &signInOutcome{pending: pending}, nil
	}
	if err != nil {
		return nil, err
	}

	events := signedInEvents(at, req)
	a.endPending(ctx, w, at)
	a.endInvitation(ctx, w, req.Invitation)
	a.touchTrustedDevice(ctx, req.UserID, events)
	sessioncore.LogSessionStarted(ctx, req.Username, id)
	a.notifySignedIn(ctx, &SignedIn{SessionID: id, UserID: req.UserID, Username: req.Username, Reason: at.reason, Events: events})

	return &signInOutcome{sessionID: id, userID: req.UserID}, nil
}

// signedInEvents are the auth events the session of at recorded: the events the
// store inserted (req.AuthEvents, which the sign-in flow may have extended with a
// trusted-device event), or the identity's method when the request carried none.
func signedInEvents(at *signInAttempt, req *sessioninfo.NewSessionRequest) []sessioninfo.AuthEvent {
	if len(req.AuthEvents) == 0 {
		return []sessioninfo.AuthEvent{identityEvent(at.identity)}
	}

	return slices.Clone(req.AuthEvents)
}

// notifySignedIn calls the SignedInHook, once the session stands. An error is logged,
// and the session stands.
func (a *Auth[S, U, Tx]) notifySignedIn(ctx context.Context, signedIn *SignedIn) {
	if a.signedIn == nil {
		return
	}
	if err := a.signedIn(ctx, signedIn); err != nil {
		logger.FromCtx(ctx).Error(errors.Wrap(err, "SignedInHook()"))
	}
}

// admitRoles refuses, before anything is resolved, written or consumed, a sign-in
// whose method synchronizes roles and recognizes none of the role names the directory
// asserted (no_roles): the refusal SyncRoles makes once the session stands, made here
// so that a refused person keeps the invitation they carried. A method that cannot
// tell beforehand (no RecognizesRoles) is still refused by SyncRoles.
func (a *Auth[S, U, Tx]) admitRoles(ctx context.Context, at *signInAttempt) error {
	if at.roleNames == nil {
		return nil
	}
	m, ok := a.registered().external[at.registration]
	if !ok || m.RecognizesRoles == nil {
		return nil
	}
	recognized, err := m.RecognizesRoles(ctx, at.roleNames)
	if err != nil {
		return errors.Wrap(err, "signin.Method.RecognizesRoles()")
	}
	if !recognized {
		return signinflow.Refusal("", sessioninfo.RefusedNoRoles, signin.ErrNoRoles, "Unauthorized: user has no roles")
	}

	return nil
}

// afterInsert runs once the session row exists and req carries the resolved user.
// It refuses a completion that resolved to a different user, and reconciles the
// method's roles; the roles were checked before the sign-in was resolved
// (admitRoles), so a refusal here is a method that could not tell beforehand.
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

	return &sessioninfo.UserInfo{
		ID: user.ID, Username: user.Username, PasswordChangeRequired: user.PasswordChangeRequired, Email: user.Email, EmailVerifiedAt: user.EmailVerifiedAt,
	}, nil
}

// validateRequest validates the session as validate does and then refuses the request
// of a user who must change their password (RefusedPasswordChangeRequired, Forbidden),
// as every request is but the password change, the session read and the logout, which
// validate on their own. An impersonated session is the actor's and is not held to the
// user's mark.
func (a *Auth[S, U, Tx]) validateRequest(ctx context.Context) (context.Context, error) {
	ctx, err := a.validate(ctx)
	if err != nil {
		return ctx, err
	}
	if _, impersonated := sessioninfo.ImpersonationFromCtx(ctx); !impersonated && sessioninfo.UserFromCtx(ctx).PasswordChangeRequired {
		return ctx, errPasswordChangeRequired()
	}

	return ctx, nil
}

// errPasswordChangeRequired is the refusal of a request under the password change mark.
func errPasswordChangeRequired() error {
	return sessioninfo.NewLoginRefusal(sessioninfo.RefusedPasswordChangeRequired, httpio.NewForbiddenMessage("Change your password to continue"))
}

// passwordSignIn checks username and password for client and signs the user in.
func (a *Auth[S, U, Tx]) passwordSignIn(ctx context.Context, w http.ResponseWriter, username, password string, client attempts.Client) (*signInOutcome, error) {
	user, err := a.checkCredentials(ctx, username, password, client)
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

// checkCredentials returns the enabled user for username when password matches, under
// the attempt limiter. A name or a client the limiter holds is refused before anything
// is read or hashed, with too_many_attempts and the wait. Otherwise the user is looked
// up and the password compared: against a dummy hash when there is no user or no
// password, so an unknown name takes as long as a known one, and a missing user, a
// wrong password and a password-less user are all invalid credentials, counted against
// the name and the client alike. A match resets the name. An outdated hash is upgraded
// when auto-upgrade is enabled, and a disabled user is refused after the match.
func (a *Auth[S, U, Tx]) checkCredentials(ctx context.Context, username, password string, client attempts.Client) (*sessionstorage.SessionUser, error) {
	methods := a.registered()
	if err := a.limitAttempt(ctx, username, client); err != nil {
		return nil, err
	}

	user, lookupErr := a.storage.UserByUserName(ctx, username)
	if lookupErr != nil && !httpio.HasNotFound(lookupErr) {
		return nil, httpio.NewUnauthorizedMessageWithError(lookupErr, "Invalid Credentials")
	}
	var hash *securehash.Hash
	if lookupErr == nil {
		hash = user.PasswordHash
	}
	upgrade, err := a.compareOrDummy(ctx, methods, hash, password)
	if err != nil {
		a.recordFailure(ctx, username, client)
		// The log names the cause: no such user, or the comparison's failure.
		if lookupErr != nil {
			err = lookupErr
		}

		return nil, httpio.NewUnauthorizedMessageWithError(err, "Invalid Credentials")
	}
	a.attemptsSucceeded(ctx, username)
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

// setPasswordHash re-hashes a password the user already has (the hash upgrade), leaving
// the password change mark as it is.
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

// setPassword sets a new password and whether the user must change it: true for a
// password an operator set, false for one the user chose.
func (a *Auth[S, U, Tx]) setPassword(ctx context.Context, userID ccc.UUID, password string, changeRequired bool) error {
	hash, err := a.registered().hasher.Hash(password)
	if err != nil {
		return errors.Wrap(err, "securehash.SecureHasher.Hash()")
	}
	if err := a.storage.SetUserPassword(ctx, userID, hash, changeRequired); err != nil {
		return errors.Wrap(err, "sessionstorage.AuthStore.SetUserPassword()")
	}

	return nil
}

// limitAttempt asks the attempt limiter whether an attempt on username by client may
// go on, and refuses it with too_many_attempts and the wait when it may not.
func (a *Auth[S, U, Tx]) limitAttempt(ctx context.Context, username string, client attempts.Client) error {
	wait, err := a.registered().attempts.Check(ctx, username, client)
	if err != nil {
		return errors.Wrap(err, "attempts.Limiter.Check()")
	}
	if wait > 0 {
		return sessioninfo.NewTooManyAttemptsRefusal(wait)
	}

	return nil
}

// compareOrDummy compares password against hash, or against the dummy hash when there
// is none (no user, or a user without a password), which then fails as a wrong
// password does, in the same time. It reports whether a matching hash should be
// upgraded.
func (a *Auth[S, U, Tx]) compareOrDummy(ctx context.Context, methods *signInMethods[Tx], hash *securehash.Hash, password string) (upgrade bool, err error) {
	if hash != nil {
		return methods.comparePassword(hash, password)
	}
	dummy, err := methods.dummyHash()
	if err != nil {
		logger.FromCtx(ctx).Error(errors.Wrap(err, "the dummy hash could not be made: a refusal for a name with no password is not timed like one for a wrong password"))
	}
	if dummy != nil {
		// The outcome is the same whatever the comparison says.
		_, _ = methods.compare(dummy, password)
	}

	return false, sessioncore.ErrNoPassword
}

// recordFailure counts a failed attempt on username by client. A store failure is
// logged; the refusal stands either way.
func (a *Auth[S, U, Tx]) recordFailure(ctx context.Context, username string, client attempts.Client) {
	lock, err := a.registered().attempts.Failed(ctx, username, client)
	if err != nil {
		logger.FromCtx(ctx).Error(err)
	}
	if lock > 0 {
		logger.FromCtx(ctx).Warnf("sign-in attempts on %q reached the limit: refused for %s", username, lock)
	}
}

// attemptsSucceeded resets username's attempts after a matching password. A store
// failure is logged; the sign-in goes on.
func (a *Auth[S, U, Tx]) attemptsSucceeded(ctx context.Context, username string) {
	if err := a.registered().attempts.Succeeded(ctx, username); err != nil {
		logger.FromCtx(ctx).Error(err)
	}
}

// clearAttempts resets username's attempts after an MFA completion or a password
// change. A store failure is logged; the operation stands.
func (a *Auth[S, U, Tx]) clearAttempts(ctx context.Context, username string) {
	if err := a.registered().attempts.Clear(ctx, username); err != nil {
		logger.FromCtx(ctx).Error(err)
	}
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

		outcome, err := a.passwordSignIn(ctx, w, req.Username, req.Password, a.clientOf(r))
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

// changeUserPasswordHandler is the password method's change-password handler. It is
// the one route a user who must change their password reaches, so it validates the
// session itself, without the mark's refusal, unless ValidateSession already has.
func (a *Auth[S, U, Tx]) changeUserPasswordHandler() http.HandlerFunc {
	type request struct {
		OldPassword string `json:"oldPassword"`
		NewPassword string `json:"newPassword"`
	}
	decoder := sessioncore.NewDecoder[request]()

	return a.baseSession.Handle(func(w http.ResponseWriter, r *http.Request) error {
		ctx, span := tracer.Start(r.Context())
		defer span.End()

		if _, validated := ctx.Value(sessioninfo.CtxUserInfo).(*sessioninfo.UserInfo); !validated {
			var err error
			if ctx, err = a.validate(ctx); err != nil {
				return httpio.NewEncoder(w).ClientMessage(ctx, err)
			}
		}
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

// refusalResponse is a JSON sign-in handler's answer to a refused sign-in. RetryAfter
// is the wait in seconds of a too_many_attempts refusal, and absent otherwise.
type refusalResponse struct {
	Message    string                       `json:"message"`
	Code       sessioninfo.LoginRefusalCode `json:"code"`
	RetryAfter int                          `json:"retryAfter,omitempty"`
}

// writeSignInError writes a JSON sign-in handler's error. A sessioninfo.LoginRefusal
// is answered with 401 (403 for a forbidden cause) and {"message", "code"}, so the
// page can map the code to its own text; a too_many_attempts refusal is 429 with the
// wait in seconds as "retryAfter" and the Retry-After header. Any other error is the
// usual client message.
func writeSignInError(ctx context.Context, w http.ResponseWriter, err error) error {
	var refusal *sessioninfo.LoginRefusal
	if !errors.As(err, &refusal) {
		if werr := httpio.NewEncoder(w).ClientMessage(ctx, err); werr != nil {
			return errors.Wrap(werr, "httpio.Encoder.ClientMessage()")
		}

		return nil
	}

	status := http.StatusUnauthorized
	body := refusalResponse{Message: httpio.Message(err), Code: refusal.Code()}
	switch {
	case httpio.HasForbidden(err):
		status = http.StatusForbidden
	case httpio.HasTooManyRequests(err):
		status = http.StatusTooManyRequests
	}
	if wait, ok := sessioninfo.RetryAfterOf(err); ok {
		body.RetryAfter = retryAfterSeconds(wait)
		w.Header().Set("Retry-After", strconv.Itoa(body.RetryAfter))
	}
	if werr := httpio.NewEncoder(w).StatusCodeWithBody(status, body); werr != nil {
		return errors.Wrap(werr, "httpio.Encoder.StatusCodeWithBody()")
	}

	return err
}

// retryAfterSeconds renders a wait as the whole seconds Retry-After carries, rounded
// up, and at least one so a client never retries at once.
func retryAfterSeconds(wait time.Duration) int {
	return max(int(math.Ceil(wait.Seconds())), 1)
}

// namesItsUser reports whether identity names its user instead of being resolved to
// one: a password identity, or the application's own (StartAuthenticatedSession).
func namesItsUser(identity *sessioninfo.Identity) bool {
	return identity.Method == sessioninfo.MethodPassword || identity.Method == sessioninfo.MethodApplication
}

// identityEvent returns the auth event of a sign-in with identity. Its time is the
// database's when the event is stored.
func identityEvent(identity *sessioninfo.Identity) sessioninfo.AuthEvent {
	return sessioninfo.AuthEvent{Method: identity.Method, Connection: identity.Connection, IDPAMR: slices.Clone(identity.IDPAMR)}
}

// identityEvents returns the auth events of a sign-in with identity: the sign-in's
// own, then the attestation the identity's connection makes, when it makes one, under
// the same connection and with the provider's evidence.
func identityEvents(identity *sessioninfo.Identity) []sessioninfo.AuthEvent {
	events := []sessioninfo.AuthEvent{identityEvent(identity)}
	if method := identity.Attestation.Method(); method != "" {
		events = append(events, sessioninfo.AuthEvent{Method: method, Connection: identity.Connection, IDPAMR: slices.Clone(identity.IDPAMR)})
	}

	return events
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
