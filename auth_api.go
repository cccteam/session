package session

import (
	"context"
	"net/http"

	"github.com/cccteam/ccc"
	"github.com/cccteam/ccc/securehash"
	"github.com/cccteam/ccc/tracer"
	"github.com/cccteam/httpio"
	"github.com/cccteam/session/internal/attempts"
	"github.com/cccteam/session/internal/sessioncore"
	"github.com/cccteam/session/sessioninfo"
	"github.com/cccteam/session/sessionstorage"
	"github.com/go-playground/errors/v5"
)

// ValidateSession validates the session cookie and stores the session data and its
// user (sessioninfo.UserFromCtx) in the context. Like Auth.ValidateSession, it
// refuses a session whose user is missing or disabled as unauthorized, and the request
// of a user who must change their password as forbidden, with a
// *sessioninfo.LoginRefusal carrying RefusedPasswordChangeRequired.
func (p *AuthAPI[S, U, Tx]) ValidateSession(ctx context.Context) (context.Context, error) {
	return p.auth.validateRequest(ctx)
}

// ValidateCredentials checks a username and password and returns the user ID. A
// password-less user always fails validation. It starts no session and asks no
// sign-in policy. It is limited as the login is: a failure counts against the name,
// and a name whose attempts reached the limit is refused with a
// *sessioninfo.LoginRefusal carrying RefusedTooManyAttempts and the wait
// (sessioninfo.RetryAfterOf), before the user is looked up or the password hashed.
// The call has no client, so only the name is counted.
func (p *AuthAPI[S, U, Tx]) ValidateCredentials(ctx context.Context, username, password string) (ccc.UUID, error) {
	user, err := p.auth.checkCredentials(ctx, username, password, attempts.Client{})
	if err != nil {
		return ccc.NilUUID, err
	}

	return user.ID, nil
}

// StartAuthenticatedSession starts a session for an existing user the application
// authenticated itself, recording how in events, which must name at least one method:
// a sign-up that just created the user, a factor the application ran on its own. It is
// decided like a login: the sign-in policy, when one is set, answers with the request's
// ReasonExternalAuth, and the library refuses a missing or disabled user. An Allow
// establishes the session under a new session ID; a Deny is a refusal
// (sessioninfo.LoginRefusal); a RequireMFA holds the sign-in as the browser's pending
// identity and returns a *signin.PendingSignInError, as CompletePending does, for
// CompletePending to finish. There is no session start that skips the policy: a support
// session is StartImpersonatedSession.
//
// An event with a zero At records the session's creation time. Optional customData
// (at most one *S) is written atomically with the session insert, and the custom
// session data resolver is not called for it; without it the resolver receives
// ReasonExternalAuth.
func (p *AuthAPI[S, U, Tx]) StartAuthenticatedSession(ctx context.Context, w http.ResponseWriter, userID ccc.UUID, events []sessioninfo.AuthEvent, customData ...*S) (ccc.UUID, error) {
	ctx, span := tracer.Start(ctx)
	defer span.End()

	if len(customData) > 1 {
		return ccc.NilUUID, errors.New("at most one customData value may be provided; it is the complete custom session data row")
	}
	if len(events) == 0 {
		return ccc.NilUUID, httpio.NewBadRequestMessage("StartAuthenticatedSession records how the user authenticated: pass at least one auth event")
	}
	if err := validateEvents(events); err != nil {
		return ccc.NilUUID, err
	}

	user, err := p.auth.storage.User(ctx, userID)
	if err != nil {
		return ccc.NilUUID, errors.Wrap(err, "sessionstorage.AuthStore.User()")
	}

	at := &signInAttempt{
		identity: &sessioninfo.Identity{Method: sessioninfo.MethodApplication, Subject: user.ID.String()},
		reason:   sessioninfo.ReasonExternalAuth,
		userID:   user.ID,
		username: user.Username,
		events:   events,
		sameSite: sessioncore.SameSiteStrict,
	}
	if len(customData) == 1 && customData[0] != nil {
		at.customData = customData[0]
	}
	outcome, err := p.auth.signIn(ctx, w, at)
	if err != nil {
		return ccc.NilUUID, err
	}
	if outcome.pending != nil {
		return ccc.NilUUID, stillPending(outcome.pending)
	}

	return outcome.sessionID, nil
}

// startSession inserts req's session and writes its cookies. It is for sessions the
// application or a user operation starts, with no identity to resolve.
func (a *Auth[S, U, Tx]) startSession(ctx context.Context, w http.ResponseWriter, req *sessioninfo.NewSessionRequest) (ccc.UUID, error) {
	id, err := sessioncore.EstablishSession(ctx, w, a.baseSession, sessioncore.SameSiteStrict, func(ctx context.Context) (ccc.UUID, error) {
		id, err := a.storage.CreateSession(ctx, req)
		if err != nil {
			return ccc.NilUUID, errors.Wrap(err, "sessionstorage.AuthStore.CreateSession()")
		}

		return id, nil
	})
	if err != nil {
		return ccc.NilUUID, err
	}

	sessioncore.LogSessionStarted(ctx, req.Username, id)

	return id, nil
}

// Logout destroys the current session.
func (p *AuthAPI[S, U, Tx]) Logout(ctx context.Context) error {
	return p.auth.shared().Logout(ctx)
}

// CreateSessionUser creates a user. A nil req.Password creates a password-less
// user. req.PasswordChangeRequired marks the password as one an operator set, which
// the user changes before anything else is served; a user without a password has
// nothing to change, so the mark without a password is a BadRequest. req.Email, when
// given, is written unverified and reserves the address; one another user holds is a
// Conflict.
func (p *AuthAPI[S, U, Tx]) CreateSessionUser(ctx context.Context, req *CreateUserRequest, customData ...*U) (ccc.UUID, error) {
	ctx, span := tracer.Start(ctx)
	defer span.End()

	if len(customData) > 1 {
		return ccc.NilUUID, errors.New("at most one customData value may be provided; it is the complete custom user data row")
	}
	if req.PasswordChangeRequired && req.Password == nil {
		return ccc.NilUUID, httpio.NewBadRequestMessage("a password change can only be required of a user that has a password")
	}

	var hash *securehash.Hash
	if req.Password != nil {
		var err error
		if hash, err = p.auth.registered().hasher.Hash(*req.Password); err != nil {
			return ccc.NilUUID, errors.Wrap(err, "securehash.SecureHasher.Hash()")
		}
	}

	// Explicit conversion so a typed nil *U never crosses as a non-nil any.
	var data any
	if len(customData) == 1 && customData[0] != nil {
		data = customData[0]
	}

	email, err := optionalAddress(req.Email)
	if err != nil {
		return ccc.NilUUID, err
	}
	user, err := p.auth.storage.CreateUser(ctx, &sessionstorage.InsertSessionUser{
		Username: req.Username, PasswordHash: hash, Disabled: req.Disabled, PasswordChangeRequired: req.PasswordChangeRequired, Email: email,
	}, data)
	if err != nil {
		return ccc.NilUUID, errors.Wrap(err, "sessionstorage.AuthStore.CreateUser()")
	}

	return user.ID, nil
}

// Users lists every user, by username. A user carries its username, whether it is
// disabled, its password hash (nil for a password-less user), whether it must change
// its password, when it was created and when it last signed in.
func (p *AuthAPI[S, U, Tx]) Users(ctx context.Context) ([]*sessionstorage.SessionUser, error) {
	users, err := p.auth.storage.Users(ctx)
	if err != nil {
		return nil, errors.Wrap(err, "sessionstorage.AuthStore.Users()")
	}

	return users, nil
}

// User returns a user by ID, or a NotFound error.
func (p *AuthAPI[S, U, Tx]) User(ctx context.Context, userID ccc.UUID) (*sessionstorage.SessionUser, error) {
	user, err := p.auth.storage.User(ctx, userID)
	if err != nil {
		return nil, errors.Wrap(err, "sessionstorage.AuthStore.User()")
	}

	return user, nil
}

// UserByUsername returns a user by username, matched without regard to case, or a
// NotFound error.
func (p *AuthAPI[S, U, Tx]) UserByUsername(ctx context.Context, username string) (*sessionstorage.SessionUser, error) {
	user, err := p.auth.storage.UserByUserName(ctx, username)
	if err != nil {
		return nil, errors.Wrap(err, "sessionstorage.AuthStore.UserByUserName()")
	}

	return user, nil
}

// ChangeSessionUserUsername changes a user's username, and atomically the username
// on its live sessions.
func (p *AuthAPI[S, U, Tx]) ChangeSessionUserUsername(ctx context.Context, userID ccc.UUID, username string) error {
	if err := p.auth.storage.SetUserUsername(ctx, userID, username); err != nil {
		return errors.Wrap(err, "sessionstorage.AuthStore.SetUserUsername()")
	}

	return nil
}

// ChangeSessionUserPassword changes a user's password to one the user chose and
// regenerates its session.
//
// The old password must match and the new one must differ from it (BadRequest
// otherwise). The password change mark is cleared, every session of the user is
// destroyed, by UserId, and the caller continues in a new session (ReasonRegeneration)
// that records a password event.
func (p *AuthAPI[S, U, Tx]) ChangeSessionUserPassword(ctx context.Context, w http.ResponseWriter, userID ccc.UUID, req *ChangeSessionUserPasswordRequest) error {
	ctx, span := tracer.Start(ctx)
	defer span.End()

	a := p.auth
	user, err := a.storage.User(ctx, userID)
	if err != nil {
		return errors.Wrap(err, "sessionstorage.AuthStore.User()")
	}
	if _, err := sessioncore.ComparePassword(a.registered().hasher, user.PasswordHash, req.OldPassword); err != nil {
		return httpio.NewBadRequestMessageWithError(err, "Old password incorrect")
	}
	if req.NewPassword == req.OldPassword {
		return httpio.NewBadRequestMessage("The new password must differ from the old one")
	}

	if err := a.storage.DestroyUserSessions(ctx, user.ID); err != nil {
		return errors.Wrap(err, "sessionstorage.AuthStore.DestroyUserSessions()")
	}
	if err := a.setPassword(ctx, user.ID, req.NewPassword, false); err != nil {
		return err
	}
	a.clearAttempts(ctx, user.Username)

	// The regenerated session keeps the provider's session id, and its issuer, of the
	// session it replaces, so a provider-initiated logout still finds it.
	req2 := &sessioninfo.NewSessionRequest{
		Reason:     sessioninfo.ReasonRegeneration,
		Username:   user.Username,
		UserID:     user.ID,
		AuthEvents: []sessioninfo.AuthEvent{{Method: sessioninfo.MethodPassword}},
	}
	if current, ok := ctx.Value(sessioninfo.CtxSessionInfo).(*sessioninfo.SessionData); ok && current != nil {
		req2.ProviderSessionID = current.ProviderSessionID
		req2.ProviderSessionIssuer = current.ProviderSessionIssuer
	}
	_, err = a.startSession(ctx, w, req2)

	return err
}

// SetSessionUserPassword sets a password the user chose, without the old one: the end
// of a flow of the application's own that proved who they are (a reset link, an
// enrollment). The password change mark is cleared, the user's sessions are
// destroyed and the name's sign-in attempts are reset. A password an operator chose
// is ResetSessionUserPassword.
func (p *AuthAPI[S, U, Tx]) SetSessionUserPassword(ctx context.Context, userID ccc.UUID, password string) error {
	return p.auth.replacePassword(ctx, userID, password, false)
}

// ResetSessionUserPassword sets a temporary password an operator chose: the user must
// change it before anything else is served (SessionUser.PasswordChangeRequired; see
// "Users and the forced password change" in the README), its sessions are destroyed
// and the name's sign-in attempts are reset.
func (p *AuthAPI[S, U, Tx]) ResetSessionUserPassword(ctx context.Context, userID ccc.UUID, temporary string) error {
	return p.auth.replacePassword(ctx, userID, temporary, true)
}

// replacePassword sets a new password for userID with its change mark, destroys the
// user's sessions and resets the name's sign-in attempts.
func (a *Auth[S, U, Tx]) replacePassword(ctx context.Context, userID ccc.UUID, password string, changeRequired bool) error {
	user, err := a.storage.User(ctx, userID)
	if err != nil {
		return errors.Wrap(err, "sessionstorage.AuthStore.User()")
	}
	if err := a.setPassword(ctx, userID, password, changeRequired); err != nil {
		return err
	}
	if err := a.storage.DestroyUserSessions(ctx, userID); err != nil {
		return errors.Wrap(err, "sessionstorage.AuthStore.DestroyUserSessions()")
	}
	a.clearAttempts(ctx, user.Username)

	return nil
}

// DeactivateSessionUser disables a user and destroys its sessions. The caller must
// guard against self-deactivation.
func (p *AuthAPI[S, U, Tx]) DeactivateSessionUser(ctx context.Context, userID ccc.UUID) error {
	if err := p.auth.storage.DeactivateUser(ctx, userID); err != nil {
		return errors.Wrap(err, "sessionstorage.AuthStore.DeactivateUser()")
	}
	if err := p.auth.storage.DestroyUserSessions(ctx, userID); err != nil {
		return errors.Wrap(err, "sessionstorage.AuthStore.DestroyUserSessions()")
	}

	return nil
}

// ActivateSessionUser enables a user.
func (p *AuthAPI[S, U, Tx]) ActivateSessionUser(ctx context.Context, userID ccc.UUID) error {
	if err := p.auth.storage.ActivateUser(ctx, userID); err != nil {
		return errors.Wrap(err, "sessionstorage.AuthStore.ActivateUser()")
	}

	return nil
}

// DeleteSessionUser deletes a user with its identity links and sessions. The
// sessions are destroyed first, by UserId, so a failed delete leaves no live session
// behind. The caller must guard against self-deletion.
func (p *AuthAPI[S, U, Tx]) DeleteSessionUser(ctx context.Context, userID ccc.UUID) error {
	if _, err := p.auth.storage.User(ctx, userID); err != nil {
		return errors.Wrap(err, "sessionstorage.AuthStore.User()")
	}
	if err := p.auth.storage.DestroyUserSessions(ctx, userID); err != nil {
		return errors.Wrap(err, "sessionstorage.AuthStore.DestroyUserSessions()")
	}
	if err := p.auth.storage.DeleteUser(ctx, userID); err != nil {
		return errors.Wrap(err, "sessionstorage.AuthStore.DeleteUser()")
	}

	return nil
}

// DestroyUserSessions expires every session of a user.
func (p *AuthAPI[S, U, Tx]) DestroyUserSessions(ctx context.Context, userID ccc.UUID) error {
	if err := p.auth.storage.DestroyUserSessions(ctx, userID); err != nil {
		return errors.Wrap(err, "sessionstorage.AuthStore.DestroyUserSessions()")
	}

	return nil
}

// Identities lists a user's linked external identities.
func (p *AuthAPI[S, U, Tx]) Identities(ctx context.Context, userID ccc.UUID) ([]*sessionstorage.SessionIdentity, error) {
	identities, err := p.auth.storage.IdentitiesByUser(ctx, userID)
	if err != nil {
		return nil, errors.Wrap(err, "sessionstorage.AuthStore.IdentitiesByUser()")
	}

	return identities, nil
}

// UnlinkIdentity removes an identity link. The last means of sign-in of a password-less
// user is refused (sessionstorage.ErrLastSignInMethod, Conflict).
func (p *AuthAPI[S, U, Tx]) UnlinkIdentity(ctx context.Context, identityID ccc.UUID) error {
	if err := p.auth.storage.UnlinkIdentity(ctx, identityID); err != nil {
		return errors.Wrap(err, "sessionstorage.AuthStore.UnlinkIdentity()")
	}

	return nil
}

// UpdateCustomSessionData updates the custom session data of an active session.
func (p *AuthAPI[S, U, Tx]) UpdateCustomSessionData(ctx context.Context, sessionID ccc.UUID, mutate func(data *S) error) error {
	return p.auth.shared().UpdateCustomSessionData(ctx, sessionID, mutate)
}

// CustomData returns the current session's custom data.
func (p *AuthAPI[S, U, Tx]) CustomData(ctx context.Context) (S, error) {
	return p.auth.shared().CustomData(ctx)
}

// CustomUserData returns a user's custom user data.
func (p *AuthAPI[S, U, Tx]) CustomUserData(ctx context.Context, userID ccc.UUID) (U, error) {
	return p.auth.shared().CustomUserData(ctx, userID)
}

// UpdateCustomUserData updates a user's custom user data.
func (p *AuthAPI[S, U, Tx]) UpdateCustomUserData(ctx context.Context, userID ccc.UUID, mutate func(data *U) error) error {
	return p.auth.shared().UpdateCustomUserData(ctx, userID, mutate)
}

// StartImpersonatedSession starts an impersonated session, with the same semantics as
// the other session types. A user principal resolves against the users, as on
// PasswordAuth.
//
// A user principal's session belongs to the impersonated user (SessionData.UserID).
// A role principal's session belongs to no user (null UserID). The session records
// an impersonation auth event whose connection is the actor.
func (p *AuthAPI[S, U, Tx]) StartImpersonatedSession(ctx context.Context, w http.ResponseWriter, req *ImpersonationRequest, customData ...*S) (ccc.UUID, error) {
	return p.auth.shared().StartImpersonatedSession(ctx, w, req, customData, sessioncore.UserIdentity(p.auth.storage))
}

// DestroyImpersonatedSessions expires every impersonated session started by actor.
func (p *AuthAPI[S, U, Tx]) DestroyImpersonatedSessions(ctx context.Context, actor string) error {
	return p.auth.shared().DestroyImpersonatedSessions(ctx, actor)
}

// ActiveImpersonations lists active impersonations matching q.
func (p *AuthAPI[S, U, Tx]) ActiveImpersonations(ctx context.Context, q *ImpersonationQuery) ([]*sessioninfo.Impersonation, error) {
	return p.auth.shared().ActiveImpersonations(ctx, q)
}

// DestroyImpersonatedSession expires one impersonated session.
func (p *AuthAPI[S, U, Tx]) DestroyImpersonatedSession(ctx context.Context, sessionID ccc.UUID) error {
	return p.auth.shared().DestroyImpersonatedSession(ctx, sessionID)
}

// EndImpersonation ends the current impersonated session, restoring the actor's
// session when possible.
func (p *AuthAPI[S, U, Tx]) EndImpersonation(ctx context.Context, w http.ResponseWriter) (restored bool, err error) {
	return p.auth.shared().EndImpersonation(ctx, w)
}
