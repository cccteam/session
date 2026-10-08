package session

import (
	"context"
	"net/http"

	"github.com/cccteam/ccc"
	"github.com/cccteam/ccc/securehash"
	"github.com/cccteam/ccc/tracer"
	"github.com/cccteam/httpio"
	"github.com/cccteam/session/sessioninfo"
	"github.com/cccteam/session/sessionstorage"
	"github.com/go-playground/errors/v5"
)

// ValidateSession validates the session cookie and stores session data in the context,
// with the session's account (sessioninfo.UserFromCtx): a session whose account is
// missing or disabled is refused as unauthorized, as Auth.ValidateSession does.
func (p *AuthAPI[S, U]) ValidateSession(ctx context.Context) (context.Context, error) {
	return p.auth.validate(ctx)
}

// ValidateCredentials checks a username and password and returns the account ID. A
// password-less account always fails validation. It starts no session and asks no
// sign-in policy.
func (p *AuthAPI[S, U]) ValidateCredentials(ctx context.Context, username, password string) (ccc.UUID, error) {
	user, err := p.auth.checkCredentials(ctx, username, password)
	if err != nil {
		return ccc.NilUUID, err
	}

	return user.ID, nil
}

// StartAuthenticatedSession starts a session for an existing account after the
// application has authenticated it itself, recording events; the sign-in policy is not
// consulted. It regenerates the session ID.
//
// The account must exist and be enabled. Each event needs a method; one with a zero At
// records the session's creation time. Optional customData (at most one *S) is written
// atomically with the session insert and the custom session data resolver is not
// invoked; otherwise the resolver receives ReasonExternalAuth.
func (p *AuthAPI[S, U]) StartAuthenticatedSession(ctx context.Context, w http.ResponseWriter, userID ccc.UUID, events []sessioninfo.AuthEvent, customData ...*S) (ccc.UUID, error) {
	ctx, span := tracer.Start(ctx)
	defer span.End()

	if len(customData) > 1 {
		return ccc.NilUUID, errors.New("at most one customData value may be provided; it is the complete custom session data row")
	}
	if err := validateEvents(events); err != nil {
		return ccc.NilUUID, err
	}

	user, err := p.auth.storage.User(ctx, userID)
	if err != nil {
		return ccc.NilUUID, errors.Wrap(err, "sessionstorage.AccountStore.User()")
	}
	if user.Disabled {
		return ccc.NilUUID, httpio.NewUnauthorizedMessage("Account disabled")
	}

	req := &sessioninfo.NewSessionRequest{Reason: sessioninfo.ReasonExternalAuth, Username: user.Username, UserID: user.ID, AuthEvents: events}
	if len(customData) == 1 && customData[0] != nil {
		req.CustomData = customData[0]
	}

	return p.auth.startSession(ctx, w, req)
}

// startSession inserts req's session and writes its cookies: a session the application
// or an account operation starts, with no identity to resolve.
func (a *Auth[S, U]) startSession(ctx context.Context, w http.ResponseWriter, req *sessioninfo.NewSessionRequest) (ccc.UUID, error) {
	id, err := establishSession(ctx, w, a.baseSession, sameSiteStrict, func(ctx context.Context) (ccc.UUID, error) {
		id, err := a.storage.CreateSession(ctx, req)
		if err != nil {
			return ccc.NilUUID, errors.Wrap(err, "sessionstorage.AccountStore.CreateSession()")
		}

		return id, nil
	})
	if err != nil {
		return ccc.NilUUID, err
	}

	logSessionStarted(ctx, req.Username, id)

	return id, nil
}

// Logout destroys the current session.
func (p *AuthAPI[S, U]) Logout(ctx context.Context) error {
	return p.auth.shared().logout(ctx)
}

// CreateSessionUser creates an account. A nil req.Password creates a password-less
// account.
func (p *AuthAPI[S, U]) CreateSessionUser(ctx context.Context, req *CreateUserRequest, customData ...*U) (ccc.UUID, error) {
	ctx, span := tracer.Start(ctx)
	defer span.End()

	if len(customData) > 1 {
		return ccc.NilUUID, errors.New("at most one customData value may be provided; it is the complete custom user data row")
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

	user, err := p.auth.storage.CreateUser(ctx, &sessionstorage.InsertSessionUser{Username: req.Username, PasswordHash: hash, Disabled: req.Disabled}, data)
	if err != nil {
		return ccc.NilUUID, errors.Wrap(err, "sessionstorage.AccountStore.CreateUser()")
	}

	return user.ID, nil
}

// ChangeSessionUserUsername changes an account's username, and atomically the username
// on its live sessions.
func (p *AuthAPI[S, U]) ChangeSessionUserUsername(ctx context.Context, userID ccc.UUID, username string) error {
	if err := p.auth.storage.SetUserUsername(ctx, userID, username); err != nil {
		return errors.Wrap(err, "sessionstorage.AccountStore.SetUserUsername()")
	}

	return nil
}

// ChangeSessionUserPassword changes an account's password and regenerates its session.
//
// The old password must match (BadRequest otherwise). Every session of the account is
// destroyed, by UserId, and the caller continues in a new session (ReasonRegeneration)
// that records a password event.
func (p *AuthAPI[S, U]) ChangeSessionUserPassword(ctx context.Context, w http.ResponseWriter, userID ccc.UUID, req *ChangeSessionUserPasswordRequest) error {
	ctx, span := tracer.Start(ctx)
	defer span.End()

	a := p.auth
	user, err := a.storage.User(ctx, userID)
	if err != nil {
		return errors.Wrap(err, "sessionstorage.AccountStore.User()")
	}
	if _, err := comparePassword(a.registered().hasher, user.PasswordHash, req.OldPassword); err != nil {
		return httpio.NewBadRequestMessageWithError(err, "Old password incorrect")
	}

	if err := a.storage.DestroyUserSessions(ctx, user.ID); err != nil {
		return errors.Wrap(err, "sessionstorage.AccountStore.DestroyUserSessions()")
	}
	if err := a.setPasswordHash(ctx, user.ID, req.NewPassword); err != nil {
		return err
	}

	_, err = a.startSession(ctx, w, &sessioninfo.NewSessionRequest{
		Reason:     sessioninfo.ReasonRegeneration,
		Username:   user.Username,
		UserID:     user.ID,
		AuthEvents: []sessioninfo.AuthEvent{{Method: sessioninfo.MethodPassword}},
	})

	return err
}

// SetSessionUserPassword sets an account's password without the old one (enrollment,
// reset), destroying its sessions.
func (p *AuthAPI[S, U]) SetSessionUserPassword(ctx context.Context, userID ccc.UUID, password string) error {
	if err := p.auth.setPasswordHash(ctx, userID, password); err != nil {
		return err
	}
	if err := p.auth.storage.DestroyUserSessions(ctx, userID); err != nil {
		return errors.Wrap(err, "sessionstorage.AccountStore.DestroyUserSessions()")
	}

	return nil
}

// DeactivateSessionUser disables an account and destroys its sessions. No
// self-deactivation guard is applied: that is the caller's.
func (p *AuthAPI[S, U]) DeactivateSessionUser(ctx context.Context, userID ccc.UUID) error {
	if err := p.auth.storage.DeactivateUser(ctx, userID); err != nil {
		return errors.Wrap(err, "sessionstorage.AccountStore.DeactivateUser()")
	}
	if err := p.auth.storage.DestroyUserSessions(ctx, userID); err != nil {
		return errors.Wrap(err, "sessionstorage.AccountStore.DestroyUserSessions()")
	}

	return nil
}

// ActivateSessionUser enables an account.
func (p *AuthAPI[S, U]) ActivateSessionUser(ctx context.Context, userID ccc.UUID) error {
	if err := p.auth.storage.ActivateUser(ctx, userID); err != nil {
		return errors.Wrap(err, "sessionstorage.AccountStore.ActivateUser()")
	}

	return nil
}

// DeleteSessionUser deletes an account, its identities and sessions. The sessions are
// destroyed first, by UserId, so a failed delete leaves no live session behind. No
// self-deletion guard is applied: that is the caller's.
func (p *AuthAPI[S, U]) DeleteSessionUser(ctx context.Context, userID ccc.UUID) error {
	if _, err := p.auth.storage.User(ctx, userID); err != nil {
		return errors.Wrap(err, "sessionstorage.AccountStore.User()")
	}
	if err := p.auth.storage.DestroyUserSessions(ctx, userID); err != nil {
		return errors.Wrap(err, "sessionstorage.AccountStore.DestroyUserSessions()")
	}
	if err := p.auth.storage.DeleteUser(ctx, userID); err != nil {
		return errors.Wrap(err, "sessionstorage.AccountStore.DeleteUser()")
	}

	return nil
}

// DestroyUserSessions expires every session of an account.
func (p *AuthAPI[S, U]) DestroyUserSessions(ctx context.Context, userID ccc.UUID) error {
	if err := p.auth.storage.DestroyUserSessions(ctx, userID); err != nil {
		return errors.Wrap(err, "sessionstorage.AccountStore.DestroyUserSessions()")
	}

	return nil
}

// Identities lists an account's linked external identities.
func (p *AuthAPI[S, U]) Identities(ctx context.Context, userID ccc.UUID) ([]*sessionstorage.SessionIdentity, error) {
	identities, err := p.auth.storage.IdentitiesByUser(ctx, userID)
	if err != nil {
		return nil, errors.Wrap(err, "sessionstorage.AccountStore.IdentitiesByUser()")
	}

	return identities, nil
}

// UnlinkIdentity removes an identity link. The last means of sign-in of a password-less
// account is refused (sessionstorage.ErrLastSignInMethod, Conflict).
func (p *AuthAPI[S, U]) UnlinkIdentity(ctx context.Context, identityID ccc.UUID) error {
	if err := p.auth.storage.UnlinkIdentity(ctx, identityID); err != nil {
		return errors.Wrap(err, "sessionstorage.AccountStore.UnlinkIdentity()")
	}

	return nil
}

// UpdateCustomSessionData updates the custom session data of an active session.
func (p *AuthAPI[S, U]) UpdateCustomSessionData(ctx context.Context, sessionID ccc.UUID, mutate func(data *S) error) error {
	return p.auth.shared().updateCustomSessionData(ctx, sessionID, mutate)
}

// CustomData returns the current session's custom data.
func (p *AuthAPI[S, U]) CustomData(ctx context.Context) (S, error) {
	return p.auth.shared().customData(ctx)
}

// CustomUserData returns an account's custom user data.
func (p *AuthAPI[S, U]) CustomUserData(ctx context.Context, userID ccc.UUID) (U, error) {
	return p.auth.shared().customUserData(ctx, userID)
}

// UpdateCustomUserData updates an account's custom user data.
func (p *AuthAPI[S, U]) UpdateCustomUserData(ctx context.Context, userID ccc.UUID, mutate func(data *U) error) error {
	return p.auth.shared().updateCustomUserData(ctx, userID, mutate)
}

// StartImpersonatedSession starts an impersonated session (same semantics as the
// legacy types): a user principal resolves against the accounts, as on PasswordAuth.
//
// For a user principal the session belongs to the impersonated account
// (SessionData.UserID); for a role principal it belongs to no account (null UserID).
// The session records an impersonation auth event whose connection is the actor.
func (p *AuthAPI[S, U]) StartImpersonatedSession(ctx context.Context, w http.ResponseWriter, req *ImpersonationRequest, customData ...*S) (ccc.UUID, error) {
	return p.auth.shared().startImpersonatedSession(ctx, w, req, customData, accountIdentity(p.auth.storage))
}

// DestroyImpersonatedSessions expires every impersonated session started by actor.
func (p *AuthAPI[S, U]) DestroyImpersonatedSessions(ctx context.Context, actor string) error {
	return p.auth.shared().destroyImpersonatedSessions(ctx, actor)
}

// ActiveImpersonations lists active impersonations matching q.
func (p *AuthAPI[S, U]) ActiveImpersonations(ctx context.Context, q *ImpersonationQuery) ([]*sessioninfo.Impersonation, error) {
	return p.auth.shared().activeImpersonations(ctx, q)
}

// DestroyImpersonatedSession expires one impersonated session.
func (p *AuthAPI[S, U]) DestroyImpersonatedSession(ctx context.Context, sessionID ccc.UUID) error {
	return p.auth.shared().destroyImpersonatedSession(ctx, sessionID)
}

// EndImpersonation ends the current impersonated session, restoring the actor's
// session when possible.
func (p *AuthAPI[S, U]) EndImpersonation(ctx context.Context, w http.ResponseWriter) (restored bool, err error) {
	return p.auth.shared().endImpersonation(ctx, w)
}
