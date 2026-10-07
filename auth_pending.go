package session

import (
	"bytes"
	"compress/gzip"
	"context"
	"encoding/base64"
	"encoding/json"
	"io"
	"net/http"
	"slices"
	"time"

	"github.com/cccteam/ccc"
	"github.com/cccteam/ccc/tracer"
	"github.com/cccteam/httpio"
	"github.com/cccteam/logger"
	"github.com/cccteam/session/cookie"
	"github.com/cccteam/session/internal/dbtype"
	"github.com/cccteam/session/sessioninfo"
	"github.com/cccteam/session/sessionstorage"
	"github.com/go-playground/errors/v5"
)

// A pending identity is a verified identity that waits for a password confirmation or
// the application's MFA step before it becomes a session. It is held in two parts:
//
//   - a preauth stepping-stone session row in the session table (no account, never
//     authenticated), which makes the pending identity single-use and revocable: it is
//     expired when the identity completes, is canceled or is replaced; and
//   - the pending cookie (default "auth-pending"), encrypted and authenticated with the
//     cookie key, which carries the identity itself (method, connection, subject, email,
//     claims), the account it waits on, the auth events so far, and where the browser
//     goes afterwards, bound to that row's ID.
//
// The identity is accepted only while both agree: the cookie decrypts, its expiry has
// not passed, and its row is live and accountless. Nothing about it is readable or
// forgeable by the browser.

// pendingCookieKey is the pending cookie's value holding the encoded pendingState.
const pendingCookieKey cookie.Key = "pending"

// maxPendingCookieValue bounds the encoded pending identity, so the cookie stays within
// what browsers keep (4096 bytes per cookie, encryption overhead included).
const maxPendingCookieValue = 2800

// pendingCtxKey is the context key StartSession stores the browser's pending identity
// under.
type pendingCtxKey struct{}

// pendingState is a pending identity as the pending cookie carries it.
type pendingState struct {
	// ID is the stepping-stone session row.
	ID        ccc.UUID                  `json:"id"`
	Identity  sessioninfo.Identity      `json:"identity"`
	Reason    sessioninfo.PendingReason `json:"reason"`
	UserID    ccc.NullUUID              `json:"userId"`
	Username  string                    `json:"username"`
	Tenant    string                    `json:"tenant"`
	ExpiresAt time.Time                 `json:"expiresAt"`
	ReturnURL string                    `json:"returnUrl"`
	// Events are the steps so far, the sign-in first.
	Events []sessioninfo.AuthEvent `json:"events"`
	// RoleNames are the role names the method asserted at sign-in, reconciled when the
	// session is finally established; nil when the method synchronizes no roles.
	RoleNames []string `json:"roleNames"`
}

// public is the PendingIdentity the API reports.
func (p *pendingState) public() *sessioninfo.PendingIdentity {
	return &sessioninfo.PendingIdentity{Identity: p.Identity, Reason: p.Reason, UserID: p.UserID, Username: p.Username, ExpiresAt: p.ExpiresAt}
}

// encodePending renders state for the pending cookie: compressed JSON, base64.
func encodePending(state *pendingState) (string, error) {
	raw, err := json.Marshal(state)
	if err != nil {
		return "", errors.Wrap(err, "json.Marshal()")
	}

	var buf bytes.Buffer
	zw := gzip.NewWriter(&buf)
	if _, err := zw.Write(raw); err != nil {
		return "", errors.Wrap(err, "gzip.Writer.Write()")
	}
	if err := zw.Close(); err != nil {
		return "", errors.Wrap(err, "gzip.Writer.Close()")
	}

	encoded := base64.RawURLEncoding.EncodeToString(buf.Bytes())
	if len(encoded) > maxPendingCookieValue {
		return "", errors.Newf("the pending identity is too large to hold in a cookie (%d encoded bytes, at most %d): its claims are too large", len(encoded), maxPendingCookieValue)
	}

	return encoded, nil
}

// decodePending reverses encodePending.
func decodePending(encoded string) (*pendingState, error) {
	compressed, err := base64.RawURLEncoding.DecodeString(encoded)
	if err != nil {
		return nil, errors.Wrap(err, "base64.DecodeString()")
	}
	zr, err := gzip.NewReader(bytes.NewReader(compressed))
	if err != nil {
		return nil, errors.Wrap(err, "gzip.NewReader()")
	}
	defer zr.Close()
	raw, err := io.ReadAll(io.LimitReader(zr, 1<<20))
	if err != nil {
		return nil, errors.Wrap(err, "io.ReadAll()")
	}

	state := &pendingState{}
	if err := json.Unmarshal(raw, state); err != nil {
		return nil, errors.Wrap(err, "json.Unmarshal()")
	}
	// An identity without claims round-trips as the JSON literal null.
	if string(state.Identity.Claims) == "null" {
		state.Identity.Claims = nil
	}

	return state, nil
}

// withPendingCookie returns the request's context carrying the browser's pending
// identity, as the pending cookie states it, when it has one. Whether it is still
// accepted is decided when it is used (pending).
func (a *Auth[S, U]) withPendingCookie(r *http.Request) context.Context {
	ctx := r.Context()

	cval, found, err := a.pendingCookies.Cookie().Read(r, a.settings.pendingCookie)
	if err != nil || !found {
		return ctx
	}
	encoded, err := cval.GetString(pendingCookieKey)
	if err != nil {
		return ctx
	}
	state, err := decodePending(encoded)
	if err != nil {
		logger.FromCtx(ctx).Warnf("pending identity cookie ignored: %v", err)

		return ctx
	}

	return context.WithValue(ctx, pendingCtxKey{}, state)
}

// pending returns the browser's pending identity from ctx (see StartSession): NotFound
// when there is none, a pending_expired refusal when it has expired or its row is no
// longer live (completed, canceled or replaced).
func (a *Auth[S, U]) pending(ctx context.Context) (*pendingState, error) {
	state, ok := ctx.Value(pendingCtxKey{}).(*pendingState)
	if !ok {
		return nil, httpio.NewNotFoundMessage("no pending sign-in")
	}
	if !time.Now().Before(state.ExpiresAt) {
		return nil, errPendingExpired()
	}

	row, err := a.storage.Session(ctx, state.ID)
	if err != nil {
		if httpio.HasNotFound(err) {
			return nil, errPendingExpired()
		}

		return nil, errors.Wrap(err, "sessionstorage.AccountStore.Session()")
	}
	if row.Expired || row.UserID.Valid {
		return nil, errPendingExpired()
	}

	return state, nil
}

func errPendingExpired() error {
	return sessioninfo.NewLoginRefusal(sessioninfo.RefusedPendingExpired, httpio.NewUnauthorizedMessage("the pending sign-in has expired"))
}

// holdPending makes a sign-in that must wait the browser's pending identity: a new
// stepping-stone row and the pending cookie bound to it, replacing any earlier pending
// identity.
func (a *Auth[S, U]) holdPending(ctx context.Context, w http.ResponseWriter, at *signInAttempt, wait *sessionstorage.PendingSignInError) (*pendingState, error) {
	now := time.Now()
	events := at.events
	if events == nil {
		events = []sessioninfo.AuthEvent{identityEvent(at.identity, now)}
	}
	state := &pendingState{
		Identity:  *at.identity,
		Reason:    wait.Reason,
		UserID:    wait.UserID,
		Username:  wait.Username,
		Tenant:    wait.Tenant,
		ExpiresAt: now.Add(a.settings.pendingTimeout),
		ReturnURL: at.returnURL,
		Events:    slices.Clone(events),
		RoleNames: at.roleNames,
	}
	if at.identity.Method == sessioninfo.MethodPassword {
		state.UserID = ccc.NullUUIDFromUUID(at.userID)
	}

	id, err := a.storage.NewSession(ctx, wait.Username, nil)
	if err != nil {
		return nil, errors.Wrap(err, "sessionstorage.AccountStore.NewSession()")
	}
	state.ID = id
	encoded, err := encodePending(state)
	if err != nil {
		a.destroyPendingRow(ctx, id)

		return nil, err
	}

	a.dropPendingRow(ctx)

	// Lax, so the cookie also reaches the login page the provider's callback redirects
	// to; the pending handlers that change anything are POSTs behind the XSRF check.
	cval := cookie.NewValues().SetString(pendingCookieKey, encoded)
	a.pendingCookies.Cookie().WritePersistentCookie(w, a.settings.pendingCookie, a.pendingCookies.Domain, true, http.SameSiteLaxMode, 2*a.settings.pendingTimeout, cval)

	return state, nil
}

// dropPending discards the browser's pending identity, if it has one: its row is
// expired and its cookie deleted.
func (a *Auth[S, U]) dropPending(ctx context.Context, w http.ResponseWriter) {
	if _, ok := ctx.Value(pendingCtxKey{}).(*pendingState); !ok {
		return
	}
	a.dropPendingRow(ctx)
	a.pendingCookies.Cookie().Delete(w, a.settings.pendingCookie, a.pendingCookies.Domain)
}

// dropPendingRow expires the row of the browser's pending identity, if it has one.
func (a *Auth[S, U]) dropPendingRow(ctx context.Context) {
	if state, ok := ctx.Value(pendingCtxKey{}).(*pendingState); ok {
		a.destroyPendingRow(ctx, state.ID)
	}
}

func (a *Auth[S, U]) destroyPendingRow(ctx context.Context, id ccc.UUID) {
	if err := a.storage.DestroySession(ctx, id); err != nil && !httpio.HasNotFound(err) {
		logger.FromCtx(ctx).Error(errors.Wrap(err, "sessionstorage.AccountStore.DestroySession()"))
	}
}

// completePending establishes the session of a pending identity with reason and the
// pending identity's events followed by more: the account is resolved afresh and must
// be the one it was pending for.
func (a *Auth[S, U]) completePending(
	ctx context.Context, w http.ResponseWriter, state *pendingState, reason sessioninfo.NewSessionReason, more ...sessioninfo.AuthEvent,
) (*signInOutcome, error) {
	identity := state.Identity
	at := &signInAttempt{
		identity:     &identity,
		reason:       reason,
		username:     state.Username,
		expectUserID: state.UserID,
		events:       append(slices.Clone(state.Events), more...),
		returnURL:    state.ReturnURL,
		roleNames:    state.RoleNames,
		sameSite:     sameSiteStrict,
	}
	if identity.Method == sessioninfo.MethodPassword {
		if !state.UserID.Valid {
			return nil, errors.New("a pending password sign-in names no account")
		}
		at.userID = state.UserID.UUID
	}

	return a.signIn(ctx, w, at)
}

// stillPending is the error a completion step returns when the sign-in waits again.
func stillPending(state *pendingState) error {
	return &sessionstorage.PendingSignInError{Reason: state.Reason, UserID: state.UserID, Username: state.Username, Tenant: state.Tenant}
}

// PendingIdentity returns the pending identity of the current request, or a NotFound
// error. An expired one is a sessioninfo.RefusedPendingExpired refusal. It reads the
// pending identity StartSession found, so the route must run behind StartSession.
func (p *AuthAPI[S, U]) PendingIdentity(ctx context.Context) (*sessioninfo.PendingIdentity, error) {
	state, err := p.auth.pending(ctx)
	if err != nil {
		return nil, err
	}

	return state.public(), nil
}

// CompletePending finishes a pending identity after the application's MFA step:
// records the step-up events, links the identity if needed, starts the session, and
// regenerates the session ID.
//
// The pending identity must wait for MFA (Conflict otherwise). The account is resolved
// afresh (a provisioning resolver provisions now) and the sign-in policy is not asked
// again; the session records the sign-in's events followed by stepUp. When the sign-in
// must wait again (the resolver now asks for a confirmation), the error is a
// *sessionstorage.PendingSignInError and the pending identity is replaced.
func (p *AuthAPI[S, U]) CompletePending(ctx context.Context, w http.ResponseWriter, stepUp ...sessioninfo.AuthEvent) (ccc.UUID, error) {
	ctx, span := tracer.Start(ctx)
	defer span.End()

	state, err := p.auth.pending(ctx)
	if err != nil {
		return ccc.NilUUID, err
	}
	if state.Reason != sessioninfo.PendingMFA {
		return ccc.NilUUID, httpio.NewConflictMessage("the pending sign-in waits for a password confirmation, not MFA")
	}
	if err := validateEvents(stepUp); err != nil {
		return ccc.NilUUID, err
	}

	outcome, err := p.auth.completePending(ctx, w, state, sessioninfo.ReasonStepUp, stepUp...)
	if err != nil {
		return ccc.NilUUID, err
	}
	if outcome.pending != nil {
		return ccc.NilUUID, stillPending(outcome.pending)
	}

	return outcome.sessionID, nil
}

// ConfirmPendingWithPassword checks the password of the pending identity's account,
// links the identity, calls the IdentityLinked hook, and starts the session.
//
// The pending identity must wait for a password confirmation (Conflict otherwise). A
// wrong password is Unauthorized and leaves the pending identity in place. The session
// records the sign-in's event and a link-confirmation event. When the sign-in policy
// requires MFA after the link, no session starts: the error is a
// *sessionstorage.PendingSignInError with reason PendingMFA, and the pending identity
// remains, now waiting for MFA (CompletePending).
func (p *AuthAPI[S, U]) ConfirmPendingWithPassword(ctx context.Context, w http.ResponseWriter, password string) (ccc.UUID, error) {
	ctx, span := tracer.Start(ctx)
	defer span.End()

	a := p.auth
	state, err := a.pending(ctx)
	if err != nil {
		return ccc.NilUUID, err
	}
	if state.Reason != sessioninfo.PendingConfirmation || !state.UserID.Valid {
		return ccc.NilUUID, httpio.NewConflictMessage("the pending sign-in does not wait for a password confirmation")
	}

	user, err := a.storage.User(ctx, state.UserID.UUID)
	if err != nil {
		return ccc.NilUUID, errors.Wrap(err, "sessionstorage.AccountStore.User()")
	}
	if _, err := comparePassword(a.hasher, user.PasswordHash, password); err != nil {
		return ccc.NilUUID, httpio.NewUnauthorizedMessageWithError(err, "Invalid Credentials")
	}
	if user.Disabled {
		return ccc.NilUUID, dbtype.Refusal("", sessioninfo.RefusedAccountDisabled, sessionstorage.ErrAccountDisabled, "Account disabled")
	}

	if err := a.linkPending(ctx, user.ID, state); err != nil {
		return ccc.NilUUID, err
	}

	outcome, err := a.completePending(ctx, w, state, sessioninfo.ReasonIdentityLinked, sessioninfo.AuthEvent{Method: sessioninfo.MethodLinkConfirmation, At: time.Now()})
	if err != nil {
		return ccc.NilUUID, err
	}
	if outcome.pending != nil {
		return ccc.NilUUID, stillPending(outcome.pending)
	}

	return outcome.sessionID, nil
}

// linkPending links a confirmed pending identity to userID and reports the link. An
// identity linked meanwhile to the same account is fine; to another account, refused.
func (a *Auth[S, U]) linkPending(ctx context.Context, userID ccc.UUID, state *pendingState) error {
	_, err := a.storage.LinkIdentity(ctx, userID, &state.Identity, state.Tenant)
	switch {
	case err == nil:
		a.notifyLinked(ctx, userID, &state.Identity)

		return nil
	case httpio.HasConflict(err):
		link, lerr := a.storage.Identity(ctx, state.Identity.Method, state.Identity.Connection, state.Identity.Subject)
		if lerr == nil && link.UserID == userID {
			return nil
		}

		return dbtype.Refusal("", sessioninfo.RefusedIdentityRejected, sessionstorage.ErrIdentityRejected, "the identity is linked to another account")
	default:
		return errors.Wrap(err, "sessionstorage.AccountStore.LinkIdentity()")
	}
}

// pendingStatus is Pending().Status().
func (a *Auth[S, U]) pendingStatus() http.HandlerFunc {
	type response struct {
		Reason    sessioninfo.PendingReason `json:"reason"`
		Email     string                    `json:"email"`
		ExpiresAt time.Time                 `json:"expiresAt"`
		ReturnURL string                    `json:"returnUrl"`
	}

	return a.baseSession.Handle(func(w http.ResponseWriter, r *http.Request) error {
		ctx, span := tracer.Start(r.Context())
		defer span.End()

		state, err := a.pending(ctx)
		if err != nil {
			return writeSignInError(ctx, w, err)
		}

		return httpio.NewEncoder(w).Ok(response{Reason: state.Reason, Email: state.Identity.Email, ExpiresAt: state.ExpiresAt, ReturnURL: returnURLOrRoot(state.ReturnURL)})
	})
}

// pendingConfirm is Pending().ConfirmWithPassword().
func (a *Auth[S, U]) pendingConfirm() http.HandlerFunc {
	type request struct {
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

		_, err = a.API().ConfirmPendingWithPassword(ctx, w, req.Password)
		var wait *sessionstorage.PendingSignInError
		switch {
		case errors.As(err, &wait):
			return httpio.NewEncoder(w).Ok(mfaResponse{MFAIsRequired: true})
		case err != nil:
			return writeSignInError(ctx, w, err)
		}

		return httpio.NewEncoder(w).Ok(mfaResponse{})
	})
}

// pendingCancel is Pending().Cancel().
func (a *Auth[S, U]) pendingCancel() http.HandlerFunc {
	return a.baseSession.Handle(func(w http.ResponseWriter, r *http.Request) error {
		ctx, span := tracer.Start(r.Context())
		defer span.End()

		a.dropPending(ctx, w)

		return httpio.NewEncoder(w).Ok(nil)
	})
}

func returnURLOrRoot(returnURL string) string {
	if returnURL == "" {
		return "/"
	}

	return returnURL
}
