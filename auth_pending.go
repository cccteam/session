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
	internalcookie "github.com/cccteam/session/internal/cookie"
	"github.com/cccteam/session/internal/dbtype"
	"github.com/cccteam/session/sessioninfo"
	"github.com/cccteam/session/sessionstorage"
	"github.com/go-playground/errors/v5"
)

// A pending identity is a verified identity that waits for a password confirmation or
// the application's MFA step. It is held as a stepping-stone row in the session table
// and an encrypted pending cookie bound to that row's ID. It is accepted only while the
// cookie decrypts, has not expired, and its row is live and has no user. Expiring
// the row makes it single-use. See "What a pending identity is" in the README.

// pendingCookieKey is the pending cookie's value holding the encoded pendingState.
const pendingCookieKey cookie.Key = "pending"

// maxPendingCookieValue bounds the encoded pending identity, so the cookie stays within
// what browsers keep (4096 bytes per cookie, encryption overhead included).
const maxPendingCookieValue = 2800

// pendingCtxKey is the context key for the browser's pending identity, set by
// StartSession.
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
	return &sessioninfo.PendingIdentity{Identity: p.Identity, Reason: p.Reason, UserID: p.UserID, Username: p.Username, ExpiresAt: p.ExpiresAt, ReturnURL: p.ReturnURL}
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

// withPendingCookie returns the request's context with the pending identity from the
// pending cookie, if there is one. pending decides whether it is still accepted.
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

// pending returns the browser's pending identity from ctx. It returns NotFound when
// there is none, and a pending_expired refusal when it has expired or its row is no
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

		return nil, errors.Wrap(err, "sessionstorage.AuthStore.Session()")
	}
	if row.Expired || row.UserID.Valid {
		return nil, errPendingExpired()
	}

	return state, nil
}

func errPendingExpired() error {
	return sessioninfo.NewLoginRefusal(sessioninfo.RefusedPendingExpired, httpio.NewUnauthorizedMessage("the pending sign-in has expired"))
}

// holdPending stores a sign-in that must wait as the browser's pending identity. It
// inserts a new stepping-stone row and writes the pending cookie bound to it, replacing
// any earlier pending identity.
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
		ReturnURL: pendingReturnURL(at.returnURL),
		Events:    slices.Clone(events),
		RoleNames: at.roleNames,
	}
	if at.identity.Method == sessioninfo.MethodPassword {
		state.UserID = ccc.NullUUIDFromUUID(at.userID)
	}

	// The row's reason keeps the custom session data resolver off it: it has no user.
	id, err := a.storage.CreateSession(ctx, &sessioninfo.NewSessionRequest{Reason: sessioninfo.ReasonPendingIdentity, Username: wait.Username})
	if err != nil {
		return nil, errors.Wrap(err, "sessionstorage.AuthStore.CreateSession()")
	}
	state.ID = id
	encoded, err := encodePending(state)
	if err != nil {
		a.destroyPendingRow(ctx, id)

		return nil, err
	}

	a.dropPendingRow(ctx)

	// Lax, so the cookie also reaches the login page the provider's callback redirects
	// to. The pending handlers that change anything are POSTs behind the XSRF check.
	cval := cookie.NewValues().SetString(pendingCookieKey, encoded)
	a.pendingCookies.Cookie().WritePersistentCookie(w, a.settings.pendingCookie, a.pendingCookies.Domain, true, http.SameSiteLaxMode, 2*a.settings.pendingTimeout, cval)

	return state, nil
}

// onPending runs the PendingHook, if one is configured, for a pending identity a handler
// just stored. handled reports that the hook wrote the response itself, so the handler
// writes nothing more. redirectURL is where the hook sends the browser, or "" for the
// handler's default. An error discards the pending identity.
func (a *Auth[S, U]) onPending(ctx context.Context, w http.ResponseWriter, r *http.Request, state *pendingState) (redirectURL string, handled bool, err error) {
	if a.settings.pendingHook == nil {
		return "", false, nil
	}

	tracked := &responseTracker{ResponseWriter: w}
	redirectURL, err = a.settings.pendingHook(ctx, tracked, r, state.public())
	if err != nil {
		a.destroyPendingRow(ctx, state.ID)
		if !tracked.written {
			a.pendingCookies.Cookie().Delete(w, a.settings.pendingCookie, a.pendingCookies.Domain)
		}

		return "", tracked.written, errors.Wrap(err, "PendingHook()")
	}

	return redirectURL, tracked.written, nil
}

// responseTracker records whether a hook wrote the response.
type responseTracker struct {
	http.ResponseWriter
	written bool
}

func (t *responseTracker) WriteHeader(statusCode int) {
	t.written = true
	t.ResponseWriter.WriteHeader(statusCode)
}

func (t *responseTracker) Write(b []byte) (int, error) {
	t.written = true

	n, err := t.ResponseWriter.Write(b)
	if err != nil {
		return n, errors.Wrap(err, "http.ResponseWriter.Write()")
	}

	return n, nil
}

// Unwrap gives http.ResponseController the underlying writer.
func (t *responseTracker) Unwrap() http.ResponseWriter {
	return t.ResponseWriter
}

// dropPending discards the browser's pending identity, if it has one. It expires the
// row and deletes the cookie.
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
		logger.FromCtx(ctx).Error(errors.Wrap(err, "sessionstorage.AuthStore.DestroySession()"))
	}
}

// completePending establishes the session of a pending identity. The session records
// the pending identity's events followed by more. The user is resolved again and
// must be the one the identity waited on.
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
			return nil, errors.New("a pending password sign-in names no user")
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

// CompletePending finishes a pending identity after the application's MFA step. It
// records the step-up events, links the identity if needed, starts the session, and
// regenerates the session ID.
//
// The pending identity must wait for MFA (Conflict otherwise). The user is resolved
// again and must be the one the identity waited on. The sign-in policy is not asked
// again. The session records the sign-in's events followed by stepUp. If the sign-in
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

// ConfirmPendingWithPassword checks the password of the pending identity's user,
// links the identity, calls the IdentityLinked hook, and starts the session.
//
// The pending identity must wait for a password confirmation (Conflict otherwise). A
// wrong password is Unauthorized and leaves the pending identity in place. The session
// records the sign-in's event and a link-confirmation event. If the sign-in policy
// requires MFA after the link, no session starts. The error is then a
// *sessionstorage.PendingSignInError with reason PendingMFA, and the pending identity
// remains, now waiting for MFA (see CompletePending).
func (p *AuthAPI[S, U]) ConfirmPendingWithPassword(ctx context.Context, w http.ResponseWriter, password string) (ccc.UUID, error) {
	ctx, span := tracer.Start(ctx)
	defer span.End()

	outcome, err := p.auth.confirmPending(ctx, w, password)
	if err != nil {
		return ccc.NilUUID, err
	}
	if outcome.pending != nil {
		return ccc.NilUUID, stillPending(outcome.pending)
	}

	return outcome.sessionID, nil
}

// confirmPending implements ConfirmPendingWithPassword and returns the sign-in's outcome.
func (a *Auth[S, U]) confirmPending(ctx context.Context, w http.ResponseWriter, password string) (*signInOutcome, error) {
	state, err := a.pending(ctx)
	if err != nil {
		return nil, err
	}
	if state.Reason != sessioninfo.PendingConfirmation || !state.UserID.Valid {
		return nil, httpio.NewConflictMessage("the pending sign-in does not wait for a password confirmation")
	}

	user, err := a.storage.User(ctx, state.UserID.UUID)
	if err != nil {
		return nil, errors.Wrap(err, "sessionstorage.AuthStore.User()")
	}
	if _, err := comparePassword(a.registered().hasher, user.PasswordHash, password); err != nil {
		return nil, httpio.NewUnauthorizedMessageWithError(err, "Invalid Credentials")
	}
	if user.Disabled {
		return nil, dbtype.Refusal("", sessioninfo.RefusedUserDisabled, sessionstorage.ErrUserDisabled, "User disabled")
	}

	if err := a.linkPending(ctx, user.ID, state); err != nil {
		return nil, err
	}

	return a.completePending(ctx, w, state, sessioninfo.ReasonIdentityLinked, sessioninfo.AuthEvent{Method: sessioninfo.MethodLinkConfirmation, At: time.Now()})
}

// linkPending links a confirmed pending identity to userID and reports the link. If the
// identity was linked meanwhile, that is accepted for the same user and refused for
// another.
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

		return dbtype.Refusal("", sessioninfo.RefusedIdentityRejected, sessionstorage.ErrIdentityRejected, "the identity is linked to another user")
	default:
		return errors.Wrap(err, "sessionstorage.AuthStore.LinkIdentity()")
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

		return httpio.NewEncoder(w).Ok(response{Reason: state.Reason, Email: state.Identity.Email, ExpiresAt: state.ExpiresAt, ReturnURL: internalcookie.SanitizeReturnURL(state.ReturnURL)})
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

		outcome, err := a.confirmPending(ctx, w, req.Password)
		if err != nil {
			return writeSignInError(ctx, w, err)
		}

		return a.answerSignIn(ctx, w, r, outcome)
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

// pendingReturnURL returns the return URL a pending identity keeps. It is empty when the
// sign-in had none (a password sign-in), and the sanitized path otherwise. The
// PendingHook, the pending redirect and Pending().Status() all read it, so it never
// holds an unsanitized value.
func pendingReturnURL(returnURL string) string {
	if returnURL == "" {
		return ""
	}

	return internalcookie.SanitizeReturnURL(returnURL)
}
