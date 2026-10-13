package session

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"net/http"
	"slices"
	"time"

	"github.com/cccteam/ccc"
	"github.com/cccteam/ccc/tracer"
	"github.com/cccteam/httpio"
	"github.com/cccteam/logger"
	"github.com/cccteam/session/cookie"
	internalcookie "github.com/cccteam/session/internal/cookie"
	"github.com/cccteam/session/internal/sessioncore"
	"github.com/cccteam/session/internal/signinflow"
	"github.com/cccteam/session/sessioninfo"
	"github.com/cccteam/session/sessionstorage"
	"github.com/cccteam/session/signin"
	"github.com/go-playground/errors/v5"
)

// A pending identity is a verified identity that waits for a password confirmation or
// the application's MFA step. It is held as a row of the pending sign-ins table, with
// everything the sign-in carried, and an encrypted pending cookie holding an opaque
// token; the row keeps the token's hash. It is accepted only while the cookie decrypts
// and its row is live: not expired and not consumed. A completion consumes the row by a
// conditional update before it signs in, so the token is single-use. See "What a
// pending identity is" in the README.

// pendingCookieKey is the pending cookie's value holding the token.
const pendingCookieKey cookie.Key = "pending"

// pendingTokenSize is the token's size in bytes.
const pendingTokenSize = 32

// pendingCtxKey is the context key for the hash of the browser's pending token, set by
// StartSession.
type pendingCtxKey struct{}

// pendingState is a pending identity as the pending sign-ins table holds it.
type pendingState = sessionstorage.PendingSignIn

// pendingIdentityOf is the PendingIdentity the API reports for p.
func pendingIdentityOf(p *pendingState) *sessioninfo.PendingIdentity {
	return &sessioninfo.PendingIdentity{
		Identity: p.Identity, Reason: p.Step, UserID: p.UserID, Username: p.Username, ExpiresAt: p.ExpiresAt, ReturnURL: p.ReturnURL, Factors: p.Factors,
	}
}

// newPendingToken returns a fresh token as the cookie carries it, and its hash as the
// row keeps it.
func newPendingToken() (token string, hash []byte, err error) {
	raw := make([]byte, pendingTokenSize)
	if _, err := rand.Read(raw); err != nil {
		return "", nil, errors.Wrap(err, "rand.Read()")
	}

	return base64.RawURLEncoding.EncodeToString(raw), hashPendingToken(raw), nil
}

func hashPendingToken(raw []byte) []byte {
	sum := sha256.Sum256(raw)

	return sum[:]
}

// withPendingCookie returns the request's context with the hash of the pending token
// from the pending cookie, if there is one. pending decides whether the pending identity
// is still accepted.
func (a *Auth[S, U, Tx]) withPendingCookie(r *http.Request) context.Context {
	ctx := r.Context()

	cval, found, err := a.pendingCookies.Cookie().Read(r, a.settings.pendingCookie)
	if err != nil || !found {
		return ctx
	}
	token, err := cval.GetString(pendingCookieKey)
	if err != nil {
		return ctx
	}
	raw, err := base64.RawURLEncoding.DecodeString(token)
	if err != nil || len(raw) != pendingTokenSize {
		logger.FromCtx(ctx).Warn("pending identity cookie ignored: not a pending token")

		return ctx
	}

	return context.WithValue(ctx, pendingCtxKey{}, hashPendingToken(raw))
}

// pendingTokenHash returns the hash of the browser's pending token from ctx.
func pendingTokenHash(ctx context.Context) ([]byte, bool) {
	hash, ok := ctx.Value(pendingCtxKey{}).([]byte)

	return hash, ok
}

// pending returns the browser's pending identity from ctx. It returns NotFound when
// there is none, and a pending_expired refusal when its row is no longer live (expired,
// completed, canceled or replaced).
func (a *Auth[S, U, Tx]) pending(ctx context.Context) (*pendingState, error) {
	hash, ok := pendingTokenHash(ctx)
	if !ok {
		return nil, httpio.NewNotFoundMessage("no pending sign-in")
	}

	p, err := a.storage.PendingSignIn(ctx, hash)
	if err != nil {
		if httpio.HasNotFound(err) {
			return nil, errPendingExpired()
		}

		return nil, errors.Wrap(err, "sessionstorage.AuthStore.PendingSignIn()")
	}
	if p.ConsumedAt != nil || !time.Now().Before(p.ExpiresAt) {
		return nil, errPendingExpired()
	}

	return p, nil
}

func errPendingExpired() error {
	return sessioninfo.NewLoginRefusal(sessioninfo.RefusedPendingExpired, httpio.NewUnauthorizedMessage("the pending sign-in has expired"))
}

// holdPending stores a sign-in that must wait as the browser's pending identity. It
// inserts the row, consumes any earlier pending identity the browser had (unless the
// sign-in completed it, which consumed it already), and writes the pending cookie with
// the new token.
func (a *Auth[S, U, Tx]) holdPending(ctx context.Context, w http.ResponseWriter, at *signInAttempt, wait *signin.PendingSignInError) (*pendingState, error) {
	now := time.Now()
	events := at.events
	if events == nil {
		events = []sessioninfo.AuthEvent{identityEvent(at.identity, now)}
	}
	token, hash, err := newPendingToken()
	if err != nil {
		return nil, err
	}
	p := &pendingState{
		TokenHash:    hash,
		Step:         wait.Reason,
		Registration: at.registration,
		Identity:     *at.identity,
		UserID:       wait.UserID,
		Username:     wait.Username,
		Tenant:       wait.Tenant,
		Events:       slices.Clone(events),
		RoleNames:    at.roleNames,
		Factors:      wait.Factors,
		ReturnURL:    pendingReturnURL(at.returnURL),
		CreatedAt:    now,
		ExpiresAt:    now.Add(a.settings.pendingTimeout),
	}
	if at.identity.Method == sessioninfo.MethodPassword {
		p.UserID = ccc.NullUUIDFromUUID(at.userID)
	}

	id, err := a.storage.HoldSignIn(ctx, p)
	if err != nil {
		return nil, errors.Wrap(err, "sessionstorage.AuthStore.HoldSignIn()")
	}
	p.ID = id

	if !at.fromPending {
		a.consumePendingOf(ctx)
	}

	// Lax, so the cookie also reaches the login page the provider's callback redirects
	// to. The pending handlers that change anything are POSTs behind the XSRF check.
	cval := cookie.NewValues().SetString(pendingCookieKey, token)
	a.pendingCookies.Cookie().WritePersistentCookie(w, a.settings.pendingCookie, a.pendingCookies.Domain, true, http.SameSiteLaxMode, 2*a.settings.pendingTimeout, cval)

	return p, nil
}

// onPending runs the PendingHook, if one is configured, for a pending identity a handler
// just stored. handled reports that the hook wrote the response itself, so the handler
// writes nothing more. redirectURL is where the hook sends the browser, or "" for the
// handler's default. An error discards the pending identity.
func (a *Auth[S, U, Tx]) onPending(ctx context.Context, w http.ResponseWriter, r *http.Request, p *pendingState) (redirectURL string, handled bool, err error) {
	if a.settings.pendingHook == nil {
		return "", false, nil
	}

	tracked := &responseTracker{ResponseWriter: w}
	redirectURL, err = a.settings.pendingHook(ctx, tracked, r, pendingIdentityOf(p))
	if err != nil {
		a.consumePendingRow(ctx, p.TokenHash)
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

// dropPending discards the browser's pending identity, if it has one. It consumes the
// row and deletes the cookie.
func (a *Auth[S, U, Tx]) dropPending(ctx context.Context, w http.ResponseWriter) {
	if _, ok := pendingTokenHash(ctx); !ok {
		return
	}
	a.consumePendingOf(ctx)
	a.pendingCookies.Cookie().Delete(w, a.settings.pendingCookie, a.pendingCookies.Domain)
}

// endPending ends the browser's pending identity, if it has one, once the sign-in at
// succeeded: the row is consumed, unless at completed it and consumed it first, and the
// cookie is deleted.
func (a *Auth[S, U, Tx]) endPending(ctx context.Context, w http.ResponseWriter, at *signInAttempt) {
	if _, ok := pendingTokenHash(ctx); !ok {
		return
	}
	if !at.fromPending {
		a.consumePendingOf(ctx)
	}
	a.pendingCookies.Cookie().Delete(w, a.settings.pendingCookie, a.pendingCookies.Domain)
}

// consumePendingOf consumes the row of the browser's pending identity, if it has one
// that is still live.
func (a *Auth[S, U, Tx]) consumePendingOf(ctx context.Context) {
	if hash, ok := pendingTokenHash(ctx); ok {
		a.consumePendingRow(ctx, hash)
	}
}

// consumePendingRow consumes the pending identity holding tokenHash. A row that is no
// longer live is nothing to consume.
func (a *Auth[S, U, Tx]) consumePendingRow(ctx context.Context, tokenHash []byte) {
	if err := a.storage.ConsumePendingSignIn(ctx, tokenHash); err != nil && !httpio.HasNotFound(err) {
		logger.FromCtx(ctx).Error(errors.Wrap(err, "sessionstorage.AuthStore.ConsumePendingSignIn()"))
	}
}

// consumePending consumes p before its completion signs in, so a token completes once:
// of two completions racing, the conditional update lets one through. A row that is no
// longer live has expired.
func (a *Auth[S, U, Tx]) consumePending(ctx context.Context, p *pendingState) error {
	if err := a.storage.ConsumePendingSignIn(ctx, p.TokenHash); err != nil {
		if httpio.HasNotFound(err) {
			return errPendingExpired()
		}

		return errors.Wrap(err, "sessionstorage.AuthStore.ConsumePendingSignIn()")
	}

	return nil
}

// completePending establishes the session of a consumed pending identity. The session
// records the pending identity's events followed by more. The user is resolved again
// and must be the one the identity waited on.
func (a *Auth[S, U, Tx]) completePending(
	ctx context.Context, w http.ResponseWriter, p *pendingState, reason sessioninfo.NewSessionReason, more ...sessioninfo.AuthEvent,
) (*signInOutcome, error) {
	identity := p.Identity
	at := &signInAttempt{
		identity:     &identity,
		reason:       reason,
		registration: p.Registration,
		username:     p.Username,
		expectUserID: p.UserID,
		events:       append(slices.Clone(p.Events), more...),
		returnURL:    p.ReturnURL,
		roleNames:    p.RoleNames,
		sameSite:     sessioncore.SameSiteStrict,
		fromPending:  true,
	}
	if identity.Method == sessioninfo.MethodPassword {
		if !p.UserID.Valid {
			return nil, errors.New("a pending password sign-in names no user")
		}
		at.userID = p.UserID.UUID
	}

	return a.signIn(ctx, w, at)
}

// acceptedFactors refuses a step-up event whose method is not one the sign-in policy
// accepts for the MFA step. A policy that named no factors accepts any.
func acceptedFactors(factors []sessioninfo.AuthMethod, stepUp []sessioninfo.AuthEvent) error {
	if len(factors) == 0 {
		return nil
	}
	for _, e := range stepUp {
		if !slices.Contains(factors, e.Method) {
			return httpio.NewBadRequestMessagef("the sign-in policy accepts %v for the MFA step, not %q", factors, e.Method)
		}
	}

	return nil
}

// stillPending is the error a completion step returns when the sign-in waits again.
func stillPending(p *pendingState) error {
	return &signin.PendingSignInError{Reason: p.Step, UserID: p.UserID, Username: p.Username, Tenant: p.Tenant, Factors: p.Factors}
}

// PendingIdentity returns the pending identity of the current request, or a NotFound
// error. An expired one is a sessioninfo.RefusedPendingExpired refusal. It reads the
// pending identity StartSession found, so the route must run behind StartSession.
func (p *AuthAPI[S, U, Tx]) PendingIdentity(ctx context.Context) (*sessioninfo.PendingIdentity, error) {
	pending, err := p.auth.pending(ctx)
	if err != nil {
		return nil, err
	}

	return pendingIdentityOf(pending), nil
}

// CompletePending finishes a pending identity after the application's MFA step. It
// records the step-up events, links the identity if needed, starts the session, and
// regenerates the session ID.
//
// The pending identity must wait for MFA (Conflict otherwise). It is consumed first, so
// it completes once: a second completion finds it expired. The user is resolved again
// and must be the one the identity waited on. The sign-in policy is not asked again.
// The session records the sign-in's events followed by stepUp. If the sign-in must wait
// again (the resolver now asks for a confirmation), the error is a
// *signin.PendingSignInError and the pending identity is replaced.
func (p *AuthAPI[S, U, Tx]) CompletePending(ctx context.Context, w http.ResponseWriter, stepUp ...sessioninfo.AuthEvent) (ccc.UUID, error) {
	ctx, span := tracer.Start(ctx)
	defer span.End()

	pending, err := p.auth.pending(ctx)
	if err != nil {
		return ccc.NilUUID, err
	}
	if pending.Step != sessioninfo.PendingMFA {
		return ccc.NilUUID, httpio.NewConflictMessage("the pending sign-in waits for a password confirmation, not MFA")
	}
	if err := validateEvents(stepUp); err != nil {
		return ccc.NilUUID, err
	}
	if err := acceptedFactors(pending.Factors, stepUp); err != nil {
		return ccc.NilUUID, err
	}
	if err := p.auth.consumePending(ctx, pending); err != nil {
		return ccc.NilUUID, err
	}

	outcome, err := p.auth.completePending(ctx, w, pending, sessioninfo.ReasonStepUp, stepUp...)
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
// wrong password is Unauthorized and leaves the pending identity in place; the right
// one consumes it. The session records the sign-in's event and a link-confirmation
// event. If the sign-in policy requires MFA after the link, no session starts. The
// error is then a *signin.PendingSignInError with reason PendingMFA, and a new pending
// identity waits for MFA (see CompletePending).
func (p *AuthAPI[S, U, Tx]) ConfirmPendingWithPassword(ctx context.Context, w http.ResponseWriter, password string) (ccc.UUID, error) {
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
func (a *Auth[S, U, Tx]) confirmPending(ctx context.Context, w http.ResponseWriter, password string) (*signInOutcome, error) {
	p, err := a.pending(ctx)
	if err != nil {
		return nil, err
	}
	if p.Step != sessioninfo.PendingConfirmation || !p.UserID.Valid {
		return nil, httpio.NewConflictMessage("the pending sign-in does not wait for a password confirmation")
	}

	user, err := a.storage.User(ctx, p.UserID.UUID)
	if err != nil {
		return nil, errors.Wrap(err, "sessionstorage.AuthStore.User()")
	}
	if _, err := sessioncore.ComparePassword(a.registered().hasher, user.PasswordHash, password); err != nil {
		return nil, httpio.NewUnauthorizedMessageWithError(err, "Invalid Credentials")
	}
	if user.Disabled {
		return nil, signinflow.Refusal("", sessioninfo.RefusedUserDisabled, signin.ErrUserDisabled, "User disabled")
	}
	if err := a.consumePending(ctx, p); err != nil {
		return nil, err
	}

	if err := a.linkPending(ctx, user.ID, p); err != nil {
		return nil, err
	}

	return a.completePending(ctx, w, p, sessioninfo.ReasonIdentityLinked, sessioninfo.AuthEvent{Method: sessioninfo.MethodLinkConfirmation, At: time.Now()})
}

// linkPending links a confirmed pending identity to userID and reports the link. If the
// identity was linked meanwhile, that is accepted for the same user and refused for
// another.
func (a *Auth[S, U, Tx]) linkPending(ctx context.Context, userID ccc.UUID, p *pendingState) error {
	_, err := a.storage.LinkIdentity(ctx, userID, &p.Identity, p.Tenant)
	switch {
	case err == nil:
		a.notifyLinked(ctx, userID, &p.Identity)

		return nil
	case httpio.HasConflict(err):
		link, lerr := a.storage.Identity(ctx, p.Identity.Method, p.Identity.Connection, p.Identity.Subject)
		if lerr == nil && link.UserID == userID {
			return nil
		}

		return signinflow.Refusal("", sessioninfo.RefusedIdentityRejected, signin.ErrIdentityRejected, "the identity is linked to another user")
	default:
		return errors.Wrap(err, "sessionstorage.AuthStore.LinkIdentity()")
	}
}

// pendingStatus is Pending().Status().
func (a *Auth[S, U, Tx]) pendingStatus() http.HandlerFunc {
	type response struct {
		Reason    sessioninfo.PendingReason `json:"reason"`
		Email     string                    `json:"email"`
		ExpiresAt time.Time                 `json:"expiresAt"`
		ReturnURL string                    `json:"returnUrl"`
		// Factors are the methods the sign-in policy accepts for the MFA step.
		Factors []sessioninfo.AuthMethod `json:"factors,omitempty"`
	}

	return a.baseSession.Handle(func(w http.ResponseWriter, r *http.Request) error {
		ctx, span := tracer.Start(r.Context())
		defer span.End()

		p, err := a.pending(ctx)
		if err != nil {
			return writeSignInError(ctx, w, err)
		}

		return httpio.NewEncoder(w).Ok(response{
			Reason: p.Step, Email: p.Identity.Email, ExpiresAt: p.ExpiresAt, ReturnURL: internalcookie.SanitizeReturnURL(p.ReturnURL), Factors: p.Factors,
		})
	})
}

// pendingConfirm is Pending().ConfirmWithPassword().
func (a *Auth[S, U, Tx]) pendingConfirm() http.HandlerFunc {
	type request struct {
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

		outcome, err := a.confirmPending(ctx, w, req.Password)
		if err != nil {
			return writeSignInError(ctx, w, err)
		}

		return a.answerSignIn(ctx, w, r, outcome)
	})
}

// pendingCancel is Pending().Cancel().
func (a *Auth[S, U, Tx]) pendingCancel() http.HandlerFunc {
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
