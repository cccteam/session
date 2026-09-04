// Package basesession implements the session management for the application.
package basesession

import (
	"context"
	"net/http"
	"strconv"
	"time"

	"github.com/cccteam/ccc"
	"github.com/cccteam/ccc/accesstypes"
	"github.com/cccteam/ccc/tracer"
	"github.com/cccteam/httpio"
	"github.com/cccteam/logger"
	internalcookie "github.com/cccteam/session/internal/cookie"
	"github.com/cccteam/session/sessioninfo"
	"github.com/cccteam/session/sessionstorage"
	"github.com/go-playground/errors/v5"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/trace"
)

// attrEndUserID is the OpenTelemetry semantic-convention attribute for the
// authenticated end user of a request.
const attrEndUserID = "enduser.id"

// LogHandler defines the handler signature required for handling logs.
type LogHandler func(handler func(w http.ResponseWriter, r *http.Request) error) http.HandlerFunc

// BaseSession implements the shared features for all session implementations
type BaseSession struct {
	SessionTimeout time.Duration
	// ImpersonationTimeout is the hard cap on an impersonated session's lifetime,
	// fixed when the session is established; zero selects the library default.
	ImpersonationTimeout time.Duration
	// ImpersonationAudit, when set, receives every lifecycle event of an impersonated
	// session (see sessioninfo.ImpersonationEvent).
	ImpersonationAudit func(ctx context.Context, event sessioninfo.ImpersonationEvent) error
	// PrincipalResolver, when set, chooses the request's authorization subject at
	// validation (see session.WithPrincipalResolver). It runs with the validated
	// session in ctx for ordinary sessions and user-principal impersonations; a
	// role-principal impersonation already names its subject and skips it.
	PrincipalResolver func(ctx context.Context) (accesstypes.Principal, error)
	Handle            LogHandler
	Storage           sessionstorage.BaseStore
	CookieHandler     internalcookie.Handler
}

// StartSession initializes a session by restoring it from a cookie, or if
// that fails, initializing a new session. The session cookie is then updated and
// the sessionID is inserted into the context.
func (s *BaseSession) StartSession(next http.Handler) http.Handler {
	return s.Handle(func(w http.ResponseWriter, r *http.Request) error {
		ctx, span := tracer.Start(r.Context())
		defer span.End()

		ctx, err := s.StartSessionAPI(ctx, w, r)
		if err != nil {
			return httpio.NewEncoder(w).ClientMessage(ctx, err)
		}

		next.ServeHTTP(w, r.WithContext(ctx))

		return nil
	})
}

// StartSessionAPI exposes the internals of the StartSession Handler for use with the API interface
func (s *BaseSession) StartSessionAPI(ctx context.Context, w http.ResponseWriter, r *http.Request) (context.Context, error) {
	// Read Auth Cookie
	cval, foundAuthCookie, err := s.CookieHandler.ReadAuthCookie(r)
	if err != nil {
		return ctx, errors.Wrap(err, "cookie.CookieHandler.ReadAuthCookie()")
	}

	var sessionID ccc.UUID
	var validSessionID bool
	if foundAuthCookie {
		cSessionID, err := cval.GetString(internalcookie.SessionID)
		if err == nil {
			sessionID, validSessionID = internalcookie.ValidSessionID(cSessionID)
		}
	}

	if !foundAuthCookie || !validSessionID {
		var err error
		sessionID, err = ccc.NewUUID()
		if err != nil {
			return ctx, errors.Wrap(err, "ccc.NewUUID()")
		}
		cval = s.CookieHandler.NewAuthCookie(w, true, sessionID)
	}

	if sameSiteStrict, _ := cval.GetString(internalcookie.SameSiteStrict); sameSiteStrict != strconv.FormatBool(true) {
		// Upgrade cookie to SameSite=Strict
		// CallbackOIDC() sets it to None to allow OAuth flow to work
		s.CookieHandler.WriteAuthCookie(w, true, cval)
	}

	// Store sessionID in context
	ctx = context.WithValue(ctx, sessioninfo.CTXSessionID, sessionID)

	// Add session ID to logging context
	l := logger.FromCtx(ctx).AddRequestAttribute("session ID", sessionID).
		WithAttributes().AddAttribute("session ID", sessionID).Logger()

	ctx = logger.NewCtx(ctx, l)

	return ctx, nil
}

// ValidateSession checks the sessionID in the database to validate that it has not expired
// and updates the last activity timestamp if it is still valid.
// StartSession handler must be called before calling ValidateSession
//
// The request's evidence — enduser.id, and the impersonation.* and principal.*
// attributes when they apply — is stamped on the span current in r.Context(): the
// server span, which is what trace-list filters match on.
func (s *BaseSession) ValidateSession(next http.Handler) http.Handler {
	return s.Handle(func(w http.ResponseWriter, r *http.Request) error {
		evidence := trace.SpanFromContext(r.Context())

		ctx, span := tracer.Start(r.Context())
		defer span.End()

		ctx, err := s.validateSession(ctx, evidence)
		if err != nil {
			return httpio.NewEncoder(w).ClientMessage(ctx, err)
		}

		next.ServeHTTP(w, r.WithContext(ctx))

		return nil
	})
}

// ValidateSessionAPI checks the session cookie and if it is valid, stores the session
// data into the context. The request's evidence (see ValidateSession) is stamped on the
// span current in ctx — the caller's span.
func (s *BaseSession) ValidateSessionAPI(ctx context.Context) (context.Context, error) {
	return s.validateSession(ctx, trace.SpanFromContext(ctx))
}

// validateSession validates the session in ctx and stamps the request's evidence on
// the evidence span.
func (s *BaseSession) validateSession(ctx context.Context, evidence trace.Span) (context.Context, error) {
	ctx, span := tracer.Start(ctx)
	defer span.End()

	// Validate that the sessionID is in database
	sessInfo, err := s.Storage.Session(ctx, sessioninfo.IDFromCtx(ctx))
	if err != nil {
		return ctx, httpio.NewUnauthorizedMessageWithError(err, "invalid session")
	}

	// An impersonated session's evidence goes on the span before any refusal, so a
	// trace of a refused request still names the actor and principal.
	if imp := sessInfo.Impersonation; imp != nil {
		evidence.SetAttributes(impersonationSpanAttributes(imp)...)
	}

	// Check for expiration: the idle timeout, and an impersonated session's hard cap.
	if sessInfo.Expired || time.Since(sessInfo.UpdatedAt) > s.SessionTimeout || impersonationExpired(sessInfo) {
		s.endImpersonation(ctx, sessInfo, sessioninfo.ImpersonationEndedByExpiry)

		return ctx, httpio.NewUnauthorizedMessage("session expired")
	}

	// Update last activity (rate limit updates)
	if time.Since(sessInfo.UpdatedAt) > time.Second*5 {
		if err := s.Storage.UpdateSessionActivity(ctx, sessInfo.ID); err != nil {
			return ctx, errors.Wrap(err, "sessionstorage.BaseStore.UpdateSessionActivity()")
		}
	}

	// Store session info in context
	ctx = context.WithValue(ctx, sessioninfo.CtxSessionInfo, sessInfo)

	if err := s.resolvePrincipal(ctx, sessInfo); err != nil {
		return ctx, err
	}

	// enduser.id is the OpenTelemetry convention for the authenticated end user: the
	// session's effective identity, on every validated request.
	evidence.SetAttributes(attribute.String(attrEndUserID, sessInfo.Username))

	// Add user to logging context — and, for an impersonated session, the evidence
	// attributes on the request entry and every line logged within it; likewise the
	// principal when a resolver changed it.
	l := logger.FromCtx(ctx).AddRequestAttribute("username", sessInfo.Username)
	attrs := l.WithAttributes().AddAttribute("username", sessInfo.Username)
	if imp := sessInfo.Impersonation; imp != nil {
		for _, a := range imp.Attributes() {
			l = l.AddRequestAttribute(a.Key, a.Value)
			attrs = attrs.AddAttribute(a.Key, a.Value)
		}
	}
	if p := sessInfo.Principal; p != (accesstypes.Principal{}) {
		kind, name := principalKindName(p)
		l.AddRequestAttribute(sessioninfo.AttrPrincipalKind, kind).AddRequestAttribute(sessioninfo.AttrPrincipal, name)
		attrs = attrs.AddAttribute(sessioninfo.AttrPrincipalKind, kind).AddAttribute(sessioninfo.AttrPrincipal, name)
		evidence.SetAttributes(attribute.String(sessioninfo.AttrPrincipalKind, kind), attribute.String(sessioninfo.AttrPrincipal, name))
	}

	return logger.NewCtx(ctx, attrs.Logger()), nil
}

// resolvePrincipal runs the configured PrincipalResolver for the validated session in
// ctx and records its choice on sessData.Principal when it differs from the default
// subject. A role-principal impersonation is skipped: the record already names the
// subject. A resolver error is a server error, never an unauthorized one — the session
// is valid; the application could not decide what it acts as.
func (s *BaseSession) resolvePrincipal(ctx context.Context, sessData *sessioninfo.SessionData) error {
	if s.PrincipalResolver == nil {
		return nil
	}
	if imp := sessData.Impersonation; imp != nil && imp.Principal.IsRole() {
		return nil
	}

	principal, err := s.PrincipalResolver(ctx)
	if err != nil {
		return errors.Wrap(err, "PrincipalResolver()")
	}
	if principal == (accesstypes.Principal{}) || principal == sessioninfo.PrincipalFromCtx(ctx) {
		return nil
	}
	sessData.Principal = principal

	return nil
}

// principalKindName renders a principal as its evidence attributes.
func principalKindName(p accesstypes.Principal) (kind, name string) {
	if role, ok := p.Role(); ok {
		return sessioninfo.PrincipalKindRole, string(role)
	}
	user, _ := p.User()

	return sessioninfo.PrincipalKindUser, string(user)
}

// Authenticated is the handler reports if the session is authenticated
func (s *BaseSession) Authenticated() http.HandlerFunc {
	type response struct {
		Authenticated bool                   `json:"authenticated"`
		Username      string                 `json:"username"`
		Impersonation *ImpersonationResponse `json:"impersonation,omitempty"`
	}

	return s.Handle(func(w http.ResponseWriter, r *http.Request) error {
		ctx, span := tracer.Start(r.Context())
		defer span.End()

		ctx, err := s.ValidateSessionAPI(ctx)
		if err != nil {
			if httpio.HasUnauthorized(err) {
				return httpio.NewEncoder(w).Ok(response{})
			}

			return httpio.NewEncoder(w).ClientMessage(ctx, err)
		}

		sessInfo := sessioninfo.FromCtx(ctx)
		imp, _ := sessioninfo.ImpersonationFromCtx(ctx)

		// set response values
		res := response{
			Authenticated: true,
			Username:      sessInfo.Username,
			Impersonation: NewImpersonationResponse(imp),
		}

		return httpio.NewEncoder(w).Ok(res)
	})
}

// Logout destroys the current session
func (s *BaseSession) Logout() http.HandlerFunc {
	return s.Handle(func(w http.ResponseWriter, r *http.Request) error {
		ctx, span := tracer.Start(r.Context())
		defer span.End()

		if err := s.LogoutAPI(ctx); err != nil {
			return httpio.NewEncoder(w).ClientMessage(ctx, err)
		}

		return httpio.NewEncoder(w).Ok(nil)
	})
}

// SetXSRFToken sets the XSRF Token
func (s *BaseSession) SetXSRFToken(next http.Handler) http.Handler {
	return s.Handle(func(w http.ResponseWriter, r *http.Request) error {
		set, err := s.CookieHandler.RefreshXSRFTokenCookie(w, r, sessioninfo.IDFromRequest(r))
		if err != nil {
			return httpio.NewEncoder(w).ClientMessage(r.Context(), err)
		}

		if set && !internalcookie.SafeMethods.Contain(r.Method) {
			// Cookie was not present and request requires XSRF Token, so
			// redirect request to try again now that the XSRF Token Cookie is set.
			// Sanitized because a crafted "//host/path" request URI would otherwise
			// become a scheme-relative redirect off-site.
			http.Redirect(w, r, internalcookie.SanitizeReturnURL(r.RequestURI), http.StatusTemporaryRedirect)

			return nil
		}

		next.ServeHTTP(w, r)

		return nil
	})
}

// ValidateXSRFToken validates the XSRF Token
func (s *BaseSession) ValidateXSRFToken(next http.Handler) http.Handler {
	return s.Handle(func(w http.ResponseWriter, r *http.Request) error {
		// Validate XSRFToken for non-safe
		if !internalcookie.SafeMethods.Contain(r.Method) {
			hasValidXSRFToken, err := s.CookieHandler.HasValidXSRFToken(r)
			if err != nil {
				return httpio.NewEncoder(w).ClientMessage(r.Context(), err)
			}

			if !hasValidXSRFToken {
				// Token validation failed
				return httpio.NewEncoder(w).ClientMessage(r.Context(), httpio.NewForbiddenMessage("invalid XSRF token"))
			}
		}

		next.ServeHTTP(w, r)

		return nil
	})
}
