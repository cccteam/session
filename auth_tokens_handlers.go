package session

import (
	"net/http"
	"time"

	"github.com/cccteam/ccc"
	"github.com/cccteam/ccc/tracer"
	"github.com/cccteam/httpio"
	"github.com/cccteam/session/internal/sessioncore"
	"github.com/cccteam/session/sessioninfo"
	"github.com/cccteam/session/sessionstorage"
)

// ApplicationTokenHandlers are the HTTP handlers of a person's application tokens:
// the page where they issue, list and revoke tokens for programs of their own.
type ApplicationTokenHandlers struct {
	create, list, revoke http.HandlerFunc
}

// Create accepts {"name", "outlet", "expiresIn"} from the signed-in person, expiresIn
// in seconds and optional, and issues an application token for the outlet as them. It
// answers {"id", "token", "name", "outlet", "expiresAt"}: token is the secret, shown
// this once. An outlet that is not registered, a missing name or a lifetime past the
// Auth's is 400. Route it behind ValidateSession and ValidateXSRFToken.
func (h *ApplicationTokenHandlers) Create() http.HandlerFunc { return h.create }

// List answers the signed-in person's live tokens, newest first, as [{"id", "kind",
// "name", "outlet", "clientId", "createdAt", "expiresAt", "lastUsedAt"}]: their
// application tokens and the tokens of their device grants, never a secret. Route it
// behind ValidateSession.
func (h *ApplicationTokenHandlers) List() http.HandlerFunc { return h.list }

// Revoke accepts {"id"} from the signed-in person and revokes that token of theirs,
// a device grant's with its family. It answers {}; a token that is not theirs or not
// live is 404. Route it behind ValidateSession and ValidateXSRFToken.
func (h *ApplicationTokenHandlers) Revoke() http.HandlerFunc { return h.revoke }

// ApplicationTokens returns the application token handlers.
func (a *Auth[S, U, Tx]) ApplicationTokens() *ApplicationTokenHandlers {
	return &ApplicationTokenHandlers{
		create: a.serving(a.tokenCreate()),
		list:   a.serving(a.tokenList()),
		revoke: a.serving(a.tokenRevoke()),
	}
}

// createTokenRequest is Create's request.
type createTokenRequest struct {
	Name      string `json:"name"`
	Outlet    string `json:"outlet"`
	ExpiresIn int64  `json:"expiresIn"`
}

// revokeTokenRequest is Revoke's request.
type revokeTokenRequest struct {
	ID ccc.UUID `json:"id"`
}

var (
	createTokenDecoder = sessioncore.NewDecoder[createTokenRequest]()
	revokeTokenDecoder = sessioncore.NewDecoder[revokeTokenRequest]()
)

// issuedTokenResponse is Create's answer.
type issuedTokenResponse struct {
	ID        ccc.UUID  `json:"id"`
	Token     string    `json:"token"`
	Name      string    `json:"name"`
	Outlet    string    `json:"outlet"`
	ExpiresAt time.Time `json:"expiresAt"`
}

// tokenView is one token as List answers it.
type tokenView struct {
	ID         ccc.UUID                 `json:"id"`
	Kind       sessionstorage.TokenKind `json:"kind"`
	Name       string                   `json:"name,omitempty"`
	Outlet     string                   `json:"outlet"`
	ClientID   string                   `json:"clientId,omitempty"`
	CreatedAt  time.Time                `json:"createdAt"`
	ExpiresAt  time.Time                `json:"expiresAt"`
	LastUsedAt *time.Time               `json:"lastUsedAt,omitempty"`
}

// tokenCreate is ApplicationTokens().Create().
func (a *Auth[S, U, Tx]) tokenCreate() http.HandlerFunc {
	return a.baseSession.Handle(func(w http.ResponseWriter, r *http.Request) error {
		ctx, span := tracer.Start(r.Context())
		defer span.End()

		ctx, err := a.validateRequest(ctx)
		if err != nil {
			return httpio.NewEncoder(w).ClientMessage(ctx, err)
		}
		req, err := createTokenDecoder.Decode(r)
		if err != nil {
			return httpio.NewEncoder(w).ClientMessage(ctx, err)
		}
		issued, err := a.API().CreateApplicationToken(ctx, &ApplicationTokenRequest{
			UserID: sessioninfo.UserFromCtx(ctx).ID, Outlet: req.Outlet, Name: req.Name, ExpiresIn: time.Duration(req.ExpiresIn) * time.Second,
		})
		if err != nil {
			return httpio.NewEncoder(w).ClientMessage(ctx, err)
		}

		return httpio.NewEncoder(w).Ok(issuedTokenResponse{
			ID: issued.Token.ID, Token: issued.Secret, Name: issued.Token.Name, Outlet: issued.Token.Outlet, ExpiresAt: issued.Token.ExpiresAt,
		})
	})
}

// tokenList is ApplicationTokens().List().
func (a *Auth[S, U, Tx]) tokenList() http.HandlerFunc {
	return a.baseSession.Handle(func(w http.ResponseWriter, r *http.Request) error {
		ctx, span := tracer.Start(r.Context())
		defer span.End()

		ctx, err := a.validateRequest(ctx)
		if err != nil {
			return httpio.NewEncoder(w).ClientMessage(ctx, err)
		}
		tokens, err := a.API().Tokens(ctx, sessioninfo.UserFromCtx(ctx).ID)
		if err != nil {
			return httpio.NewEncoder(w).ClientMessage(ctx, err)
		}
		views := make([]tokenView, len(tokens))
		for i, t := range tokens {
			views[i] = tokenView{ID: t.ID, Kind: t.Kind, Name: t.Name, Outlet: t.Outlet, ClientID: t.ClientID, CreatedAt: t.CreatedAt, ExpiresAt: t.ExpiresAt, LastUsedAt: t.LastUsedAt}
		}

		return httpio.NewEncoder(w).Ok(views)
	})
}

// tokenRevoke is ApplicationTokens().Revoke().
func (a *Auth[S, U, Tx]) tokenRevoke() http.HandlerFunc {
	return a.baseSession.Handle(func(w http.ResponseWriter, r *http.Request) error {
		ctx, span := tracer.Start(r.Context())
		defer span.End()

		ctx, err := a.validateRequest(ctx)
		if err != nil {
			return httpio.NewEncoder(w).ClientMessage(ctx, err)
		}
		req, err := revokeTokenDecoder.Decode(r)
		if err != nil {
			return httpio.NewEncoder(w).ClientMessage(ctx, err)
		}
		if err := a.API().RevokeToken(ctx, sessioninfo.UserFromCtx(ctx).ID, req.ID); err != nil {
			return httpio.NewEncoder(w).ClientMessage(ctx, err)
		}

		return httpio.NewEncoder(w).Ok(struct{}{})
	})
}
