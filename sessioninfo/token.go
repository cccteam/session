package sessioninfo

import (
	"context"
	"net/http"

	"github.com/cccteam/ccc"
)

// MethodToken is the method of the auth event a request on a machine outlet records:
// the request was authenticated by a bearer token the Auth issued, and the event's
// connection is the token's kind, "application" or "access".
const MethodToken AuthMethod = "token"

// The token kinds as a request's TokenInfo names them.
const (
	// TokenKindApplication is a token a person issued to an application of their own.
	TokenKindApplication = "application"
	// TokenKindAccess is the access token of a device grant a command-line client
	// obtained.
	TokenKindAccess = "access"
)

// The evidence attributes of a request a bearer token authenticated, on the request's
// log entry, every line logged within it and its trace span.
const (
	// AttrTokenID is the token's id, the row's key.
	AttrTokenID = "token.id"
	// AttrTokenKind is the token's kind: "application" or "access".
	AttrTokenKind = "token.kind"
	// AttrTokenName is the name the person gave an application token; absent for an
	// access token.
	AttrTokenName = "token.name"
	// AttrTokenClient is the client a device grant's access token was issued to; absent
	// for an application token.
	AttrTokenClient = "token.client"
)

// TokenInfo is the credential of a request a machine outlet validated
// (session.MachineOutlet.ValidateToken): which token acts for the person, of which
// kind, under what name or for which client, and for which outlet. It is on the
// context's SessionData; a browser session carries none.
type TokenInfo struct {
	ID ccc.UUID
	// Kind is TokenKindApplication or TokenKindAccess.
	Kind string
	// Name is the name the person gave an application token; "" for an access token.
	Name string
	// ClientID is the client a device grant was issued to; "" for an application token.
	ClientID string
	// Outlet names the machine outlet the token was issued for and validated on.
	Outlet string
}

// Attributes renders the token as its evidence attributes.
func (t *TokenInfo) Attributes() []Attribute {
	attrs := []Attribute{{Key: AttrTokenID, Value: t.ID.String()}, {Key: AttrTokenKind, Value: t.Kind}}
	if t.Name != "" {
		attrs = append(attrs, Attribute{Key: AttrTokenName, Value: t.Name})
	}
	if t.ClientID != "" {
		attrs = append(attrs, Attribute{Key: AttrTokenClient, Value: t.ClientID})
	}

	return attrs
}

// TokenFromRequest returns the token that authenticated the request and true, or nil
// and false for a browser session. It panics when no session is in the context, like
// FromRequest.
func TokenFromRequest(r *http.Request) (*TokenInfo, bool) {
	return TokenFromCtx(r.Context())
}

// TokenFromCtx returns the token that authenticated the request in ctx and true, or
// nil and false for a browser session. It panics when no session is in the context,
// like FromCtx.
func TokenFromCtx(ctx context.Context) (*TokenInfo, bool) {
	sess := DataFromCtx(ctx)
	if sess.Token == nil {
		return nil, false
	}

	return sess.Token, true
}
