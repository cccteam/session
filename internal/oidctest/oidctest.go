// Package oidctest holds the test doubles the OIDC authenticator tests share: a minimal
// identity provider that signs real ID tokens, and a cookie client with a fresh key.
package oidctest

import (
	"crypto/rand"
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	internalcookie "github.com/cccteam/session/internal/cookie"
	"github.com/go-jose/go-jose/v4"
)

// FakeIDP is a minimal OIDC provider: discovery, JWKS, and a token endpoint that
// returns an ID token built per request by the test case. NewFakeIDP serves them at
// the root, as Google does; NewFakeEntra serves them per tenant, as the Microsoft
// identity platform does.
type FakeIDP struct {
	Server   *httptest.Server
	clientID string

	// mu guards keys: Rotate adds one while the server may be serving the set.
	mu sync.Mutex
	// keys are the provider's signing keys, the last one current; the key set serves
	// them all, as a provider does while it rolls a key over.
	keys []signingKey
	// keyFetches counts the key set's reads.
	keyFetches atomic.Int64

	// TokenClaims builds the ID token claims for the next token-endpoint call. The
	// issuer and audience are filled in by the fake unless already present, and so is
	// an expiry an hour out.
	TokenClaims func() map[string]any
	// TokenStatus, when non-zero, makes the token endpoint fail with that status.
	TokenStatus int
	// Mint, when set, serializes the next token from its claims in place of the
	// provider's own signing: a token under a key the provider never published
	// (SignedBy), without a signature (Unsigned) or under another algorithm
	// (SignedHS256).
	Mint func(claims map[string]any) string
}

// signingKey is one of the provider's keys with its id.
type signingKey struct {
	kid string
	key *rsa.PrivateKey
}

// NewFakeIDP starts a provider whose tokens are issued for clientID, serving discovery,
// the key set and the token endpoint at its root with the issuer being the server. It
// is closed with the test.
func NewFakeIDP(t *testing.T, clientID string) *FakeIDP {
	t.Helper()

	f := &FakeIDP{keys: []signingKey{{kid: "test-key", key: NewKey(t)}}, clientID: clientID}

	mux := http.NewServeMux()
	mux.HandleFunc("/.well-known/openid-configuration", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{
			"issuer":                 f.Server.URL,
			"authorization_endpoint": f.Server.URL + "/auth",
			"token_endpoint":         f.Server.URL + "/token",
			"jwks_uri":               f.Server.URL + "/jwks",
		})
	})
	mux.HandleFunc("/jwks", func(w http.ResponseWriter, _ *http.Request) { f.serveKeys(w) })
	mux.HandleFunc("/token", func(w http.ResponseWriter, _ *http.Request) {
		f.serveToken(w, func(map[string]any) string { return f.Server.URL })
	})

	f.Server = httptest.NewServer(mux)
	t.Cleanup(f.Server.Close)

	return f
}

// NewKey is a fresh RSA signing key.
func NewKey(t *testing.T) *rsa.PrivateKey {
	t.Helper()

	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("rsa.GenerateKey() error = %v", err)
	}

	return key
}

// Rotate gives the provider a new signing key under a new key id: tokens are signed
// with it from now on, and the key set serves the old keys beside it.
func (f *FakeIDP) Rotate(t *testing.T) {
	t.Helper()

	key := NewKey(t)
	f.mu.Lock()
	defer f.mu.Unlock()
	f.keys = append(f.keys, signingKey{kid: fmt.Sprintf("test-key-%d", len(f.keys)+1), key: key})
}

// KeyFetches is how many times the key set was read.
func (f *FakeIDP) KeyFetches() int {
	return int(f.keyFetches.Load())
}

// serveKeys writes the provider's key set.
func (f *FakeIDP) serveKeys(w http.ResponseWriter) {
	f.keyFetches.Add(1)
	f.mu.Lock()
	set := jose.JSONWebKeySet{}
	for _, k := range f.keys {
		set.Keys = append(set.Keys, jose.JSONWebKey{Key: k.key.Public(), KeyID: k.kid, Algorithm: "RS256", Use: "sig"})
	}
	f.mu.Unlock()

	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(set)
}

// serveToken answers the token endpoint: a failure when TokenStatus says so, otherwise
// an ID token of the claims the test case builds, with the issuer defaultIssuer gives
// them, the audience and an expiry an hour out filled in unless already present.
func (f *FakeIDP) serveToken(w http.ResponseWriter, defaultIssuer func(claims map[string]any) string) {
	if f.TokenStatus != 0 {
		http.Error(w, "token endpoint failure", f.TokenStatus)

		return
	}

	claims := f.TokenClaims()
	if _, ok := claims["iss"]; !ok {
		claims["iss"] = defaultIssuer(claims)
	}
	if _, ok := claims["aud"]; !ok {
		claims["aud"] = f.clientID
	}
	if _, ok := claims["exp"]; !ok {
		claims["exp"] = time.Now().Add(time.Hour).Unix()
	}
	claims["iat"] = time.Now().Unix()
	mint := f.SignToken
	if f.Mint != nil {
		mint = f.Mint
	}

	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]any{
		"access_token": "test-access-token",
		"token_type":   "Bearer",
		"expires_in":   3600,
		"id_token":     mint(claims),
	})
}

// SignToken signs claims as a compact RS256 JWT under the provider's key.
func (f *FakeIDP) SignToken(claims map[string]any) string {
	f.mu.Lock()
	current := f.keys[len(f.keys)-1]
	f.mu.Unlock()

	return SignedBy(current.key, current.kid, claims)
}

// SignedBy is claims as an RS256 ID token signed with key under the key id kid, which a
// provider's key set may or may not publish.
func SignedBy(key *rsa.PrivateKey, kid string, claims map[string]any) string {
	return serialize(claims, jose.SigningKey{Algorithm: jose.RS256, Key: key}, kid)
}

// SignedHS256 is claims as an ID token under the HMAC algorithm with secret (at least 32
// bytes), which no OpenID provider of these tests signs with.
func SignedHS256(secret []byte, claims map[string]any) string {
	return serialize(claims, jose.SigningKey{Algorithm: jose.HS256, Key: secret}, "test-key")
}

// Unsigned is claims as a JWT with the algorithm none and no signature.
func Unsigned(claims map[string]any) string {
	payload, err := json.Marshal(claims)
	if err != nil {
		panic(err)
	}
	header, err := json.Marshal(map[string]string{"alg": "none", "typ": "JWT", "kid": "test-key"})
	if err != nil {
		panic(err)
	}

	return base64.RawURLEncoding.EncodeToString(header) + "." + base64.RawURLEncoding.EncodeToString(payload) + "."
}

// serialize signs claims with key under kid into a compact JWS.
func serialize(claims map[string]any, key jose.SigningKey, kid string) string {
	payload, err := json.Marshal(claims)
	if err != nil {
		panic(err)
	}
	signer, err := jose.NewSigner(key, &jose.SignerOptions{
		ExtraHeaders: map[jose.HeaderKey]any{"kid": kid},
	})
	if err != nil {
		panic(err)
	}
	jws, err := signer.Sign(payload)
	if err != nil {
		panic(err)
	}
	token, err := jws.CompactSerialize()
	if err != nil {
		panic(err)
	}

	return token
}

// NewCookieClient returns a cookie client with a fresh random master key.
func NewCookieClient(t *testing.T) *internalcookie.Client {
	t.Helper()

	key := make([]byte, 64)
	if _, err := rand.Read(key); err != nil {
		t.Fatalf("rand.Read() error = %v", err)
	}
	client, err := internalcookie.NewCookieClient(base64.StdEncoding.EncodeToString(key))
	if err != nil {
		t.Fatalf("internalcookie.NewCookieClient() error = %v", err)
	}

	return client
}
