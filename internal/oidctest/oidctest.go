// Package oidctest holds the test doubles the OIDC authenticator tests share: a minimal
// identity provider that signs real ID tokens, and a cookie client with a fresh key.
package oidctest

import (
	"crypto/rand"
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	internalcookie "github.com/cccteam/session/internal/cookie"
	"github.com/go-jose/go-jose/v4"
)

// FakeIDP is a minimal OIDC provider: discovery, JWKS, and a token endpoint that
// returns an ID token built per request by the test case.
type FakeIDP struct {
	Server   *httptest.Server
	clientID string
	key      *rsa.PrivateKey

	// TokenClaims builds the ID token claims for the next token-endpoint call. The
	// issuer and audience are filled in by the fake unless already present.
	TokenClaims func() map[string]any
	// TokenStatus, when non-zero, makes the token endpoint fail with that status.
	TokenStatus int
}

// NewFakeIDP starts a provider whose tokens are issued for clientID. It is closed with
// the test.
func NewFakeIDP(t *testing.T, clientID string) *FakeIDP {
	t.Helper()

	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("rsa.GenerateKey() error = %v", err)
	}

	f := &FakeIDP{key: key, clientID: clientID}

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
	mux.HandleFunc("/jwks", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(jose.JSONWebKeySet{
			Keys: []jose.JSONWebKey{{Key: key.Public(), KeyID: "test-key", Algorithm: "RS256", Use: "sig"}},
		})
	})
	mux.HandleFunc("/token", func(w http.ResponseWriter, _ *http.Request) {
		if f.TokenStatus != 0 {
			http.Error(w, "token endpoint failure", f.TokenStatus)

			return
		}

		claims := f.TokenClaims()
		if _, ok := claims["iss"]; !ok {
			claims["iss"] = f.Server.URL
		}
		if _, ok := claims["aud"]; !ok {
			claims["aud"] = f.clientID
		}
		claims["exp"] = time.Now().Add(time.Hour).Unix()
		claims["iat"] = time.Now().Unix()

		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{
			"access_token": "test-access-token",
			"token_type":   "Bearer",
			"expires_in":   3600,
			"id_token":     f.SignToken(claims),
		})
	})

	f.Server = httptest.NewServer(mux)
	t.Cleanup(f.Server.Close)

	return f
}

// SignToken signs claims as a compact RS256 JWT under the provider's key.
func (f *FakeIDP) SignToken(claims map[string]any) string {
	payload, err := json.Marshal(claims)
	if err != nil {
		panic(err)
	}
	signer, err := jose.NewSigner(jose.SigningKey{Algorithm: jose.RS256, Key: f.key}, &jose.SignerOptions{
		ExtraHeaders: map[jose.HeaderKey]any{"kid": "test-key"},
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
