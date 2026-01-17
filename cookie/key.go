package cookie

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"io"

	"aidanwoods.dev/go-paseto"
	"github.com/go-playground/errors/v5"
	"golang.org/x/crypto/hkdf"
)

// createPasetoKey returns a v4 local symmetric key.
func createPasetoKey(keyBase64 string) (paseto.V4SymmetricKey, error) {
	if keyBase64 == "" {
		// Handle "Dev Mode" / Empty Key
		rKey := make([]byte, 32)
		if _, err := rand.Read(rKey); err != nil {
			return paseto.V4SymmetricKey{}, errors.New("failed to generate random key")
		}
		keyBase64 = base64.StdEncoding.EncodeToString(rKey)
		fmt.Printf("Using random Key (Base64): %s\n", keyBase64)
	}

	keyMaterial, err := base64.StdEncoding.DecodeString(keyBase64)
	if err != nil {
		return paseto.V4SymmetricKey{}, fmt.Errorf("base64 decode failed: %w", err)
	}

	// Use HKDF to derive a 32-byte key for PASETO v4 (XChaCha20).
	// This strengthens the key and ensures it's the correct length.
	salt := []byte("cccteam-cookie-key-salt")
	hkdfReader := hkdf.New(sha256.New, keyMaterial, salt, nil)
	derivedKey := make([]byte, 32)
	if _, err := io.ReadFull(hkdfReader, derivedKey); err != nil {
		return paseto.V4SymmetricKey{}, errors.Wrap(err, "failed to derive key using HKDF")
	}

	key, err := paseto.V4SymmetricKeyFromBytes(derivedKey)
	if err != nil {
		return paseto.V4SymmetricKey{}, errors.Wrap(err, "paseto.V4SymmetricKeyFromBytes()")
	}

	return key, nil
}
