package cookie

import (
	"crypto/rand"
	"encoding/base64"
	"fmt"

	"aidanwoods.dev/go-paseto"
	"github.com/go-playground/errors/v5"
)

// createPasetoKey derives a specific key for a named cookie from a master base64 string.
func createPasetoKey(masterKeyBase64 string) (paseto.V4SymmetricKey, error) {
	if masterKeyBase64 == "" {
		// Handle "Dev Mode" / Empty Key
		rKey := make([]byte, 32)
		if _, err := rand.Read(rKey); err != nil {
			return paseto.V4SymmetricKey{}, errors.New("failed to generate random key")
		}
		masterKeyBase64 = base64.StdEncoding.EncodeToString(rKey)
		fmt.Printf("Using random Master Key (Base64): %s\n", masterKeyBase64)
	}

	masterBytes, err := base64.StdEncoding.DecodeString(masterKeyBase64)
	if err != nil {
		return paseto.V4SymmetricKey{}, fmt.Errorf("base64 decode failed: %w", err)
	}

	// PASETO v4 uses XChaCha20, which needs a 32-byte key.
	if len(masterBytes) < 32 {
		return paseto.V4SymmetricKey{}, errors.New("master Key too short, expect minimum 32 bytes (decoded)")
	}

	key, err := paseto.V4SymmetricKeyFromBytes(masterBytes[:32])
	if err != nil {
		return paseto.V4SymmetricKey{}, errors.Wrap(err, "paseto.V4SymmetricKeyFromBytes()")
	}

	return key, nil
}
