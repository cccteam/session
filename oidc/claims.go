package oidc

import (
	"encoding/json"

	"github.com/go-playground/errors/v5"
)

// DecodeClaims decodes the fields a method needs from the verified claims.
func DecodeClaims[C any](rawClaims json.RawMessage) (*C, error) {
	claims := new(C)
	if err := json.Unmarshal(rawClaims, claims); err != nil {
		return nil, errors.Wrap(err, "json.Unmarshal()")
	}

	return claims, nil
}
