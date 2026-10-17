package oidc

import (
	"encoding/json"

	"github.com/cccteam/httpio"
	"github.com/cccteam/session/sessioninfo"
	"github.com/go-playground/errors/v5"
)

// Issuer returns the iss claim of verified claims, "" when they carry none. Claims
// that do not decode are refused (parse_claims_failed).
func Issuer(rawClaims json.RawMessage) (string, error) {
	c, err := DecodeClaims[struct {
		Iss string `json:"iss"`
	}](rawClaims)
	if err != nil {
		return "", sessioninfo.NewLoginRefusal(sessioninfo.RefusedClaimsParse, httpio.NewUnauthorizedMessageWithError(err, "Failed to parse ID token claims"))
	}

	return c.Iss, nil
}

// DecodeClaims decodes the fields a method needs from the verified claims.
func DecodeClaims[C any](rawClaims json.RawMessage) (*C, error) {
	claims := new(C)
	if err := json.Unmarshal(rawClaims, claims); err != nil {
		return nil, errors.Wrap(err, "json.Unmarshal()")
	}

	return claims, nil
}
