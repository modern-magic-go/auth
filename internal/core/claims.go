package core

import (
	"encoding/json"
	"fmt"
	"time"
)

var reservedClaimKeys = map[string]struct{}{
	"jti": {},
	"typ": {},
	"sub": {},
	"iat": {},
	"exp": {},
	"ver": {},
	"sid": {},
	"iss": {},
	"aud": {},
	"nbf": {},
}

func validateExtraClaims(extra map[string]any) error {
	for key := range extra {
		if key == "" {
			return ErrInvalidTokenFormat
		}
		if _, reserved := reservedClaimKeys[key]; reserved {
			return fmt.Errorf("%w: %s", ErrReservedClaim, key)
		}
	}
	return nil
}

func cloneExtraClaims(extra map[string]any) map[string]any {
	if len(extra) == 0 {
		return nil
	}
	out := make(map[string]any, len(extra))
	for key, value := range extra {
		out[key] = value
	}
	return out
}

func claimsToMap(claims TokenClaims) (map[string]any, error) {
	if err := validateExtraClaims(claims.ExtraClaims); err != nil {
		return nil, err
	}

	payload := map[string]any{
		"jti": claims.TokenID,
		"typ": string(claims.TokenType),
		"sub": claims.Subject,
		"iat": claims.IssuedAt.Unix(),
		"exp": claims.ExpiresAt.Unix(),
		"ver": claims.Version,
	}
	if claims.SessionID != "" {
		payload["sid"] = claims.SessionID
	}
	for key, value := range claims.ExtraClaims {
		payload[key] = value
	}
	return payload, nil
}

func claimsFromMap(payload map[string]json.RawMessage) (TokenClaims, error) {
	tokenID, err := decodeRawString(payload, "jti")
	if err != nil || tokenID == "" {
		return TokenClaims{}, ErrInvalidTokenFormat
	}
	tokenType, err := decodeRawString(payload, "typ")
	if err != nil || (tokenType != string(TokenTypeAccess) && tokenType != string(TokenTypeRefresh)) {
		return TokenClaims{}, ErrInvalidTokenFormat
	}
	subject, err := decodeRawString(payload, "sub")
	if err != nil || subject == "" {
		return TokenClaims{}, ErrInvalidTokenFormat
	}
	version, err := decodeRawString(payload, "ver")
	if err != nil || version == "" {
		return TokenClaims{}, ErrInvalidTokenFormat
	}
	issuedAt, err := decodeRawInt64(payload, "iat")
	if err != nil {
		return TokenClaims{}, ErrInvalidTokenFormat
	}
	expiresAt, err := decodeRawInt64(payload, "exp")
	if err != nil {
		return TokenClaims{}, ErrInvalidTokenFormat
	}

	sessionID := ""
	if raw, ok := payload["sid"]; ok {
		if err := json.Unmarshal(raw, &sessionID); err != nil {
			return TokenClaims{}, ErrInvalidTokenFormat
		}
	}

	claims := TokenClaims{
		TokenID:   tokenID,
		TokenType: TokenType(tokenType),
		Subject:   subject,
		IssuedAt:  time.Unix(issuedAt, 0).UTC(),
		ExpiresAt: time.Unix(expiresAt, 0).UTC(),
		Version:   version,
		SessionID: sessionID,
	}
	if !claims.ExpiresAt.After(claims.IssuedAt) {
		return TokenClaims{}, ErrInvalidTokenFormat
	}

	for key, raw := range payload {
		if _, reserved := reservedClaimKeys[key]; reserved {
			continue
		}
		var value any
		if err := json.Unmarshal(raw, &value); err != nil {
			return TokenClaims{}, ErrInvalidTokenFormat
		}
		if claims.ExtraClaims == nil {
			claims.ExtraClaims = make(map[string]any)
		}
		claims.ExtraClaims[key] = value
	}

	return claims, nil
}

func decodeRawString(payload map[string]json.RawMessage, key string) (string, error) {
	raw, ok := payload[key]
	if !ok {
		return "", ErrInvalidTokenFormat
	}
	var value string
	if err := json.Unmarshal(raw, &value); err != nil {
		return "", ErrInvalidTokenFormat
	}
	return value, nil
}

func decodeRawInt64(payload map[string]json.RawMessage, key string) (int64, error) {
	raw, ok := payload[key]
	if !ok {
		return 0, ErrInvalidTokenFormat
	}
	var value int64
	if err := json.Unmarshal(raw, &value); err != nil {
		return 0, ErrInvalidTokenFormat
	}
	return value, nil
}
