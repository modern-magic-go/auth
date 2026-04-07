package core

import (
	"encoding/base64"
	"encoding/json"
	"time"
)

type defaultTokenPayload struct {
	TokenID   string `json:"jti"`
	TokenType string `json:"typ"`
	Subject   string `json:"sub"`
	IssuedAt  int64  `json:"iat"`
	ExpiresAt int64  `json:"exp"`
	Version   string `json:"ver"`
}

// DefaultTokenFormatAdapter 是当前版本唯一内置的非 JWT token 格式适配器。
// 格式为 Base64URL(JSON payload)，仅包含认证核心最小字段。
type DefaultTokenFormatAdapter struct{}

// NewDefaultTokenFormatAdapter 创建默认 token 格式适配器。
func NewDefaultTokenFormatAdapter() TokenFormatAdapter {
	return DefaultTokenFormatAdapter{}
}

// Encode 编码 token claims。
func (DefaultTokenFormatAdapter) Encode(claims TokenClaims) (string, error) {
	payload := defaultTokenPayload{
		TokenID:   claims.TokenID,
		TokenType: string(claims.TokenType),
		Subject:   claims.Subject,
		IssuedAt:  claims.IssuedAt.Unix(),
		ExpiresAt: claims.ExpiresAt.Unix(),
		Version:   claims.Version,
	}
	b, err := json.Marshal(payload)
	if err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(b), nil
}

// Decode 解码并校验 token 文本。
func (DefaultTokenFormatAdapter) Decode(token string) (TokenClaims, error) {
	b, err := base64.RawURLEncoding.DecodeString(token)
	if err != nil {
		return TokenClaims{}, ErrInvalidTokenFormat
	}

	var payload defaultTokenPayload
	if err := json.Unmarshal(b, &payload); err != nil {
		return TokenClaims{}, ErrInvalidTokenFormat
	}

	claims := TokenClaims{
		TokenID:   payload.TokenID,
		TokenType: TokenType(payload.TokenType),
		Subject:   payload.Subject,
		IssuedAt:  time.Unix(payload.IssuedAt, 0).UTC(),
		ExpiresAt: time.Unix(payload.ExpiresAt, 0).UTC(),
		Version:   payload.Version,
	}

	if claims.TokenID == "" || claims.Subject == "" || claims.Version == "" {
		return TokenClaims{}, ErrInvalidTokenFormat
	}
	if claims.TokenType != TokenTypeAccess && claims.TokenType != TokenTypeRefresh {
		return TokenClaims{}, ErrInvalidTokenFormat
	}
	if !claims.ExpiresAt.After(claims.IssuedAt) {
		return TokenClaims{}, ErrInvalidTokenFormat
	}

	return claims, nil
}
