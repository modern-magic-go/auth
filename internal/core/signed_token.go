package core

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"strings"
	"time"
)

// SignedTokenFormatAdapter 提供 HMAC-SHA256 签名的 token 格式。
// 格式: Base64URL(payload) + "." + Base64URL(signature)
type SignedTokenFormatAdapter struct {
	secret []byte
}

// NewSignedTokenFormatAdapter 创建带 HMAC-SHA256 签名的 token 格式适配器。
// secret 必须至少 32 字节，建议使用 crypto/rand 生成。
func NewSignedTokenFormatAdapter(secret []byte) TokenFormatAdapter {
	if len(secret) == 0 {
		panic("go-auth: secret cannot be empty")
	}
	return &SignedTokenFormatAdapter{secret: secret}
}

// Encode 编码并签名 token claims。
func (a *SignedTokenFormatAdapter) Encode(claims TokenClaims) (string, error) {
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
	payloadB64 := base64.RawURLEncoding.EncodeToString(b)

	// 计算 HMAC-SHA256 签名
	mac := hmac.New(sha256.New, a.secret)
	mac.Write([]byte(payloadB64))
	sig := base64.RawURLEncoding.EncodeToString(mac.Sum(nil))

	return payloadB64 + "." + sig, nil
}

// Decode 解码并验证 token 签名。
func (a *SignedTokenFormatAdapter) Decode(token string) (TokenClaims, error) {
	parts := strings.Split(token, ".")
	if len(parts) != 2 {
		return TokenClaims{}, ErrInvalidTokenFormat
	}

	payloadB64, sigB64 := parts[0], parts[1]

	// 验证签名
	mac := hmac.New(sha256.New, a.secret)
	mac.Write([]byte(payloadB64))
	expectedSig, err := base64.RawURLEncoding.DecodeString(sigB64)
	if err != nil {
		return TokenClaims{}, ErrInvalidTokenFormat
	}
	if !hmac.Equal(mac.Sum(nil), expectedSig) {
		return TokenClaims{}, ErrInvalidTokenFormat
	}

	// 解码 payload
	b, err := base64.RawURLEncoding.DecodeString(payloadB64)
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
