package core

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"strings"
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
	return &SignedTokenFormatAdapter{secret: append([]byte(nil), secret...)}
}

// IsSigned 报告该格式提供签名完整性保护。
func (a *SignedTokenFormatAdapter) IsSigned() bool {
	return true
}

// Encode 编码并签名 token claims。
func (a *SignedTokenFormatAdapter) Encode(claims TokenClaims) (string, error) {
	payload, err := claimsToMap(claims)
	if err != nil {
		return "", err
	}
	bytes, err := json.Marshal(payload)
	if err != nil {
		return "", err
	}
	payloadB64 := base64.RawURLEncoding.EncodeToString(bytes)

	mac := hmac.New(sha256.New, a.secret)
	_, _ = mac.Write([]byte(payloadB64))
	signature := base64.RawURLEncoding.EncodeToString(mac.Sum(nil))

	return payloadB64 + "." + signature, nil
}

// Decode 解码并验证 token 签名。
func (a *SignedTokenFormatAdapter) Decode(token string) (TokenClaims, error) {
	parts := strings.Split(token, ".")
	if len(parts) != 2 || parts[0] == "" || parts[1] == "" {
		return TokenClaims{}, ErrInvalidTokenFormat
	}

	payloadB64, signatureB64 := parts[0], parts[1]

	signature, err := decodeJWTSegment(signatureB64)
	if err != nil {
		return TokenClaims{}, ErrInvalidTokenFormat
	}
	mac := hmac.New(sha256.New, a.secret)
	_, _ = mac.Write([]byte(payloadB64))
	if !hmac.Equal(mac.Sum(nil), signature) {
		return TokenClaims{}, ErrInvalidTokenFormat
	}

	payloadBytes, err := decodeJWTSegment(payloadB64)
	if err != nil {
		return TokenClaims{}, ErrInvalidTokenFormat
	}
	var payload map[string]json.RawMessage
	if err := json.Unmarshal(payloadBytes, &payload); err != nil {
		return TokenClaims{}, ErrInvalidTokenFormat
	}
	return claimsFromMap(payload)
}
