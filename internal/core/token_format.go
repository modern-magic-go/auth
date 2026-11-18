package core

import (
	"encoding/base64"
	"encoding/json"
)

// DefaultTokenFormatAdapter 是当前版本唯一内置的非 JWT token 格式适配器。
// 格式为 Base64URL(JSON payload)，仅包含认证核心最小字段；不提供签名。
type DefaultTokenFormatAdapter struct{}

// NewDefaultTokenFormatAdapter 创建默认 token 格式适配器。
func NewDefaultTokenFormatAdapter() TokenFormatAdapter {
	return DefaultTokenFormatAdapter{}
}

// IsSigned 报告该格式不提供签名完整性保护。
func (DefaultTokenFormatAdapter) IsSigned() bool {
	return false
}

// Encode 编码 token claims。
func (DefaultTokenFormatAdapter) Encode(claims TokenClaims) (string, error) {
	payload, err := claimsToMap(claims)
	if err != nil {
		return "", err
	}
	bytes, err := json.Marshal(payload)
	if err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(bytes), nil
}

// Decode 解码并校验 token 文本。
func (DefaultTokenFormatAdapter) Decode(token string) (TokenClaims, error) {
	bytes, err := base64.RawURLEncoding.DecodeString(token)
	if err != nil {
		return TokenClaims{}, ErrInvalidTokenFormat
	}

	var payload map[string]json.RawMessage
	if err := json.Unmarshal(bytes, &payload); err != nil {
		return TokenClaims{}, ErrInvalidTokenFormat
	}
	return claimsFromMap(payload)
}
