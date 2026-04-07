package core

import (
	"strings"
)

// ParseBearerToken 从 Authorization 头中提取 Bearer token。
func ParseBearerToken(authorization string) (string, error) {
	authorization = strings.TrimSpace(authorization)
	if authorization == "" {
		return "", ErrInvalidBearerToken
	}

	parts := strings.SplitN(authorization, " ", 2)
	if len(parts) != 2 || !strings.EqualFold(parts[0], "Bearer") {
		return "", ErrInvalidBearerToken
	}

	token := strings.TrimSpace(parts[1])
	if token == "" {
		return "", ErrInvalidBearerToken
	}
	return token, nil
}
