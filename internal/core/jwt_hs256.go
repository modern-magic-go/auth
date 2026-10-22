package core

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"strings"
	"time"
)

const (
	jwtAlgorithm = "HS256"
	jwtType      = "JWT"
)

type jwtHeader struct {
	Algorithm string `json:"alg"`
	Type      string `json:"typ"`
}

type jwtPayload struct {
	TokenID   string `json:"jti"`
	TokenType string `json:"typ"`
	Subject   string `json:"sub"`
	IssuedAt  *int64 `json:"iat"`
	ExpiresAt *int64 `json:"exp"`
	NotBefore *int64 `json:"nbf,omitempty"`
	Version   string `json:"ver"`
	Issuer    string `json:"iss,omitempty"`
	Audience  any    `json:"aud,omitempty"`
}

type jwtConfig struct {
	issuer   string
	audience []string
	leeway   time.Duration
	clock    Clock
}

// JWTOption 配置 HS256 JWT 适配器。
type JWTOption func(*jwtConfig)

// WithJWTIssuer 设置签发者（iss），Decode 时会校验该值。
func WithJWTIssuer(issuer string) JWTOption {
	return func(cfg *jwtConfig) {
		cfg.issuer = issuer
	}
}

// WithJWTAudience 设置期望的受众（aud），Decode 时要求 token 至少匹配其中一个。
func WithJWTAudience(audience ...string) JWTOption {
	return func(cfg *jwtConfig) {
		cfg.audience = append([]string(nil), audience...)
	}
}

// WithJWTLeeway 设置时间校验容差。默认与服务默认 ClockSkew（30s）一致。
func WithJWTLeeway(leeway time.Duration) JWTOption {
	return func(cfg *jwtConfig) {
		cfg.leeway = leeway
	}
}

// WithJWTClock 指定 JWT 时间校验使用的时间源。
func WithJWTClock(clock Clock) JWTOption {
	return func(cfg *jwtConfig) {
		cfg.clock = clock
	}
}

type jwtHS256FormatAdapter struct {
	secret   []byte
	issuer   string
	audience []string
	leeway   time.Duration
	clock    Clock
}

// NewJWTHS256FormatAdapter 创建标准 HS256 JWT 格式适配器。
//
// 输出为三段式 JWT（header.payload.signature），header 固定 alg=HS256、typ=JWT。
// secret 必须非空，建议至少 32 字节；空 secret 会 panic，与
// NewSignedTokenFormatAdapter 保持一致。
func NewJWTHS256FormatAdapter(secret []byte, opts ...JWTOption) TokenFormatAdapter {
	if len(secret) == 0 {
		panic("auth: JWT secret cannot be empty")
	}

	cfg := jwtConfig{
		leeway: DefaultConfig().ClockSkew,
		clock:  defaultClock{},
	}
	for _, opt := range opts {
		if opt != nil {
			opt(&cfg)
		}
	}
	if cfg.clock == nil {
		cfg.clock = defaultClock{}
	}
	if cfg.leeway < 0 {
		cfg.leeway = 0
	}

	return &jwtHS256FormatAdapter{
		secret:   append([]byte(nil), secret...),
		issuer:   cfg.issuer,
		audience: append([]string(nil), cfg.audience...),
		leeway:   cfg.leeway,
		clock:    cfg.clock,
	}
}

// Encode 编码并签名 token claims。
func (a *jwtHS256FormatAdapter) Encode(claims TokenClaims) (string, error) {
	headerBytes, err := json.Marshal(jwtHeader{
		Algorithm: jwtAlgorithm,
		Type:      jwtType,
	})
	if err != nil {
		return "", err
	}

	issuedAt := claims.IssuedAt.Unix()
	expiresAt := claims.ExpiresAt.Unix()
	payload := jwtPayload{
		TokenID:   claims.TokenID,
		TokenType: string(claims.TokenType),
		Subject:   claims.Subject,
		IssuedAt:  &issuedAt,
		ExpiresAt: &expiresAt,
		Version:   claims.Version,
		Issuer:    a.issuer,
	}
	switch len(a.audience) {
	case 0:
	case 1:
		payload.Audience = a.audience[0]
	default:
		payload.Audience = append([]string(nil), a.audience...)
	}

	payloadBytes, err := json.Marshal(payload)
	if err != nil {
		return "", err
	}

	headerSegment := base64.RawURLEncoding.EncodeToString(headerBytes)
	payloadSegment := base64.RawURLEncoding.EncodeToString(payloadBytes)
	signingInput := headerSegment + "." + payloadSegment

	mac := hmac.New(sha256.New, a.secret)
	_, _ = mac.Write([]byte(signingInput))
	signatureSegment := base64.RawURLEncoding.EncodeToString(mac.Sum(nil))

	return signingInput + "." + signatureSegment, nil
}

// Decode 解码并验证 JWT 签名、头信息、claims 与时间窗口。
func (a *jwtHS256FormatAdapter) Decode(token string) (TokenClaims, error) {
	parts := strings.Split(token, ".")
	if len(parts) != 3 || parts[0] == "" || parts[1] == "" || parts[2] == "" {
		return TokenClaims{}, ErrInvalidTokenFormat
	}

	headerBytes, err := decodeJWTSegment(parts[0])
	if err != nil {
		return TokenClaims{}, ErrInvalidTokenFormat
	}
	var header jwtHeader
	if err := json.Unmarshal(headerBytes, &header); err != nil {
		return TokenClaims{}, ErrInvalidTokenFormat
	}
	if header.Algorithm != jwtAlgorithm || header.Type != jwtType {
		return TokenClaims{}, ErrInvalidTokenFormat
	}

	signature, err := decodeJWTSegment(parts[2])
	if err != nil {
		return TokenClaims{}, ErrInvalidTokenFormat
	}
	mac := hmac.New(sha256.New, a.secret)
	_, _ = mac.Write([]byte(parts[0] + "." + parts[1]))
	if !hmac.Equal(mac.Sum(nil), signature) {
		return TokenClaims{}, ErrInvalidTokenFormat
	}

	payloadBytes, err := decodeJWTSegment(parts[1])
	if err != nil {
		return TokenClaims{}, ErrInvalidTokenFormat
	}
	var payload jwtPayload
	if err := json.Unmarshal(payloadBytes, &payload); err != nil {
		return TokenClaims{}, ErrInvalidTokenFormat
	}

	if payload.TokenID == "" || payload.Subject == "" || payload.Version == "" {
		return TokenClaims{}, ErrInvalidTokenFormat
	}
	if payload.TokenType != string(TokenTypeAccess) && payload.TokenType != string(TokenTypeRefresh) {
		return TokenClaims{}, ErrInvalidTokenFormat
	}
	if payload.IssuedAt == nil || payload.ExpiresAt == nil {
		return TokenClaims{}, ErrInvalidTokenFormat
	}

	claims := TokenClaims{
		TokenID:   payload.TokenID,
		TokenType: TokenType(payload.TokenType),
		Subject:   payload.Subject,
		IssuedAt:  time.Unix(*payload.IssuedAt, 0).UTC(),
		ExpiresAt: time.Unix(*payload.ExpiresAt, 0).UTC(),
		Version:   payload.Version,
	}
	if !claims.ExpiresAt.After(claims.IssuedAt) {
		return TokenClaims{}, ErrInvalidTokenFormat
	}

	now := a.clock.Now().UTC()
	if !now.Before(claims.ExpiresAt.Add(a.leeway)) {
		return TokenClaims{}, ErrTokenExpired
	}
	if claims.IssuedAt.After(now.Add(a.leeway)) {
		return TokenClaims{}, ErrInvalidTokenFormat
	}
	if payload.NotBefore != nil {
		notBefore := time.Unix(*payload.NotBefore, 0).UTC()
		if now.Add(a.leeway).Before(notBefore) {
			return TokenClaims{}, ErrInvalidTokenFormat
		}
	}

	if a.issuer != "" && payload.Issuer != a.issuer {
		return TokenClaims{}, ErrInvalidTokenFormat
	}
	if len(a.audience) > 0 {
		ok, err := jwtAudienceMatches(payload.Audience, a.audience)
		if err != nil || !ok {
			return TokenClaims{}, ErrInvalidTokenFormat
		}
	}

	return claims, nil
}

func decodeJWTSegment(segment string) ([]byte, error) {
	if decoded, err := base64.RawURLEncoding.DecodeString(segment); err == nil {
		return decoded, nil
	}
	if decoded, err := base64.URLEncoding.DecodeString(segment); err == nil {
		return decoded, nil
	}
	return nil, ErrInvalidTokenFormat
}

func jwtAudienceMatches(raw any, expected []string) (bool, error) {
	var actual []string
	switch value := raw.(type) {
	case nil:
		return false, nil
	case string:
		actual = []string{value}
	case []any:
		for _, item := range value {
			audience, ok := item.(string)
			if !ok {
				return false, ErrInvalidTokenFormat
			}
			actual = append(actual, audience)
		}
	default:
		return false, ErrInvalidTokenFormat
	}

	for _, got := range actual {
		for _, want := range expected {
			if got == want {
				return true, nil
			}
		}
	}
	return false, nil
}
