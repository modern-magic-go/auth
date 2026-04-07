// Package core provides the internal implementation of the authentication module.
// External consumers should import the root package (github.com/modern-magic-go/auth) instead.
package core

import (
	"context"
	"errors"
	"time"
)

// ─── Version ───────────────────────────────────────────────────────────────

// ModuleVersion 标识当前认证模块能力契约版本。
const ModuleVersion = "v1.0.0"

// CompatibilityNotes 描述升级时需要关注的兼容约束。
const CompatibilityNotes = "升级模块版本时需检查配置结构、token格式、refresh策略与适配器接口兼容性"

// VersionInfo 提供稳定的版本信息结构。
type VersionInfo struct {
	ModuleVersion      string
	CompatibilityNotes string
}

// GetVersionInfo 返回当前模块版本信息。
func GetVersionInfo() VersionInfo {
	return VersionInfo{
		ModuleVersion:      ModuleVersion,
		CompatibilityNotes: CompatibilityNotes,
	}
}

// ─── Errors ────────────────────────────────────────────────────────────────

var (
	ErrInvalidConfig        = errors.New("auth: invalid config")
	ErrInvalidBearerToken   = errors.New("auth: invalid bearer token")
	ErrInvalidTokenFormat   = errors.New("auth: invalid token format")
	ErrTokenTypeMismatch    = errors.New("auth: token type mismatch")
	ErrTokenExpired         = errors.New("auth: token expired")
	ErrSessionNotFound      = errors.New("auth: session not found")
	ErrTokenRevoked         = errors.New("auth: token revoked")
	ErrRefreshTokenReplayed = errors.New("auth: refresh token replay detected")
)

// ─── Config ────────────────────────────────────────────────────────────────

// RefreshPolicy 定义 Refresh Token 的刷新策略。
type RefreshPolicy string

const (
	RefreshPolicyReuseUntilExpiry RefreshPolicy = "reuse_until_expiry"
	RefreshPolicyRotateNearExpiry RefreshPolicy = "rotate_near_expiry"
	RefreshPolicyOneTimeRotation  RefreshPolicy = "one_time_rotation"
)

// Config 是认证模块的显式配置契约。
type Config struct {
	AccessTokenTTL      time.Duration
	RefreshTokenTTL     time.Duration
	RefreshPolicy       RefreshPolicy
	RotateNearExpiry    time.Duration
	ClockSkew           time.Duration
	SlidingExpiration   bool
	SlidingExtensionTTL time.Duration
	TokenIDLength       int
}

// DefaultConfig 返回推荐默认配置。
func DefaultConfig() Config {
	return Config{
		AccessTokenTTL:      15 * time.Minute,
		RefreshTokenTTL:     7 * 24 * time.Hour,
		RefreshPolicy:       RefreshPolicyReuseUntilExpiry,
		RotateNearExpiry:    12 * time.Hour,
		ClockSkew:           30 * time.Second,
		SlidingExpiration:   false,
		SlidingExtensionTTL: 15 * time.Minute,
		TokenIDLength:       24,
	}
}

// Normalize 对配置进行归一化与兜底。
func (c Config) Normalize() Config {
	d := DefaultConfig()
	if c.AccessTokenTTL <= 0 {
		c.AccessTokenTTL = d.AccessTokenTTL
	}
	if c.RefreshTokenTTL <= 0 {
		c.RefreshTokenTTL = d.RefreshTokenTTL
	}
	if c.RefreshPolicy == "" {
		c.RefreshPolicy = d.RefreshPolicy
	}
	if c.RotateNearExpiry < 0 {
		c.RotateNearExpiry = d.RotateNearExpiry
	}
	if c.ClockSkew < 0 {
		c.ClockSkew = d.ClockSkew
	}
	if c.SlidingExtensionTTL <= 0 {
		c.SlidingExtensionTTL = d.SlidingExtensionTTL
	}
	if c.TokenIDLength <= 0 {
		c.TokenIDLength = d.TokenIDLength
	}
	return c
}

// ─── Models ────────────────────────────────────────────────────────────────

// TokenType 区分 Access Token 与 Refresh Token。
type TokenType string

const (
	TokenTypeAccess  TokenType = "access"
	TokenTypeRefresh TokenType = "refresh"
)

// TokenClaims 是认证核心与 token 格式适配器之间的最小字段契约。
type TokenClaims struct {
	TokenID   string    `json:"jti"`
	TokenType TokenType `json:"typ"`
	Subject   string    `json:"sub"`
	IssuedAt  time.Time `json:"iat"`
	ExpiresAt time.Time `json:"exp"`
	Version   string    `json:"ver"`
}

// SessionMetadata 统一承载业务扩展信息。
type SessionMetadata map[string]any

// AccessSession 为服务端存储的 Access Token 会话记录。
type AccessSession struct {
	TokenID        string          `json:"token_id"`
	Subject        string          `json:"subject"`
	IssuedAt       time.Time       `json:"issued_at"`
	ExpiresAt      time.Time       `json:"expires_at"`
	RefreshTokenID string          `json:"refresh_token_id"`
	Metadata       SessionMetadata `json:"metadata,omitempty"`
}

// RefreshSession 为服务端存储的 Refresh Token 会话记录。
type RefreshSession struct {
	TokenID   string          `json:"token_id"`
	Subject   string          `json:"subject"`
	IssuedAt  time.Time       `json:"issued_at"`
	ExpiresAt time.Time       `json:"expires_at"`
	Metadata  SessionMetadata `json:"metadata,omitempty"`
}

// TokenPair 表示登录后签发的一对令牌。
type TokenPair struct {
	AccessToken   string
	RefreshToken  string
	AccessExpiry  time.Time
	RefreshExpiry time.Time
}

// IssueRequest 是签发 token 对的输入。
type IssueRequest struct {
	Subject  string
	Metadata SessionMetadata
}

// ValidateResult 是 Access Token 校验成功后的结果。
type ValidateResult struct {
	Subject        string
	AccessTokenID  string
	RefreshTokenID string
	Metadata       SessionMetadata
	IssuedAt       time.Time
	ExpiresAt      time.Time
}

// RefreshResult 是 Refresh Token 换发后的结果。
type RefreshResult struct {
	AccessToken   string
	RefreshToken  string
	AccessExpiry  time.Time
	RefreshExpiry time.Time
	Rotated       bool
}

// ─── Interfaces ────────────────────────────────────────────────────────────

// TokenFormatAdapter 定义 token 编解码与格式校验边界。
type TokenFormatAdapter interface {
	Encode(claims TokenClaims) (string, error)
	Decode(token string) (TokenClaims, error)
}

// SessionStore 定义认证核心依赖的会话存储契约。
type SessionStore interface {
	SaveAccessSession(ctx context.Context, tokenID string, session AccessSession, ttl time.Duration) error
	SaveRefreshSession(ctx context.Context, tokenID string, session RefreshSession, ttl time.Duration) error
	GetAccessSession(ctx context.Context, tokenID string) (AccessSession, error)
	GetRefreshSession(ctx context.Context, tokenID string) (RefreshSession, error)
	DeleteAccessSession(ctx context.Context, tokenID string) error
	DeleteRefreshSession(ctx context.Context, tokenID string) error
	RotateRefreshSession(ctx context.Context, oldTokenID, newTokenID string, newSession RefreshSession, ttl time.Duration) (bool, error)
	TouchAccessSession(ctx context.Context, tokenID string, ttl time.Duration) error
}

// Clock 抽象时间源，便于测试。
type Clock interface {
	Now() time.Time
}

// RandomSource 抽象随机源，便于测试和替换实现。
type RandomSource interface {
	NewID(length int) (string, error)
}

// Serializer 为可选序列化适配边界。
type Serializer interface {
	Marshal(v any) (string, error)
	Unmarshal(data string, v any) error
}
