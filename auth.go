// Package auth provides a portable, framework-agnostic authentication core.
//
// It manages Access/Refresh token lifecycle with pluggable session storage.
// The module does not read configuration from YAML or environment variables;
// all dependencies must be explicitly injected at initialization.
package auth

import (
	"context"

	"github.com/modern-magic-go/auth/internal/core"
)

const ModuleVersion = core.ModuleVersion
const CompatibilityNotes = core.CompatibilityNotes

type VersionInfo = core.VersionInfo

func GetVersionInfo() VersionInfo { return core.GetVersionInfo() }

var (
	ErrInvalidConfig        = core.ErrInvalidConfig
	ErrInvalidBearerToken   = core.ErrInvalidBearerToken
	ErrInvalidTokenFormat   = core.ErrInvalidTokenFormat
	ErrTokenTypeMismatch    = core.ErrTokenTypeMismatch
	ErrTokenExpired         = core.ErrTokenExpired
	ErrSessionNotFound      = core.ErrSessionNotFound
	ErrTokenRevoked         = core.ErrTokenRevoked
	ErrRefreshTokenReplayed = core.ErrRefreshTokenReplayed
)

type RefreshPolicy = core.RefreshPolicy

const (
	RefreshPolicyReuseUntilExpiry = core.RefreshPolicyReuseUntilExpiry
	RefreshPolicyRotateNearExpiry = core.RefreshPolicyRotateNearExpiry
	RefreshPolicyOneTimeRotation  = core.RefreshPolicyOneTimeRotation
)

type Config = core.Config

func DefaultConfig() Config { return core.DefaultConfig() }

type TokenType = core.TokenType

const (
	TokenTypeAccess  = core.TokenTypeAccess
	TokenTypeRefresh = core.TokenTypeRefresh
)

type (
	TokenClaims     = core.TokenClaims
	SessionMetadata = core.SessionMetadata
	AccessSession   = core.AccessSession
	RefreshSession  = core.RefreshSession
	TokenPair       = core.TokenPair
	IssueRequest    = core.IssueRequest
	ValidateResult  = core.ValidateResult
	RefreshResult   = core.RefreshResult
)

type (
	TokenFormatAdapter = core.TokenFormatAdapter
	SessionStore       = core.SessionStore
	Clock              = core.Clock
	RandomSource       = core.RandomSource
	Serializer         = core.Serializer
)

type Service = core.Service
type Option = core.Option

func WithTokenFormat(format TokenFormatAdapter) Option {
	return core.WithTokenFormat(format)
}

func WithClock(clock Clock) Option {
	return core.WithClock(clock)
}

func WithRandomSource(random RandomSource) Option {
	return core.WithRandomSource(random)
}

func WithSerializer(serializer Serializer) Option {
	return core.WithSerializer(serializer)
}

func WithRollbackFailureHandler(handler func(ctx context.Context, op string, tokenID string, err error)) Option {
	return core.WithRollbackFailureHandler(handler)
}

func NewService(cfg Config, store SessionStore, opts ...Option) (*Service, error) {
	return core.NewService(cfg, store, opts...)
}

func NewDefaultTokenFormatAdapter() TokenFormatAdapter {
	return core.NewDefaultTokenFormatAdapter()
}

func NewSignedTokenFormatAdapter(secret []byte) TokenFormatAdapter {
	return core.NewSignedTokenFormatAdapter(secret)
}

func ParseBearerToken(authorization string) (string, error) {
	return core.ParseBearerToken(authorization)
}
