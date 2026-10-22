// Package auth provides a portable, framework-agnostic authentication core.
//
// It manages Access/Refresh token lifecycle with pluggable session storage.
// The module does not read configuration from YAML or environment variables;
// all dependencies must be explicitly injected at initialization.
package auth

import (
	"context"
	"time"

	"github.com/modern-magic-go/auth/internal/core"
)

const ModuleVersion = core.ModuleVersion
const CompatibilityNotes = core.CompatibilityNotes

type VersionInfo = core.VersionInfo

func GetVersionInfo() VersionInfo { return core.GetVersionInfo() }

var (
	ErrInvalidConfig           = core.ErrInvalidConfig
	ErrInvalidBearerToken      = core.ErrInvalidBearerToken
	ErrInvalidTokenFormat      = core.ErrInvalidTokenFormat
	ErrTokenTypeMismatch       = core.ErrTokenTypeMismatch
	ErrTokenExpired            = core.ErrTokenExpired
	ErrSessionNotFound         = core.ErrSessionNotFound
	ErrTokenRevoked            = core.ErrTokenRevoked
	ErrRefreshTokenReplayed    = core.ErrRefreshTokenReplayed
	ErrReservedClaim           = core.ErrReservedClaim
	ErrRevocationNotConfigured = core.ErrRevocationNotConfigured
	ErrUnsupportedMode         = core.ErrUnsupportedMode
	ErrSessionIDRequired       = core.ErrSessionIDRequired
)

type RefreshPolicy = core.RefreshPolicy

const (
	RefreshPolicyReuseUntilExpiry = core.RefreshPolicyReuseUntilExpiry
	RefreshPolicyRotateNearExpiry = core.RefreshPolicyRotateNearExpiry
	RefreshPolicyOneTimeRotation  = core.RefreshPolicyOneTimeRotation
)

type Config = core.Config

func DefaultConfig() Config { return core.DefaultConfig() }

type AccessTokenMode = core.AccessTokenMode

const (
	AccessTokenStateful  = core.AccessTokenStateful
	AccessTokenStateless = core.AccessTokenStateless
)

type TokenType = core.TokenType

const (
	TokenTypeAccess  = core.TokenTypeAccess
	TokenTypeRefresh = core.TokenTypeRefresh
)

type (
	TokenClaims        = core.TokenClaims
	SessionMetadata    = core.SessionMetadata
	AccessSession      = core.AccessSession
	RefreshSession     = core.RefreshSession
	TokenPair          = core.TokenPair
	IssueRequest       = core.IssueRequest
	ValidateResult     = core.ValidateResult
	RefreshResult      = core.RefreshResult
	SessionRef         = core.SessionRef
	RefreshGraceRecord = core.RefreshGraceRecord
)

type (
	TokenFormatAdapter        = core.TokenFormatAdapter
	RefreshTokenFormat        = core.RefreshTokenFormat
	SessionStore              = core.SessionStore
	SigningFormat             = core.SigningFormat
	IndexedSessionStore       = core.IndexedSessionStore
	RevocationStore           = core.RevocationStore
	RefreshGraceStore         = core.RefreshGraceStore
	GraceRotationStore        = core.GraceRotationStore
	IndexedGraceRotationStore = core.IndexedGraceRotationStore
	Clock                     = core.Clock
	RandomSource              = core.RandomSource
	Serializer                = core.Serializer
)

type Service = core.Service
type Option = core.Option
type JWTOption = core.JWTOption
type OpaqueRefreshOption = core.OpaqueRefreshOption

func WithTokenFormat(format TokenFormatAdapter) Option {
	return core.WithTokenFormat(format)
}

func WithAccessTokenFormat(format TokenFormatAdapter) Option {
	return core.WithAccessTokenFormat(format)
}

func WithRefreshTokenFormat(format RefreshTokenFormat) Option {
	return core.WithRefreshTokenFormat(format)
}

func WithOpaqueRefreshToken(opts ...OpaqueRefreshOption) Option {
	return core.WithOpaqueRefreshToken(opts...)
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

func WithRevocationStore(store RevocationStore) Option {
	return core.WithRevocationStore(store)
}

func WithSessionEvictionHandler(handler func(ctx context.Context, evicted []SessionRef)) Option {
	return core.WithSessionEvictionHandler(handler)
}

func WithGraceEncryptionKey(key []byte) Option {
	return core.WithGraceEncryptionKey(key)
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

func NewJWTHS256FormatAdapter(secret []byte, opts ...JWTOption) TokenFormatAdapter {
	return core.NewJWTHS256FormatAdapter(secret, opts...)
}

func WithJWTIssuer(issuer string) JWTOption {
	return core.WithJWTIssuer(issuer)
}

func WithJWTAudience(audience ...string) JWTOption {
	return core.WithJWTAudience(audience...)
}

func WithJWTLeeway(leeway time.Duration) JWTOption {
	return core.WithJWTLeeway(leeway)
}

func WithJWTClock(clock Clock) JWTOption {
	return core.WithJWTClock(clock)
}

func NewOpaqueRefreshTokenFormat(opts ...OpaqueRefreshOption) RefreshTokenFormat {
	return core.NewOpaqueRefreshTokenFormat(opts...)
}

func WithOpaqueRandomSource(random RandomSource) OpaqueRefreshOption {
	return core.WithOpaqueRandomSource(random)
}

func ParseBearerToken(authorization string) (string, error) {
	return core.ParseBearerToken(authorization)
}
