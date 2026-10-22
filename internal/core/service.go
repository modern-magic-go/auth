package core

import (
	"context"
	"errors"
	"time"
)

// Service 提供框架无关的认证核心能力。
type Service struct {
	config         Config
	store          SessionStore
	accessFormat   TokenFormatAdapter
	claimsFormat   TokenFormatAdapter
	refreshFormat  RefreshTokenFormat
	legacyFormat   TokenFormatAdapter
	legacySet      bool
	accessSet      bool
	refreshSet     bool
	clock          Clock
	random         RandomSource
	serializer     Serializer
	onRollbackFail func(ctx context.Context, op string, tokenID string, err error)
}

// Option 用于可选依赖注入。
type Option func(*Service)

// WithTokenFormat 指定 access 与 claims refresh 共用的 token 格式适配器（兼容旧行为）。
func WithTokenFormat(format TokenFormatAdapter) Option {
	return func(s *Service) {
		s.legacyFormat = format
		s.legacySet = true
	}
}

// WithAccessTokenFormat 指定 access token 使用的格式。未显式配置 refresh 格式时，
// claims refresh 默认沿用该格式；需要不透明 refresh 时再加 WithOpaqueRefreshToken。
func WithAccessTokenFormat(format TokenFormatAdapter) Option {
	return func(s *Service) {
		s.accessFormat = format
		s.accessSet = true
	}
}

// WithRefreshTokenFormat 指定不透明 refresh token 格式。
func WithRefreshTokenFormat(format RefreshTokenFormat) Option {
	return func(s *Service) {
		s.refreshFormat = format
		s.refreshSet = true
	}
}

// WithOpaqueRefreshToken 使用内置的 32 字节不透明 refresh token。
func WithOpaqueRefreshToken(opts ...OpaqueRefreshOption) Option {
	return func(s *Service) {
		s.refreshFormat = NewOpaqueRefreshTokenFormat(opts...)
		s.refreshSet = true
	}
}

// WithClock 指定时间源。
func WithClock(clock Clock) Option {
	return func(s *Service) {
		s.clock = clock
	}
}

// WithRandomSource 指定随机源。
func WithRandomSource(random RandomSource) Option {
	return func(s *Service) {
		s.random = random
	}
}

func WithRollbackFailureHandler(handler func(ctx context.Context, op string, tokenID string, err error)) Option {
	return func(s *Service) {
		s.onRollbackFail = handler
	}
}

func WithSerializer(serializer Serializer) Option {
	return func(s *Service) {
		s.serializer = serializer
	}
}

// NewService 创建认证服务。
func NewService(cfg Config, store SessionStore, opts ...Option) (*Service, error) {
	if store == nil {
		return nil, ErrInvalidConfig
	}

	s := &Service{
		config:       cfg.Normalize(),
		store:        store,
		legacyFormat: NewDefaultTokenFormatAdapter(),
		clock:        defaultClock{},
		random:       defaultRandomSource{},
		serializer:   jsonSerializer{},
	}

	for _, opt := range opts {
		opt(s)
	}

	if s.legacyFormat == nil {
		return nil, ErrInvalidConfig
	}
	if !s.accessSet {
		s.accessFormat = s.legacyFormat
	}
	if s.accessFormat == nil {
		return nil, ErrInvalidConfig
	}
	if s.refreshSet {
		if s.refreshFormat == nil {
			return nil, ErrInvalidConfig
		}
	} else {
		if s.legacySet {
			s.claimsFormat = s.legacyFormat
		} else {
			s.claimsFormat = s.accessFormat
		}
	}
	if s.clock == nil || s.random == nil {
		return nil, ErrInvalidConfig
	}

	return s, nil
}

// IssueTokenPair 签发 Access/Refresh token 对。
func (s *Service) IssueTokenPair(ctx context.Context, req IssueRequest) (TokenPair, error) {
	if req.Subject == "" {
		return TokenPair{}, ErrInvalidConfig
	}

	now := s.clock.Now().UTC()
	accessID, err := s.random.NewID(s.config.TokenIDLength)
	if err != nil {
		return TokenPair{}, err
	}

	accessExp := now.Add(s.config.AccessTokenTTL)
	refreshExp := now.Add(s.config.RefreshTokenTTL)

	accessClaims := TokenClaims{
		TokenID:   accessID,
		TokenType: TokenTypeAccess,
		Subject:   req.Subject,
		IssuedAt:  now,
		ExpiresAt: accessExp,
		Version:   ModuleVersion,
	}
	accessToken, err := s.accessFormat.Encode(accessClaims)
	if err != nil {
		return TokenPair{}, err
	}

	var (
		refreshToken string
		refreshID    string
	)
	if s.refreshFormat != nil {
		refreshToken, refreshID, err = s.refreshFormat.Generate()
		if err != nil {
			return TokenPair{}, err
		}
	} else {
		refreshID, err = s.random.NewID(s.config.TokenIDLength)
		if err != nil {
			return TokenPair{}, err
		}
		refreshClaims := TokenClaims{
			TokenID:   refreshID,
			TokenType: TokenTypeRefresh,
			Subject:   req.Subject,
			IssuedAt:  now,
			ExpiresAt: refreshExp,
			Version:   ModuleVersion,
		}
		refreshToken, err = s.claimsFormat.Encode(refreshClaims)
		if err != nil {
			return TokenPair{}, err
		}
	}

	accessSession := AccessSession{
		TokenID:        accessID,
		Subject:        req.Subject,
		IssuedAt:       now,
		ExpiresAt:      accessExp,
		RefreshTokenID: refreshID,
		Metadata:       cloneMetadata(req.Metadata),
	}
	refreshSession := RefreshSession{
		TokenID:   refreshID,
		Subject:   req.Subject,
		IssuedAt:  now,
		ExpiresAt: refreshExp,
		Metadata:  cloneMetadata(req.Metadata),
	}

	if err := s.store.SaveRefreshSession(ctx, refreshID, refreshSession, ttlFrom(now, refreshExp)); err != nil {
		return TokenPair{}, err
	}
	if err := s.store.SaveAccessSession(ctx, accessID, accessSession, ttlFrom(now, accessExp)); err != nil {
		s.rollbackRefreshSession(ctx, refreshID)
		return TokenPair{}, err
	}

	return TokenPair{
		AccessToken:   accessToken,
		RefreshToken:  refreshToken,
		AccessExpiry:  accessExp,
		RefreshExpiry: refreshExp,
	}, nil
}

// ValidateAccessToken 校验 Access Token。
func (s *Service) ValidateAccessToken(ctx context.Context, token string) (ValidateResult, error) {
	claims, err := s.accessFormat.Decode(token)
	if err != nil {
		return ValidateResult{}, err
	}
	if claims.TokenType != TokenTypeAccess {
		return ValidateResult{}, ErrTokenTypeMismatch
	}
	if s.isExpired(claims.ExpiresAt) {
		return ValidateResult{}, ErrTokenExpired
	}

	session, err := s.store.GetAccessSession(ctx, claims.TokenID)
	if err != nil {
		if errors.Is(err, ErrSessionNotFound) {
			return ValidateResult{}, ErrTokenRevoked
		}
		return ValidateResult{}, err
	}

	if s.isExpired(session.ExpiresAt) {
		_ = s.store.DeleteAccessSession(ctx, claims.TokenID)
		return ValidateResult{}, ErrTokenExpired
	}
	if session.Subject != claims.Subject {
		return ValidateResult{}, ErrInvalidTokenFormat
	}

	if s.config.SlidingExpiration {
		_ = s.store.TouchAccessSession(ctx, claims.TokenID, s.config.SlidingExtensionTTL)
	}

	return ValidateResult{
		Subject:        session.Subject,
		AccessTokenID:  session.TokenID,
		RefreshTokenID: session.RefreshTokenID,
		Metadata:       cloneMetadata(session.Metadata),
		IssuedAt:       session.IssuedAt,
		ExpiresAt:      session.ExpiresAt,
	}, nil
}

// ValidateBearerHeader 解析并校验 Authorization: Bearer <token>。
func (s *Service) ValidateBearerHeader(ctx context.Context, authorization string) (ValidateResult, error) {
	token, err := ParseBearerToken(authorization)
	if err != nil {
		return ValidateResult{}, err
	}
	return s.ValidateAccessToken(ctx, token)
}

// RefreshAccessToken 使用 Refresh Token 换发新令牌。
func (s *Service) RefreshAccessToken(ctx context.Context, refreshToken string) (RefreshResult, error) {
	var (
		refreshSession RefreshSession
		refreshKey     string
	)

	if s.refreshFormat != nil {
		parsedID, err := s.refreshFormat.Parse(refreshToken)
		if err != nil {
			return RefreshResult{}, err
		}
		session, err := s.store.GetRefreshSession(ctx, parsedID)
		if err != nil {
			if errors.Is(err, ErrSessionNotFound) {
				if s.config.RefreshPolicy == RefreshPolicyOneTimeRotation {
					return RefreshResult{}, ErrRefreshTokenReplayed
				}
				return RefreshResult{}, ErrTokenRevoked
			}
			return RefreshResult{}, err
		}
		if s.isExpired(session.ExpiresAt) {
			_ = s.store.DeleteRefreshSession(ctx, parsedID)
			return RefreshResult{}, ErrTokenExpired
		}
		refreshSession = session
		refreshKey = parsedID
	} else {
		claims, err := s.claimsFormat.Decode(refreshToken)
		if err != nil {
			return RefreshResult{}, err
		}
		if claims.TokenType != TokenTypeRefresh {
			return RefreshResult{}, ErrTokenTypeMismatch
		}
		if s.isExpired(claims.ExpiresAt) {
			return RefreshResult{}, ErrTokenExpired
		}

		session, err := s.store.GetRefreshSession(ctx, claims.TokenID)
		if err != nil {
			if errors.Is(err, ErrSessionNotFound) {
				if s.config.RefreshPolicy == RefreshPolicyOneTimeRotation {
					return RefreshResult{}, ErrRefreshTokenReplayed
				}
				return RefreshResult{}, ErrTokenRevoked
			}
			return RefreshResult{}, err
		}
		if s.isExpired(session.ExpiresAt) {
			_ = s.store.DeleteRefreshSession(ctx, claims.TokenID)
			return RefreshResult{}, ErrTokenExpired
		}
		if session.Subject != claims.Subject {
			return RefreshResult{}, ErrInvalidTokenFormat
		}
		refreshSession = session
		refreshKey = claims.TokenID
	}

	now := s.clock.Now().UTC()
	accessID, err := s.random.NewID(s.config.TokenIDLength)
	if err != nil {
		return RefreshResult{}, err
	}
	accessExp := now.Add(s.config.AccessTokenTTL)

	accessClaims := TokenClaims{
		TokenID:   accessID,
		TokenType: TokenTypeAccess,
		Subject:   refreshSession.Subject,
		IssuedAt:  now,
		ExpiresAt: accessExp,
		Version:   ModuleVersion,
	}
	accessToken, err := s.accessFormat.Encode(accessClaims)
	if err != nil {
		return RefreshResult{}, err
	}

	rotated := false
	newRefreshToken := refreshToken
	newRefreshExp := refreshSession.ExpiresAt
	refreshTokenID := refreshKey

	if s.shouldRotateRefresh(now, refreshSession.ExpiresAt) {
		var (
			newRefreshTokenValue string
			newRefreshID         string
		)
		if s.refreshFormat != nil {
			newRefreshTokenValue, newRefreshID, err = s.refreshFormat.Generate()
			if err != nil {
				return RefreshResult{}, err
			}
		} else {
			newRefreshID, err = s.random.NewID(s.config.TokenIDLength)
			if err != nil {
				return RefreshResult{}, err
			}
			refreshClaims := TokenClaims{
				TokenID:   newRefreshID,
				TokenType: TokenTypeRefresh,
				Subject:   refreshSession.Subject,
				IssuedAt:  now,
				ExpiresAt: now.Add(s.config.RefreshTokenTTL),
				Version:   ModuleVersion,
			}
			newRefreshTokenValue, err = s.claimsFormat.Encode(refreshClaims)
			if err != nil {
				return RefreshResult{}, err
			}
		}

		newRefreshSession := RefreshSession{
			TokenID:   newRefreshID,
			Subject:   refreshSession.Subject,
			IssuedAt:  now,
			ExpiresAt: now.Add(s.config.RefreshTokenTTL),
			Metadata:  cloneMetadata(refreshSession.Metadata),
		}

		ok, rotateErr := s.store.RotateRefreshSession(
			ctx,
			refreshKey,
			newRefreshID,
			newRefreshSession,
			ttlFrom(now, newRefreshSession.ExpiresAt),
		)
		if rotateErr != nil {
			return RefreshResult{}, rotateErr
		}
		if !ok {
			if s.config.RefreshPolicy == RefreshPolicyOneTimeRotation {
				return RefreshResult{}, ErrRefreshTokenReplayed
			}
			return RefreshResult{}, ErrTokenRevoked
		}

		rotated = true
		newRefreshToken = newRefreshTokenValue
		newRefreshExp = newRefreshSession.ExpiresAt
		refreshTokenID = newRefreshID
	}

	accessSession := AccessSession{
		TokenID:        accessID,
		Subject:        refreshSession.Subject,
		IssuedAt:       now,
		ExpiresAt:      accessExp,
		RefreshTokenID: refreshTokenID,
		Metadata:       cloneMetadata(refreshSession.Metadata),
	}
	if err := s.store.SaveAccessSession(ctx, accessID, accessSession, ttlFrom(now, accessExp)); err != nil {
		return RefreshResult{}, err
	}

	return RefreshResult{
		AccessToken:   accessToken,
		RefreshToken:  newRefreshToken,
		AccessExpiry:  accessExp,
		RefreshExpiry: newRefreshExp,
		Rotated:       rotated,
	}, nil
}

// RevokeAccessToken 吊销 Access Token。
func (s *Service) RevokeAccessToken(ctx context.Context, token string) error {
	claims, err := s.accessFormat.Decode(token)
	if err != nil {
		return err
	}
	if claims.TokenType != TokenTypeAccess {
		return ErrTokenTypeMismatch
	}
	return s.store.DeleteAccessSession(ctx, claims.TokenID)
}

// RevokeRefreshToken 吊销 Refresh Token。
func (s *Service) RevokeRefreshToken(ctx context.Context, token string) error {
	if s.refreshFormat != nil {
		id, err := s.refreshFormat.Parse(token)
		if err != nil {
			return err
		}
		return s.store.DeleteRefreshSession(ctx, id)
	}

	claims, err := s.claimsFormat.Decode(token)
	if err != nil {
		return err
	}
	if claims.TokenType != TokenTypeRefresh {
		return ErrTokenTypeMismatch
	}
	return s.store.DeleteRefreshSession(ctx, claims.TokenID)
}

// RenewAccessToken 对活动 Access 会话执行续期。
func (s *Service) RenewAccessToken(ctx context.Context, token string, ttl time.Duration) error {
	claims, err := s.accessFormat.Decode(token)
	if err != nil {
		return err
	}
	if claims.TokenType != TokenTypeAccess {
		return ErrTokenTypeMismatch
	}
	if ttl <= 0 {
		ttl = s.config.AccessTokenTTL
	}
	return s.store.TouchAccessSession(ctx, claims.TokenID, ttl)
}

func (s *Service) shouldRotateRefresh(now, expiresAt time.Time) bool {
	switch s.config.RefreshPolicy {
	case RefreshPolicyOneTimeRotation:
		return true
	case RefreshPolicyRotateNearExpiry:
		remaining := expiresAt.Sub(now)
		return remaining <= s.config.RotateNearExpiry
	case RefreshPolicyReuseUntilExpiry:
		fallthrough
	default:
		return false
	}
}

func (s *Service) isExpired(exp time.Time) bool {
	now := s.clock.Now().UTC()
	return !exp.After(now.Add(-s.config.ClockSkew))
}

func ttlFrom(now, exp time.Time) time.Duration {
	ttl := exp.Sub(now)
	if ttl < 0 {
		return 0
	}
	return ttl
}

func cloneMetadata(metadata SessionMetadata) SessionMetadata {
	if len(metadata) == 0 {
		return nil
	}
	out := make(SessionMetadata, len(metadata))
	for k, v := range metadata {
		out[k] = v
	}
	return out
}

func (s *Service) rollbackRefreshSession(ctx context.Context, refreshID string) {
	if err := s.store.DeleteRefreshSession(ctx, refreshID); err != nil {
		if s.onRollbackFail != nil {
			s.onRollbackFail(ctx, "DeleteRefreshSession", refreshID, err)
		}
	}
}
