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
	format         TokenFormatAdapter
	clock          Clock
	random         RandomSource
	serializer     Serializer
	onRollbackFail func(ctx context.Context, op string, tokenID string, err error)
}

// Option 用于可选依赖注入。
type Option func(*Service)

// WithTokenFormat 指定自定义 token 格式适配器。
func WithTokenFormat(format TokenFormatAdapter) Option {
	return func(s *Service) {
		s.format = format
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
		config:     cfg.Normalize(),
		store:      store,
		format:     NewDefaultTokenFormatAdapter(),
		clock:      defaultClock{},
		random:     defaultRandomSource{},
		serializer: jsonSerializer{},
	}

	for _, opt := range opts {
		opt(s)
	}

	if s.format == nil || s.clock == nil || s.random == nil {
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
	refreshID, err := s.random.NewID(s.config.TokenIDLength)
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
	refreshClaims := TokenClaims{
		TokenID:   refreshID,
		TokenType: TokenTypeRefresh,
		Subject:   req.Subject,
		IssuedAt:  now,
		ExpiresAt: refreshExp,
		Version:   ModuleVersion,
	}

	accessToken, err := s.format.Encode(accessClaims)
	if err != nil {
		return TokenPair{}, err
	}
	refreshToken, err := s.format.Encode(refreshClaims)
	if err != nil {
		return TokenPair{}, err
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
	claims, err := s.format.Decode(token)
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
	claims, err := s.format.Decode(refreshToken)
	if err != nil {
		return RefreshResult{}, err
	}
	if claims.TokenType != TokenTypeRefresh {
		return RefreshResult{}, ErrTokenTypeMismatch
	}
	if s.isExpired(claims.ExpiresAt) {
		return RefreshResult{}, ErrTokenExpired
	}

	refreshSession, err := s.store.GetRefreshSession(ctx, claims.TokenID)
	if err != nil {
		if errors.Is(err, ErrSessionNotFound) {
			if s.config.RefreshPolicy == RefreshPolicyOneTimeRotation {
				return RefreshResult{}, ErrRefreshTokenReplayed
			}
			return RefreshResult{}, ErrTokenRevoked
		}
		return RefreshResult{}, err
	}

	if s.isExpired(refreshSession.ExpiresAt) {
		_ = s.store.DeleteRefreshSession(ctx, claims.TokenID)
		return RefreshResult{}, ErrTokenExpired
	}
	if refreshSession.Subject != claims.Subject {
		return RefreshResult{}, ErrInvalidTokenFormat
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
	accessToken, err := s.format.Encode(accessClaims)
	if err != nil {
		return RefreshResult{}, err
	}

	rotated := false
	newRefreshToken := refreshToken
	newRefreshExp := refreshSession.ExpiresAt
	refreshTokenID := refreshSession.TokenID

	if s.shouldRotateRefresh(now, refreshSession.ExpiresAt) {
		newRefreshID, genErr := s.random.NewID(s.config.TokenIDLength)
		if genErr != nil {
			return RefreshResult{}, genErr
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
			refreshSession.TokenID,
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

		refreshClaims := TokenClaims{
			TokenID:   newRefreshID,
			TokenType: TokenTypeRefresh,
			Subject:   refreshSession.Subject,
			IssuedAt:  newRefreshSession.IssuedAt,
			ExpiresAt: newRefreshSession.ExpiresAt,
			Version:   ModuleVersion,
		}
		encodedRefresh, encodeErr := s.format.Encode(refreshClaims)
		if encodeErr != nil {
			return RefreshResult{}, encodeErr
		}

		rotated = true
		newRefreshToken = encodedRefresh
		newRefreshExp = newRefreshSession.ExpiresAt
		refreshTokenID = newRefreshID
	} else if s.config.RefreshPolicy == RefreshPolicyReuseUntilExpiry || s.config.RefreshPolicy == RefreshPolicyRotateNearExpiry {
		// reuse 模式不轮换时保持原 refresh session。
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
	claims, err := s.format.Decode(token)
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
	claims, err := s.format.Decode(token)
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
	claims, err := s.format.Decode(token)
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
