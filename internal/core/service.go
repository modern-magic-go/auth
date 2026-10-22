package core

import (
	"context"
	"errors"
	"time"
)

// Service 提供框架无关的认证核心能力。
type Service struct {
	config          Config
	store           SessionStore
	accessFormat    TokenFormatAdapter
	claimsFormat    TokenFormatAdapter
	refreshFormat   RefreshTokenFormat
	legacyFormat    TokenFormatAdapter
	legacySet       bool
	accessSet       bool
	refreshSet      bool
	revocationStore RevocationStore
	indexedStore    IndexedSessionStore
	graceStore      RefreshGraceStore
	graceRotation   GraceRotationStore
	graceKey        []byte
	onEviction      func(ctx context.Context, evicted []SessionRef)
	clock           Clock
	random          RandomSource
	serializer      Serializer
	onRollbackFail  func(ctx context.Context, op string, tokenID string, err error)
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

// WithSerializer 指定序列化适配边界。
func WithSerializer(serializer Serializer) Option {
	return func(s *Service) {
		s.serializer = serializer
	}
}

// WithRevocationStore 注入 SID / subject 级吊销存储。
func WithRevocationStore(store RevocationStore) Option {
	return func(s *Service) {
		s.revocationStore = store
	}
}

// WithSessionEvictionHandler 在 maxOnline 裁剪掉旧会话时回调。
func WithSessionEvictionHandler(handler func(ctx context.Context, evicted []SessionRef)) Option {
	return func(s *Service) {
		s.onEviction = handler
	}
}

// WithGraceEncryptionKey 设置 refresh grace 记录中 token 的加密密钥。
// 开启 RefreshGracePeriod 时必须提供 32 字节密钥。
func WithGraceEncryptionKey(key []byte) Option {
	return func(s *Service) {
		s.graceKey = append([]byte(nil), key...)
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
	if s.refreshSet && !s.accessSet && !s.legacySet {
		// 只配置 refresh 格式会让 access 静默退回无签名默认格式；
		// 要求调用方显式选择 access 格式，避免 stateful 下误发非 JWT token。
		return nil, ErrInvalidConfig
	}
	if s.config.AccessTokenMode != AccessTokenStateful && s.config.AccessTokenMode != AccessTokenStateless {
		return nil, ErrInvalidConfig
	}
	if s.config.AccessTokenMode == AccessTokenStateless {
		signing, ok := s.accessFormat.(SigningFormat)
		if !ok || !signing.IsSigned() || s.config.SlidingExpiration {
			return nil, ErrInvalidConfig
		}
	}
	if s.config.RotateNearExpiryRatio > 1 {
		return nil, ErrInvalidConfig
	}
	if s.config.MaxSessionsPerSubject > 0 {
		indexed, ok := store.(IndexedSessionStore)
		if !ok {
			return nil, ErrInvalidConfig
		}
		s.indexedStore = indexed
	}
	if s.config.RefreshGracePeriod > 0 {
		graceStore, graceOK := store.(RefreshGraceStore)
		graceRotation, rotationOK := store.(GraceRotationStore)
		if !graceOK || !rotationOK || len(s.graceKey) != 32 {
			return nil, ErrInvalidConfig
		}
		s.graceStore = graceStore
		s.graceRotation = graceRotation
	}

	return s, nil
}

// IssueTokenPair 签发 Access/Refresh token 对。
func (s *Service) IssueTokenPair(ctx context.Context, req IssueRequest) (TokenPair, error) {
	if req.Subject == "" {
		return TokenPair{}, ErrInvalidConfig
	}
	if err := validateExtraClaims(req.ExtraClaims); err != nil {
		return TokenPair{}, err
	}

	version := s.tokenVersion(req.Version)
	sessionID := req.SessionID
	if sessionID == "" {
		generated, err := s.random.NewID(s.config.TokenIDLength)
		if err != nil {
			return TokenPair{}, err
		}
		sessionID = generated
	}

	now := s.clock.Now().UTC()
	accessID, err := s.random.NewID(s.config.TokenIDLength)
	if err != nil {
		return TokenPair{}, err
	}

	accessExp := now.Add(s.config.AccessTokenTTL)
	refreshExp := now.Add(s.config.RefreshTokenTTL)

	accessClaims := TokenClaims{
		TokenID:     accessID,
		TokenType:   TokenTypeAccess,
		Subject:     req.Subject,
		IssuedAt:    now,
		ExpiresAt:   accessExp,
		Version:     version,
		SessionID:   sessionID,
		ExtraClaims: cloneExtraClaims(req.ExtraClaims),
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
			TokenID:     refreshID,
			TokenType:   TokenTypeRefresh,
			Subject:     req.Subject,
			IssuedAt:    now,
			ExpiresAt:   refreshExp,
			Version:     version,
			SessionID:   sessionID,
			ExtraClaims: cloneExtraClaims(req.ExtraClaims),
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
		SessionID:      sessionID,
		TokenVersion:   version,
		ExtraClaims:    cloneMetadata(req.ExtraClaims),
		Metadata:       cloneMetadata(req.Metadata),
	}
	refreshSession := RefreshSession{
		TokenID:      refreshID,
		Subject:      req.Subject,
		IssuedAt:     now,
		ExpiresAt:    refreshExp,
		SessionID:    sessionID,
		TokenVersion: version,
		ExtraClaims:  cloneMetadata(req.ExtraClaims),
		Metadata:     cloneMetadata(req.Metadata),
	}

	if s.indexedStore != nil {
		evicted, err := s.indexedStore.CreateSession(
			ctx,
			accessSession,
			refreshSession,
			ttlFrom(now, accessExp),
			ttlFrom(now, refreshExp),
			s.config.MaxSessionsPerSubject,
		)
		if err != nil {
			return TokenPair{}, err
		}
		s.handleEvictedSessions(ctx, evicted)
	} else {
		if err := s.store.SaveRefreshSession(ctx, refreshID, refreshSession, ttlFrom(now, refreshExp)); err != nil {
			return TokenPair{}, err
		}
		if err := s.store.SaveAccessSession(ctx, accessID, accessSession, ttlFrom(now, accessExp)); err != nil {
			s.rollbackRefreshSession(ctx, refreshID)
			return TokenPair{}, err
		}
	}

	return TokenPair{
		AccessToken:   accessToken,
		RefreshToken:  refreshToken,
		AccessExpiry:  accessExp,
		RefreshExpiry: refreshExp,
		SessionID:     sessionID,
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

	if s.config.AccessTokenMode == AccessTokenStateless {
		if err := s.checkRevoked(ctx, claims.SessionID, claims.Subject); err != nil {
			return ValidateResult{}, err
		}
		return ValidateResult{
			Subject:       claims.Subject,
			AccessTokenID: claims.TokenID,
			SessionID:     claims.SessionID,
			Version:       claims.Version,
			ExtraClaims:   cloneExtraClaims(claims.ExtraClaims),
			IssuedAt:      claims.IssuedAt,
			ExpiresAt:     claims.ExpiresAt,
		}, nil
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

	sessionID := session.SessionID
	if sessionID == "" {
		sessionID = claims.SessionID
	}
	if err := s.checkRevoked(ctx, sessionID, session.Subject); err != nil {
		return ValidateResult{}, err
	}

	if s.config.SlidingExpiration {
		_ = s.store.TouchAccessSession(ctx, claims.TokenID, s.config.SlidingExtensionTTL)
	}

	extraClaims := session.ExtraClaims
	if len(extraClaims) == 0 {
		extraClaims = claims.ExtraClaims
	}
	version := session.TokenVersion
	if version == "" {
		version = claims.Version
	}

	return ValidateResult{
		Subject:        session.Subject,
		AccessTokenID:  session.TokenID,
		RefreshTokenID: session.RefreshTokenID,
		SessionID:      sessionID,
		Version:        version,
		Metadata:       cloneMetadata(session.Metadata),
		ExtraClaims:    cloneExtraClaims(extraClaims),
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
		refreshClaims  TokenClaims
	)

	if s.refreshFormat != nil {
		parsedID, err := s.refreshFormat.Parse(refreshToken)
		if err != nil {
			return RefreshResult{}, err
		}
		session, err := s.store.GetRefreshSession(ctx, parsedID)
		if err != nil {
			if errors.Is(err, ErrSessionNotFound) {
				if result, ok, graceErr := s.replayFromGrace(ctx, refreshToken, parsedID); graceErr != nil {
					return RefreshResult{}, graceErr
				} else if ok {
					return result, nil
				}
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
				if result, ok, graceErr := s.replayFromGrace(ctx, refreshToken, claims.TokenID); graceErr != nil {
					return RefreshResult{}, graceErr
				} else if ok {
					return result, nil
				}
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
		refreshClaims = claims
	}

	sessionID := refreshSession.SessionID
	if sessionID == "" {
		sessionID = refreshClaims.SessionID
	}
	extraClaims := refreshSession.ExtraClaims
	if len(extraClaims) == 0 {
		extraClaims = refreshClaims.ExtraClaims
	}
	version := refreshSession.TokenVersion
	if version == "" {
		version = refreshClaims.Version
	}
	if version == "" {
		version = s.tokenVersion("")
	}
	if err := s.checkRevoked(ctx, sessionID, refreshSession.Subject); err != nil {
		return RefreshResult{}, err
	}

	now := s.clock.Now().UTC()
	accessID, err := s.random.NewID(s.config.TokenIDLength)
	if err != nil {
		return RefreshResult{}, err
	}
	accessExp := now.Add(s.config.AccessTokenTTL)

	accessClaims := TokenClaims{
		TokenID:     accessID,
		TokenType:   TokenTypeAccess,
		Subject:     refreshSession.Subject,
		IssuedAt:    now,
		ExpiresAt:   accessExp,
		Version:     version,
		SessionID:   sessionID,
		ExtraClaims: cloneExtraClaims(extraClaims),
	}
	accessToken, err := s.accessFormat.Encode(accessClaims)
	if err != nil {
		return RefreshResult{}, err
	}

	rotated := false
	newRefreshToken := refreshToken
	newRefreshExp := refreshSession.ExpiresAt
	refreshTokenID := refreshKey

	if s.shouldRotateRefresh(now, refreshSession.IssuedAt, refreshSession.ExpiresAt) {
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
				TokenID:     newRefreshID,
				TokenType:   TokenTypeRefresh,
				Subject:     refreshSession.Subject,
				IssuedAt:    now,
				ExpiresAt:   now.Add(s.config.RefreshTokenTTL),
				Version:     version,
				SessionID:   sessionID,
				ExtraClaims: cloneExtraClaims(extraClaims),
			}
			newRefreshTokenValue, err = s.claimsFormat.Encode(refreshClaims)
			if err != nil {
				return RefreshResult{}, err
			}
		}

		newRefreshSession := RefreshSession{
			TokenID:      newRefreshID,
			Subject:      refreshSession.Subject,
			IssuedAt:     now,
			ExpiresAt:    now.Add(s.config.RefreshTokenTTL),
			SessionID:    sessionID,
			TokenVersion: version,
			ExtraClaims:  cloneExtraClaims(extraClaims),
			Metadata:     cloneMetadata(refreshSession.Metadata),
		}

		var ok bool
		switch {
		case s.graceRotation != nil:
			record, recordErr := s.buildGraceRecord(ctx, refreshKey, newRefreshID, sessionID, refreshSession.Subject, accessToken, newRefreshTokenValue, accessExp, newRefreshSession.ExpiresAt)
			if recordErr != nil {
				return RefreshResult{}, recordErr
			}
			ok, err = s.graceRotation.RotateRefreshSessionWithGrace(
				ctx,
				refreshKey,
				newRefreshSession,
				record,
				ttlFrom(now, newRefreshSession.ExpiresAt),
				s.config.RefreshGracePeriod,
			)
		case s.indexedStore != nil:
			newRef := SessionRef{
				SessionID:      sessionID,
				Subject:        refreshSession.Subject,
				AccessTokenID:  accessID,
				RefreshTokenID: newRefreshID,
				IssuedAt:       refreshSession.IssuedAt,
				ExpiresAt:      newRefreshSession.ExpiresAt,
			}
			ok, err = s.indexedStore.RotateRefreshSessionWithIndex(
				ctx,
				refreshKey,
				newRefreshSession,
				newRef,
				ttlFrom(now, newRefreshSession.ExpiresAt),
			)
		default:
			ok, err = s.store.RotateRefreshSession(
				ctx,
				refreshKey,
				newRefreshID,
				newRefreshSession,
				ttlFrom(now, newRefreshSession.ExpiresAt),
			)
		}
		if err != nil {
			return RefreshResult{}, err
		}
		if !ok {
			if result, graceOK, graceErr := s.replayFromGrace(ctx, refreshToken, refreshKey); graceErr != nil {
				return RefreshResult{}, graceErr
			} else if graceOK {
				return result, nil
			}
			if s.config.RefreshPolicy == RefreshPolicyOneTimeRotation {
				return RefreshResult{}, ErrRefreshTokenReplayed
			}
			return RefreshResult{}, ErrTokenRevoked
		}
		if s.indexedStore != nil && s.graceRotation != nil {
			newRef := SessionRef{
				SessionID:      sessionID,
				Subject:        refreshSession.Subject,
				AccessTokenID:  accessID,
				RefreshTokenID: newRefreshID,
				IssuedAt:       refreshSession.IssuedAt,
				ExpiresAt:      newRefreshSession.ExpiresAt,
			}
			if err := s.indexedStore.TouchSession(ctx, newRef, ttlFrom(now, newRefreshSession.ExpiresAt)); err != nil {
				return RefreshResult{}, err
			}
		}

		rotated = true
		newRefreshToken = newRefreshTokenValue
		newRefreshExp = newRefreshSession.ExpiresAt
		refreshTokenID = newRefreshID
	} else if s.indexedStore != nil {
		ref := SessionRef{
			SessionID:      sessionID,
			Subject:        refreshSession.Subject,
			AccessTokenID:  accessID,
			RefreshTokenID: refreshTokenID,
			IssuedAt:       refreshSession.IssuedAt,
			ExpiresAt:      refreshSession.ExpiresAt,
		}
		if err := s.indexedStore.TouchSession(ctx, ref, ttlFrom(now, refreshSession.ExpiresAt)); err != nil {
			return RefreshResult{}, err
		}
	}

	accessSession := AccessSession{
		TokenID:        accessID,
		Subject:        refreshSession.Subject,
		IssuedAt:       now,
		ExpiresAt:      accessExp,
		RefreshTokenID: refreshTokenID,
		SessionID:      sessionID,
		TokenVersion:   version,
		ExtraClaims:    cloneExtraClaims(extraClaims),
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
		SessionID:     sessionID,
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
	if s.config.AccessTokenMode == AccessTokenStateless {
		if s.revocationStore == nil {
			return ErrRevocationNotConfigured
		}
		if claims.SessionID == "" {
			return ErrSessionIDRequired
		}
		return s.RevokeSession(ctx, claims.SessionID, 0)
	}
	return s.store.DeleteAccessSession(ctx, claims.TokenID)
}

// RevokeRefreshToken 吊销 Refresh Token；若是已轮换的旧 token，会跟进 grace 记录。
func (s *Service) RevokeRefreshToken(ctx context.Context, token string) error {
	refreshKey, err := s.parseRefreshID(token)
	if err != nil {
		return err
	}

	graceKey := ""
	session, getErr := s.store.GetRefreshSession(ctx, refreshKey)
	if getErr != nil && errors.Is(getErr, ErrSessionNotFound) && s.graceStore != nil {
		if record, graceErr := s.graceStore.GetRefreshGrace(ctx, refreshKey); graceErr == nil {
			graceKey = refreshKey
			refreshKey = record.NewTokenID
			session, getErr = s.store.GetRefreshSession(ctx, refreshKey)
		}
	}
	if getErr != nil && !errors.Is(getErr, ErrSessionNotFound) {
		return getErr
	}
	if err := s.store.DeleteRefreshSession(ctx, refreshKey); err != nil {
		return err
	}
	if graceKey != "" {
		_ = s.graceStore.DeleteRefreshGrace(ctx, graceKey)
	}
	if getErr == nil && s.indexedStore != nil && session.SessionID != "" {
		return s.indexedStore.RemoveSession(ctx, session.Subject, session.SessionID)
	}
	return nil
}

// Logout 完整注销一个会话：清理 session/索引并写入 denylist。
func (s *Service) Logout(ctx context.Context, token string, ttl time.Duration) error {
	if claims, err := s.accessFormat.Decode(token); err == nil && claims.TokenType == TokenTypeAccess {
		return s.logoutAccess(ctx, claims, ttl)
	}
	if s.refreshFormat != nil {
		if id, err := s.refreshFormat.Parse(token); err == nil {
			return s.logoutRefresh(ctx, id, ttl)
		}
	} else if claims, err := s.claimsFormat.Decode(token); err == nil && claims.TokenType == TokenTypeRefresh {
		return s.logoutRefresh(ctx, claims.TokenID, ttl)
	}
	return ErrInvalidTokenFormat
}

func (s *Service) logoutAccess(ctx context.Context, claims TokenClaims, ttl time.Duration) error {
	if s.config.AccessTokenMode == AccessTokenStateless && claims.SessionID == "" {
		return ErrSessionIDRequired
	}
	if claims.SessionID != "" && s.revocationStore != nil {
		if err := s.RevokeSession(ctx, claims.SessionID, ttl); err != nil {
			return err
		}
	}
	if s.indexedStore != nil && claims.SessionID != "" {
		return s.indexedStore.RemoveSession(ctx, claims.Subject, claims.SessionID)
	}

	session, getErr := s.store.GetAccessSession(ctx, claims.TokenID)
	if getErr != nil && !errors.Is(getErr, ErrSessionNotFound) {
		return getErr
	}
	if err := s.store.DeleteAccessSession(ctx, claims.TokenID); err != nil {
		return err
	}
	if getErr == nil && session.RefreshTokenID != "" {
		return s.store.DeleteRefreshSession(ctx, session.RefreshTokenID)
	}
	if s.config.AccessTokenMode == AccessTokenStateless && s.revocationStore == nil {
		return ErrRevocationNotConfigured
	}
	return nil
}

func (s *Service) logoutRefresh(ctx context.Context, refreshKey string, ttl time.Duration) error {
	session, getErr := s.store.GetRefreshSession(ctx, refreshKey)
	graceKey := ""
	if getErr != nil && errors.Is(getErr, ErrSessionNotFound) && s.graceStore != nil {
		if record, graceErr := s.graceStore.GetRefreshGrace(ctx, refreshKey); graceErr == nil {
			graceKey = refreshKey
			refreshKey = record.NewTokenID
			session, getErr = s.store.GetRefreshSession(ctx, refreshKey)
		}
	}
	if getErr != nil && !errors.Is(getErr, ErrSessionNotFound) {
		return getErr
	}
	if session.SessionID != "" && s.revocationStore != nil {
		if err := s.RevokeSession(ctx, session.SessionID, ttl); err != nil {
			return err
		}
	}
	if err := s.store.DeleteRefreshSession(ctx, refreshKey); err != nil {
		return err
	}
	if graceKey != "" {
		_ = s.graceStore.DeleteRefreshGrace(ctx, graceKey)
	}
	if s.indexedStore != nil && session.SessionID != "" {
		return s.indexedStore.RemoveSession(ctx, session.Subject, session.SessionID)
	}
	return nil
}

func (s *Service) parseRefreshID(token string) (string, error) {
	if s.refreshFormat != nil {
		return s.refreshFormat.Parse(token)
	}
	claims, err := s.claimsFormat.Decode(token)
	if err != nil {
		return "", err
	}
	if claims.TokenType != TokenTypeRefresh {
		return "", ErrTokenTypeMismatch
	}
	return claims.TokenID, nil
}

// RevokeSession 按稳定 SessionID 吊销一个会话（需要 RevocationStore）。
func (s *Service) RevokeSession(ctx context.Context, sessionID string, ttl time.Duration) error {
	if s.revocationStore == nil {
		return ErrRevocationNotConfigured
	}
	if sessionID == "" {
		return ErrSessionIDRequired
	}
	if ttl <= 0 {
		ttl = s.defaultRevocationTTL()
	}
	return s.revocationStore.RevokeSession(ctx, sessionID, ttl)
}

// RevokeSubject 按 Subject 吊销全部会话（需要 RevocationStore）。
func (s *Service) RevokeSubject(ctx context.Context, subject string, ttl time.Duration) error {
	if s.revocationStore == nil {
		return ErrRevocationNotConfigured
	}
	if subject == "" {
		return ErrInvalidConfig
	}
	if s.indexedStore != nil {
		refs, err := s.indexedStore.ListBySubject(ctx, subject)
		if err != nil {
			return err
		}
		for _, ref := range refs {
			if err := s.indexedStore.RemoveSession(ctx, subject, ref.SessionID); err != nil {
				return err
			}
		}
	}
	if ttl <= 0 {
		ttl = s.defaultRevocationTTL()
	}
	return s.revocationStore.RevokeSubject(ctx, subject, ttl)
}

// RenewAccessToken 对活动 Access 会话执行续期。
func (s *Service) RenewAccessToken(ctx context.Context, token string, ttl time.Duration) error {
	if s.config.AccessTokenMode == AccessTokenStateless {
		return ErrUnsupportedMode
	}
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

func (s *Service) tokenVersion(override string) string {
	if override != "" {
		return override
	}
	if s.config.TokenVersion != "" {
		return s.config.TokenVersion
	}
	return ModuleVersion
}

func (s *Service) checkRevoked(ctx context.Context, sessionID, subject string) error {
	if s.revocationStore == nil {
		return nil
	}
	revoked, err := s.revocationStore.IsRevoked(ctx, sessionID, subject)
	if err != nil {
		return err
	}
	if revoked {
		return ErrTokenRevoked
	}
	return nil
}

func (s *Service) defaultRevocationTTL() time.Duration {
	ttl := s.config.AccessTokenTTL
	if s.config.RefreshTokenTTL > ttl {
		ttl = s.config.RefreshTokenTTL
	}
	return ttl + s.config.ClockSkew
}

func (s *Service) handleEvictedSessions(ctx context.Context, evicted []SessionRef) {
	for _, ref := range evicted {
		if ref.AccessTokenID != "" {
			_ = s.store.DeleteAccessSession(ctx, ref.AccessTokenID)
		}
		if ref.RefreshTokenID != "" {
			_ = s.store.DeleteRefreshSession(ctx, ref.RefreshTokenID)
		}
	}
	if s.onEviction != nil && len(evicted) > 0 {
		s.onEviction(ctx, evicted)
	}
}

func (s *Service) shouldRotateRefresh(now, issuedAt, expiresAt time.Time) bool {
	switch s.config.RefreshPolicy {
	case RefreshPolicyOneTimeRotation:
		return true
	case RefreshPolicyRotateNearExpiry:
		threshold := s.config.RotateNearExpiry
		if s.config.RotateNearExpiryRatio > 0 {
			threshold = time.Duration(float64(expiresAt.Sub(issuedAt)) * s.config.RotateNearExpiryRatio)
		}
		return expiresAt.Sub(now) <= threshold
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
