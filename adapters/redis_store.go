package adapters

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strconv"
	"strings"
	"time"

	"github.com/modern-magic-go/auth"
)

// RedisClient 定义 Redis 适配器所需的最小显式能力边界。
type RedisClient interface {
	Get(key string) (string, error)
	Setex(key, value string, seconds int) error
	Del(keys ...string) (int, error)
	Eval(script string, keys []string, args ...any) (any, error)
	Expire(key string, seconds int) error
}

// KeyStrategy 定义可注入的 Redis Key 策略，避免在通用模块硬编码项目规则。
type KeyStrategy interface {
	AccessKey(tokenID string) string
	RefreshKey(tokenID string) string
}

// PrefixedKeyStrategy 是默认前缀 key 策略。
type PrefixedKeyStrategy struct {
	Prefix string
}

// NewPrefixedKeyStrategy 创建默认前缀 key 策略。
func NewPrefixedKeyStrategy(prefix string) KeyStrategy {
	return PrefixedKeyStrategy{Prefix: prefix}
}

func (s PrefixedKeyStrategy) AccessKey(tokenID string) string {
	return s.Prefix + "access:" + tokenID
}

func (s PrefixedKeyStrategy) RefreshKey(tokenID string) string {
	return s.Prefix + "refresh:" + tokenID
}

// RedisStoreConfig 是 Redis 适配器配置。
type RedisStoreConfig struct {
	KeyStrategy KeyStrategy
	Serializer  auth.Serializer
}

// RedisStore 实现基于 Redis 的会话存储适配器。
type RedisStore struct {
	client      RedisClient
	keyStrategy KeyStrategy
	serializer  auth.Serializer
}

// NewRedisStore 创建 Redis 适配器。
func NewRedisStore(client RedisClient, cfg RedisStoreConfig) *RedisStore {
	serializer := cfg.Serializer
	if serializer == nil {
		serializer = redisJSONSerializer{}
	}
	keyStrategy := cfg.KeyStrategy
	if keyStrategy == nil {
		keyStrategy = NewPrefixedKeyStrategy("auth:")
	}
	return &RedisStore{
		client:      client,
		keyStrategy: keyStrategy,
		serializer:  serializer,
	}
}

func (s *RedisStore) SaveAccessSession(_ context.Context, tokenID string, session auth.AccessSession, ttl time.Duration) error {
	val, err := s.serializer.Marshal(session)
	if err != nil {
		return err
	}
	return s.client.Setex(s.keyStrategy.AccessKey(tokenID), val, seconds(ttl))
}

func (s *RedisStore) SaveRefreshSession(_ context.Context, tokenID string, session auth.RefreshSession, ttl time.Duration) error {
	val, err := s.serializer.Marshal(session)
	if err != nil {
		return err
	}
	return s.client.Setex(s.keyStrategy.RefreshKey(tokenID), val, seconds(ttl))
}

func (s *RedisStore) GetAccessSession(_ context.Context, tokenID string) (auth.AccessSession, error) {
	val, err := s.client.Get(s.keyStrategy.AccessKey(tokenID))
	if isRedisNil(err) || val == "" {
		return auth.AccessSession{}, auth.ErrSessionNotFound
	}
	if err != nil {
		return auth.AccessSession{}, err
	}
	var session auth.AccessSession
	if err := s.serializer.Unmarshal(val, &session); err != nil {
		return auth.AccessSession{}, err
	}
	return session, nil
}

func (s *RedisStore) GetRefreshSession(_ context.Context, tokenID string) (auth.RefreshSession, error) {
	val, err := s.client.Get(s.keyStrategy.RefreshKey(tokenID))
	if isRedisNil(err) || val == "" {
		return auth.RefreshSession{}, auth.ErrSessionNotFound
	}
	if err != nil {
		return auth.RefreshSession{}, err
	}
	var session auth.RefreshSession
	if err := s.serializer.Unmarshal(val, &session); err != nil {
		return auth.RefreshSession{}, err
	}
	return session, nil
}

func (s *RedisStore) DeleteAccessSession(_ context.Context, tokenID string) error {
	_, err := s.client.Del(s.keyStrategy.AccessKey(tokenID))
	return err
}

func (s *RedisStore) DeleteRefreshSession(_ context.Context, tokenID string) error {
	_, err := s.client.Del(s.keyStrategy.RefreshKey(tokenID))
	return err
}

func (s *RedisStore) RotateRefreshSession(_ context.Context, oldTokenID, newTokenID string, newSession auth.RefreshSession, ttl time.Duration) (bool, error) {
	val, err := s.serializer.Marshal(newSession)
	if err != nil {
		return false, err
	}

	oldKey := s.keyStrategy.RefreshKey(oldTokenID)
	newKey := s.keyStrategy.RefreshKey(newTokenID)
	result, err := s.client.Eval(
		`if redis.call("GET", KEYS[1]) then
    redis.call("DEL", KEYS[1])
    redis.call("SETEX", KEYS[2], ARGV[2], ARGV[1])
    return 1
else
    return 0
end`,
		[]string{oldKey, newKey},
		val,
		seconds(ttl),
	)
	if err != nil {
		return false, err
	}
	return toBool(result)
}

func (s *RedisStore) TouchAccessSession(_ context.Context, tokenID string, ttl time.Duration) error {
	if ttl <= 0 {
		return nil
	}
	key := s.keyStrategy.AccessKey(tokenID)
	if err := s.client.Expire(key, seconds(ttl)); err != nil {
		if isRedisNil(err) {
			return auth.ErrSessionNotFound
		}
		return err
	}
	return nil
}

type redisJSONSerializer struct{}

func (redisJSONSerializer) Marshal(v any) (string, error) {
	b, err := json.Marshal(v)
	if err != nil {
		return "", err
	}
	return string(b), nil
}

func (redisJSONSerializer) Unmarshal(data string, v any) error {
	if err := json.Unmarshal([]byte(data), v); err != nil {
		return fmt.Errorf("unmarshal json: %w", err)
	}
	return nil
}

func seconds(ttl time.Duration) int {
	if ttl <= 0 {
		return 1
	}
	sec := int(ttl.Seconds())
	if sec <= 0 {
		return 1
	}
	return sec
}

func toBool(v any) (bool, error) {
	s := fmt.Sprint(v)
	s = strings.TrimSpace(strings.TrimPrefix(strings.TrimPrefix(s, "("), "["))
	s = strings.TrimSuffix(strings.TrimSuffix(s, ")"), "]")
	i, err := strconv.ParseInt(s, 10, 64)
	if err != nil {
		return false, err
	}
	return i == 1, nil
}

func isRedisNil(err error) bool {
	if err == nil {
		return false
	}
	if errors.Is(err, auth.ErrSessionNotFound) {
		return true
	}
	return strings.Contains(err.Error(), "redis: nil")
}
