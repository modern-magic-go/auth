package adapters

import (
	"context"
	"time"

	"github.com/modern-magic-go/auth"
)

// RedisRevocationStore 是基于 Redis 的 SID / subject 吊销存储。
type RedisRevocationStore struct {
	client RedisClient
	keys   ExtendedKeyStrategy
}

// NewRedisRevocationStore 创建 Redis 吊销存储。
func NewRedisRevocationStore(client RedisClient, keys ExtendedKeyStrategy) *RedisRevocationStore {
	if keys == nil {
		keys = NewPrefixedKeyStrategy("auth:")
	}
	return &RedisRevocationStore{client: client, keys: keys}
}

// RevokeSession 写入 session 级吊销标记。
func (s *RedisRevocationStore) RevokeSession(_ context.Context, sessionID string, ttl time.Duration) error {
	return s.client.Setex(s.keys.RevokedSessionKey(sessionID), "1", seconds(ttl))
}

// RevokeSubject 写入 subject 级吊销标记。
func (s *RedisRevocationStore) RevokeSubject(_ context.Context, subject string, ttl time.Duration) error {
	return s.client.Setex(s.keys.RevokedSubjectKey(subject), "1", seconds(ttl))
}

// IsRevoked 检查 session 或 subject 是否被吊销。
func (s *RedisRevocationStore) IsRevoked(_ context.Context, sessionID, subject string) (bool, error) {
	for _, key := range []string{
		s.keys.RevokedSessionKey(sessionID),
		s.keys.RevokedSubjectKey(subject),
	} {
		value, err := s.client.Get(key)
		if isRedisNil(err) || value == "" {
			continue
		}
		if err != nil {
			return false, err
		}
		return true, nil
	}
	return false, nil
}

var _ auth.RevocationStore = (*RedisRevocationStore)(nil)
