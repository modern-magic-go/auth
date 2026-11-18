package adapters

import (
	"context"
	"sync"
	"time"

	"github.com/modern-magic-go/auth"
)

// MemoryRevocationStore 是用于测试与轻量场景的吊销存储。
type MemoryRevocationStore struct {
	mu       sync.Mutex
	sessions map[string]time.Time
	subjects map[string]time.Time
}

// NewMemoryRevocationStore 创建内存吊销存储。
func NewMemoryRevocationStore() *MemoryRevocationStore {
	return &MemoryRevocationStore{
		sessions: make(map[string]time.Time),
		subjects: make(map[string]time.Time),
	}
}

// RevokeSession 吊销一个会话 ID。
func (s *MemoryRevocationStore) RevokeSession(_ context.Context, sessionID string, ttl time.Duration) error {
	if sessionID == "" {
		return auth.ErrInvalidConfig
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.sessions[sessionID] = time.Now().UTC().Add(ttl)
	return nil
}

// RevokeSubject 吊销一个 subject 的全部会话。
func (s *MemoryRevocationStore) RevokeSubject(_ context.Context, subject string, ttl time.Duration) error {
	if subject == "" {
		return auth.ErrInvalidConfig
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.subjects[subject] = time.Now().UTC().Add(ttl)
	return nil
}

// IsRevoked 检查 session 或 subject 是否在吊销状态。
func (s *MemoryRevocationStore) IsRevoked(_ context.Context, sessionID, subject string) (bool, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	now := time.Now().UTC()
	if expire, ok := s.sessions[sessionID]; ok {
		if now.Before(expire) {
			return true, nil
		}
		delete(s.sessions, sessionID)
	}
	if expire, ok := s.subjects[subject]; ok {
		if now.Before(expire) {
			return true, nil
		}
		delete(s.subjects, subject)
	}
	return false, nil
}
