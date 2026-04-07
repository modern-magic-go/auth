package adapters

import (
	"context"
	"sync"
	"time"

	"github.com/modern-magic-go/auth"
)

type memoryAccessEntry struct {
	session auth.AccessSession
	expire  time.Time
}

type memoryRefreshEntry struct {
	session auth.RefreshSession
	expire  time.Time
}

// MemoryStore 是用于测试与轻量场景的内存会话适配器。
type MemoryStore struct {
	mu      sync.RWMutex
	access  map[string]memoryAccessEntry
	refresh map[string]memoryRefreshEntry
}

// NewMemoryStore 创建内存适配器。
func NewMemoryStore() *MemoryStore {
	return &MemoryStore{
		access:  make(map[string]memoryAccessEntry),
		refresh: make(map[string]memoryRefreshEntry),
	}
}

func (m *MemoryStore) SaveAccessSession(_ context.Context, tokenID string, session auth.AccessSession, ttl time.Duration) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.access[tokenID] = memoryAccessEntry{session: session, expire: expiresAtFromTTL(ttl, session.ExpiresAt)}
	return nil
}

func (m *MemoryStore) SaveRefreshSession(_ context.Context, tokenID string, session auth.RefreshSession, ttl time.Duration) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.refresh[tokenID] = memoryRefreshEntry{session: session, expire: expiresAtFromTTL(ttl, session.ExpiresAt)}
	return nil
}

func (m *MemoryStore) GetAccessSession(_ context.Context, tokenID string) (auth.AccessSession, error) {
	m.mu.RLock()
	entry, ok := m.access[tokenID]
	m.mu.RUnlock()
	if !ok {
		return auth.AccessSession{}, auth.ErrSessionNotFound
	}
	if time.Now().UTC().After(entry.expire) {
		m.mu.Lock()
		delete(m.access, tokenID)
		m.mu.Unlock()
		return auth.AccessSession{}, auth.ErrSessionNotFound
	}
	return entry.session, nil
}

func (m *MemoryStore) GetRefreshSession(_ context.Context, tokenID string) (auth.RefreshSession, error) {
	m.mu.RLock()
	entry, ok := m.refresh[tokenID]
	m.mu.RUnlock()
	if !ok {
		return auth.RefreshSession{}, auth.ErrSessionNotFound
	}
	if time.Now().UTC().After(entry.expire) {
		m.mu.Lock()
		delete(m.refresh, tokenID)
		m.mu.Unlock()
		return auth.RefreshSession{}, auth.ErrSessionNotFound
	}
	return entry.session, nil
}

func (m *MemoryStore) DeleteAccessSession(_ context.Context, tokenID string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	delete(m.access, tokenID)
	return nil
}

func (m *MemoryStore) DeleteRefreshSession(_ context.Context, tokenID string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	delete(m.refresh, tokenID)
	return nil
}

func (m *MemoryStore) RotateRefreshSession(_ context.Context, oldTokenID, newTokenID string, newSession auth.RefreshSession, ttl time.Duration) (bool, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	old, ok := m.refresh[oldTokenID]
	if !ok || time.Now().UTC().After(old.expire) {
		delete(m.refresh, oldTokenID)
		return false, nil
	}
	delete(m.refresh, oldTokenID)
	m.refresh[newTokenID] = memoryRefreshEntry{session: newSession, expire: expiresAtFromTTL(ttl, newSession.ExpiresAt)}
	return true, nil
}

func (m *MemoryStore) TouchAccessSession(_ context.Context, tokenID string, ttl time.Duration) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	entry, ok := m.access[tokenID]
	if !ok {
		return auth.ErrSessionNotFound
	}
	entry.expire = expiresAtFromTTL(ttl, entry.session.ExpiresAt)
	m.access[tokenID] = entry
	return nil
}

func expiresAtFromTTL(ttl time.Duration, fallback time.Time) time.Time {
	now := time.Now().UTC()
	if ttl > 0 {
		return now.Add(ttl)
	}
	if !fallback.IsZero() {
		return fallback
	}
	return now
}
