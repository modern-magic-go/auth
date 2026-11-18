package adapters

import (
	"context"
	"sort"
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

type memoryGraceEntry struct {
	record auth.RefreshGraceRecord
	expire time.Time
}

// MemoryStore 是用于测试与轻量场景的内存会话适配器。
type MemoryStore struct {
	mu       sync.RWMutex
	access   map[string]memoryAccessEntry
	refresh  map[string]memoryRefreshEntry
	refs     map[string]auth.SessionRef
	subjects map[string][]string
	grace    map[string]memoryGraceEntry
}

// NewMemoryStore 创建内存适配器。
func NewMemoryStore() *MemoryStore {
	return &MemoryStore{
		access:   make(map[string]memoryAccessEntry),
		refresh:  make(map[string]memoryRefreshEntry),
		refs:     make(map[string]auth.SessionRef),
		subjects: make(map[string][]string),
		grace:    make(map[string]memoryGraceEntry),
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

// CreateSession 原子保存 access/refresh 会话并维护 subject 索引。
func (m *MemoryStore) CreateSession(_ context.Context, access auth.AccessSession, refresh auth.RefreshSession, accessTTL, refreshTTL time.Duration, maxPerSubject int) ([]auth.SessionRef, error) {
	m.mu.Lock()
	defer m.mu.Unlock()

	sessionID := access.SessionID
	if sessionID == "" {
		sessionID = access.TokenID
	}
	ref := auth.SessionRef{
		SessionID:      sessionID,
		Subject:        access.Subject,
		AccessTokenID:  access.TokenID,
		RefreshTokenID: refresh.TokenID,
		IssuedAt:       access.IssuedAt,
		ExpiresAt:      refresh.ExpiresAt,
	}

	m.access[access.TokenID] = memoryAccessEntry{session: access, expire: expiresAtFromTTL(accessTTL, access.ExpiresAt)}
	m.refresh[refresh.TokenID] = memoryRefreshEntry{session: refresh, expire: expiresAtFromTTL(refreshTTL, refresh.ExpiresAt)}
	m.refs[sessionID] = ref
	m.subjects[ref.Subject] = appendUniqueSessionID(m.subjects[ref.Subject], sessionID)
	m.sortSubjectLocked(ref.Subject)

	var evicted []auth.SessionRef
	if maxPerSubject > 0 {
		ids := m.subjects[ref.Subject]
		if len(ids) > maxPerSubject {
			evictCount := len(ids) - maxPerSubject
			for _, evictedID := range ids[:evictCount] {
				if evictedRef, ok := m.refs[evictedID]; ok {
					evicted = append(evicted, evictedRef)
					delete(m.access, evictedRef.AccessTokenID)
					delete(m.refresh, evictedRef.RefreshTokenID)
					delete(m.refs, evictedID)
				}
			}
			m.subjects[ref.Subject] = append([]string(nil), ids[evictCount:]...)
		}
	}
	return evicted, nil
}

func (m *MemoryStore) ListBySubject(_ context.Context, subject string) ([]auth.SessionRef, error) {
	m.mu.Lock()
	defer m.mu.Unlock()

	now := time.Now().UTC()
	ids := m.subjects[subject]
	refs := make([]auth.SessionRef, 0, len(ids))
	kept := make([]string, 0, len(ids))
	for _, sessionID := range ids {
		ref, ok := m.refs[sessionID]
		if !ok {
			continue
		}
		if !ref.ExpiresAt.IsZero() && !now.Before(ref.ExpiresAt) {
			delete(m.access, ref.AccessTokenID)
			delete(m.refresh, ref.RefreshTokenID)
			delete(m.refs, ref.SessionID)
			continue
		}
		kept = append(kept, sessionID)
		refs = append(refs, ref)
	}
	m.subjects[subject] = kept
	return refs, nil
}

func (m *MemoryStore) RemoveSession(_ context.Context, subject, sessionID string) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	if ref, ok := m.refs[sessionID]; ok {
		m.deleteSessionLocked(ref)
		return nil
	}
	m.subjects[subject] = removeSessionID(m.subjects[subject], sessionID)
	return nil
}

func (m *MemoryStore) TouchSession(_ context.Context, ref auth.SessionRef, _ time.Duration) error {
	if ref.SessionID == "" {
		return auth.ErrInvalidConfig
	}
	m.mu.Lock()
	defer m.mu.Unlock()

	if existing, ok := m.refs[ref.SessionID]; ok {
		if ref.IssuedAt.IsZero() {
			ref.IssuedAt = existing.IssuedAt
		}
		if ref.Subject == "" {
			ref.Subject = existing.Subject
		}
	}
	m.refs[ref.SessionID] = ref
	m.subjects[ref.Subject] = appendUniqueSessionID(m.subjects[ref.Subject], ref.SessionID)
	m.sortSubjectLocked(ref.Subject)
	return nil
}

func (m *MemoryStore) RotateRefreshSessionWithIndex(_ context.Context, oldTokenID string, newSession auth.RefreshSession, newRef auth.SessionRef, ttl time.Duration) (bool, error) {
	m.mu.Lock()
	defer m.mu.Unlock()

	old, ok := m.refresh[oldTokenID]
	if !ok || time.Now().UTC().After(old.expire) {
		delete(m.refresh, oldTokenID)
		return false, nil
	}
	delete(m.refresh, oldTokenID)
	m.refresh[newSession.TokenID] = memoryRefreshEntry{session: newSession, expire: expiresAtFromTTL(ttl, newSession.ExpiresAt)}

	if existing, ok := m.refs[newRef.SessionID]; ok {
		newRef.IssuedAt = existing.IssuedAt
		newRef.Subject = existing.Subject
	}
	m.refs[newRef.SessionID] = newRef
	m.subjects[newRef.Subject] = appendUniqueSessionID(m.subjects[newRef.Subject], newRef.SessionID)
	m.sortSubjectLocked(newRef.Subject)
	return true, nil
}

// SaveRefreshGrace 保存刷新宽限记录。
func (m *MemoryStore) SaveRefreshGrace(_ context.Context, record auth.RefreshGraceRecord, ttl time.Duration) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.grace[record.OldTokenID] = memoryGraceEntry{record: record, expire: time.Now().UTC().Add(ttl)}
	return nil
}

// GetRefreshGrace 读取刷新宽限记录。
func (m *MemoryStore) GetRefreshGrace(_ context.Context, oldTokenID string) (auth.RefreshGraceRecord, error) {
	m.mu.RLock()
	entry, ok := m.grace[oldTokenID]
	m.mu.RUnlock()
	if !ok {
		return auth.RefreshGraceRecord{}, auth.ErrSessionNotFound
	}
	if time.Now().UTC().After(entry.expire) {
		m.mu.Lock()
		delete(m.grace, oldTokenID)
		m.mu.Unlock()
		return auth.RefreshGraceRecord{}, auth.ErrSessionNotFound
	}
	return entry.record, nil
}

// DeleteRefreshGrace 删除刷新宽限记录。
func (m *MemoryStore) DeleteRefreshGrace(_ context.Context, oldTokenID string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	delete(m.grace, oldTokenID)
	return nil
}

// RotateRefreshSessionWithGrace 原子完成 refresh 轮换与 grace 记录写入。
func (m *MemoryStore) RotateRefreshSessionWithGrace(_ context.Context, oldTokenID string, newSession auth.RefreshSession, record auth.RefreshGraceRecord, sessionTTL, graceTTL time.Duration) (bool, error) {
	m.mu.Lock()
	defer m.mu.Unlock()

	old, ok := m.refresh[oldTokenID]
	if !ok || m.currentTime().After(old.expire) {
		delete(m.refresh, oldTokenID)
		return false, nil
	}
	delete(m.refresh, oldTokenID)
	m.refresh[newSession.TokenID] = memoryRefreshEntry{session: newSession, expire: expiresAtFromTTL(sessionTTL, newSession.ExpiresAt)}
	m.grace[record.OldTokenID] = memoryGraceEntry{record: record, expire: m.currentTime().Add(graceTTL)}
	return true, nil
}

// RotateRefreshSessionWithGraceAndIndex 原子完成 refresh 轮换、grace 记录与索引更新。
func (m *MemoryStore) RotateRefreshSessionWithGraceAndIndex(_ context.Context, oldTokenID string, newSession auth.RefreshSession, newRef auth.SessionRef, record auth.RefreshGraceRecord, sessionTTL, graceTTL time.Duration) (bool, error) {
	m.mu.Lock()
	defer m.mu.Unlock()

	old, ok := m.refresh[oldTokenID]
	if !ok || m.currentTime().After(old.expire) {
		delete(m.refresh, oldTokenID)
		return false, nil
	}
	delete(m.refresh, oldTokenID)
	m.refresh[newSession.TokenID] = memoryRefreshEntry{session: newSession, expire: expiresAtFromTTL(sessionTTL, newSession.ExpiresAt)}
	m.grace[record.OldTokenID] = memoryGraceEntry{record: record, expire: m.currentTime().Add(graceTTL)}

	if existing, ok := m.refs[newRef.SessionID]; ok {
		newRef.IssuedAt = existing.IssuedAt
		newRef.Subject = existing.Subject
	}
	m.refs[newRef.SessionID] = newRef
	m.subjects[newRef.Subject] = appendUniqueSessionID(m.subjects[newRef.Subject], newRef.SessionID)
	m.sortSubjectLocked(newRef.Subject)
	return true, nil
}

func (m *MemoryStore) deleteSessionLocked(ref auth.SessionRef) {
	delete(m.access, ref.AccessTokenID)
	delete(m.refresh, ref.RefreshTokenID)
	delete(m.refs, ref.SessionID)
	m.subjects[ref.Subject] = removeSessionID(m.subjects[ref.Subject], ref.SessionID)
}

func (m *MemoryStore) sortSubjectLocked(subject string) {
	ids := m.subjects[subject]
	sort.Slice(ids, func(i, j int) bool {
		left, leftOK := m.refs[ids[i]]
		right, rightOK := m.refs[ids[j]]
		if !leftOK || !rightOK {
			return ids[i] < ids[j]
		}
		if left.IssuedAt.Equal(right.IssuedAt) {
			return left.SessionID < right.SessionID
		}
		return left.IssuedAt.Before(right.IssuedAt)
	})
	m.subjects[subject] = ids
}

func appendUniqueSessionID(ids []string, sessionID string) []string {
	for _, id := range ids {
		if id == sessionID {
			return ids
		}
	}
	return append(ids, sessionID)
}

func removeSessionID(ids []string, sessionID string) []string {
	for index, id := range ids {
		if id == sessionID {
			return append(ids[:index], ids[index+1:]...)
		}
	}
	return ids
}

func (m *MemoryStore) currentTime() time.Time {
	return time.Now().UTC()
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
