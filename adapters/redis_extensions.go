package adapters

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	"github.com/modern-magic-go/auth"
)

func (s *RedisStore) extendedKeys() (ExtendedKeyStrategy, error) {
	keys, ok := s.keyStrategy.(ExtendedKeyStrategy)
	if !ok {
		return nil, auth.ErrInvalidConfig
	}
	return keys, nil
}

// CreateSession 保存 access/refresh 会话并维护 subject 排序索引。
func (s *RedisStore) CreateSession(ctx context.Context, access auth.AccessSession, refresh auth.RefreshSession, accessTTL, refreshTTL time.Duration, maxPerSubject int) ([]auth.SessionRef, error) {
	keys, err := s.extendedKeys()
	if err != nil {
		return nil, err
	}
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
	accessJSON, err := json.Marshal(access)
	if err != nil {
		return nil, err
	}
	refreshJSON, err := json.Marshal(refresh)
	if err != nil {
		return nil, err
	}
	refJSON, err := json.Marshal(ref)
	if err != nil {
		return nil, err
	}

	result, err := s.client.Eval(
		`redis.call("SETEX", KEYS[1], ARGV[1], ARGV[2])
redis.call("SETEX", KEYS[2], ARGV[3], ARGV[4])
redis.call("ZADD", KEYS[3], ARGV[5], ARGV[6])
local removed = {}
if tonumber(ARGV[7]) > 0 then
  removed = redis.call("ZRANGE", KEYS[3], 0, -(tonumber(ARGV[7]) + 1))
  if #removed > 0 then
    redis.call("ZREM", KEYS[3], unpack(removed))
  end
end
redis.call("EXPIRE", KEYS[3], ARGV[8])
return removed`,
		[]string{
			keys.AccessKey(access.TokenID),
			keys.RefreshKey(refresh.TokenID),
			keys.SubjectSessionsKey(access.Subject),
		},
		seconds(accessTTL),
		string(accessJSON),
		seconds(refreshTTL),
		string(refreshJSON),
		access.IssuedAt.Unix(),
		string(refJSON),
		maxPerSubject,
		seconds(refreshTTL),
	)
	if err != nil {
		return nil, err
	}
	return parseSessionRefs(result)
}

// ListBySubject 返回 subject 的会话索引。
func (s *RedisStore) ListBySubject(ctx context.Context, subject string) ([]auth.SessionRef, error) {
	keys, err := s.extendedKeys()
	if err != nil {
		return nil, err
	}
	result, err := s.client.Eval(
		`return redis.call("ZRANGE", KEYS[1], 0, -1)`,
		[]string{keys.SubjectSessionsKey(subject)},
	)
	if err != nil {
		return nil, err
	}
	return parseSessionRefs(result)
}

// RemoveSession 删除 subject 索引中的会话及对应 session。
func (s *RedisStore) RemoveSession(ctx context.Context, subject, sessionID string) error {
	keys, err := s.extendedKeys()
	if err != nil {
		return err
	}
	refs, err := s.ListBySubject(ctx, subject)
	if err != nil {
		return err
	}
	for _, ref := range refs {
		if ref.SessionID != sessionID {
			continue
		}
		if ref.AccessTokenID != "" {
			_, _ = s.client.Del(keys.AccessKey(ref.AccessTokenID))
		}
		if ref.RefreshTokenID != "" {
			_, _ = s.client.Del(keys.RefreshKey(ref.RefreshTokenID))
		}
		member, marshalErr := json.Marshal(ref)
		if marshalErr != nil {
			return marshalErr
		}
		_, err = s.client.Eval(
			`return redis.call("ZREM", KEYS[1], ARGV[1])`,
			[]string{keys.SubjectSessionsKey(subject)},
			string(member),
		)
		return err
	}
	return nil
}

// TouchSession 更新索引中的会话引用与 TTL。
func (s *RedisStore) TouchSession(ctx context.Context, ref auth.SessionRef, ttl time.Duration) error {
	keys, err := s.extendedKeys()
	if err != nil {
		return err
	}
	if ref.IssuedAt.IsZero() {
		ref.IssuedAt = time.Now().UTC()
	}
	indexKey := keys.SubjectSessionsKey(ref.Subject)
	refs, err := s.ListBySubject(ctx, ref.Subject)
	if err != nil {
		return err
	}
	for _, existing := range refs {
		if existing.SessionID != ref.SessionID {
			continue
		}
		member, marshalErr := json.Marshal(existing)
		if marshalErr != nil {
			return marshalErr
		}
		if _, err := s.client.Eval(
			`return redis.call("ZREM", KEYS[1], ARGV[1])`,
			[]string{indexKey},
			string(member),
		); err != nil {
			return err
		}
	}
	member, err := json.Marshal(ref)
	if err != nil {
		return err
	}
	_, err = s.client.Eval(
		`redis.call("ZADD", KEYS[1], ARGV[1], ARGV[2])
redis.call("EXPIRE", KEYS[1], ARGV[3])
return 1`,
		[]string{indexKey},
		ref.IssuedAt.Unix(),
		string(member),
		seconds(ttl),
	)
	return err
}

// RotateRefreshSessionWithIndex 轮换 refresh session 并更新索引引用。
func (s *RedisStore) RotateRefreshSessionWithIndex(ctx context.Context, oldTokenID string, newSession auth.RefreshSession, newRef auth.SessionRef, ttl time.Duration) (bool, error) {
	ok, err := s.RotateRefreshSession(ctx, oldTokenID, newSession.TokenID, newSession, ttl)
	if err != nil || !ok {
		return ok, err
	}
	if err := s.TouchSession(ctx, newRef, ttl); err != nil {
		return false, err
	}
	return true, nil
}

// SaveRefreshGrace 保存刷新宽限记录。
func (s *RedisStore) SaveRefreshGrace(ctx context.Context, record auth.RefreshGraceRecord, ttl time.Duration) error {
	keys, err := s.extendedKeys()
	if err != nil {
		return err
	}
	payload, err := json.Marshal(record)
	if err != nil {
		return err
	}
	return s.client.Setex(keys.RefreshGraceKey(record.OldTokenID), string(payload), seconds(ttl))
}

// GetRefreshGrace 读取刷新宽限记录。
func (s *RedisStore) GetRefreshGrace(ctx context.Context, oldTokenID string) (auth.RefreshGraceRecord, error) {
	keys, err := s.extendedKeys()
	if err != nil {
		return auth.RefreshGraceRecord{}, err
	}
	value, err := s.client.Get(keys.RefreshGraceKey(oldTokenID))
	if isRedisNil(err) || value == "" {
		return auth.RefreshGraceRecord{}, auth.ErrSessionNotFound
	}
	if err != nil {
		return auth.RefreshGraceRecord{}, err
	}
	var record auth.RefreshGraceRecord
	if err := json.Unmarshal([]byte(value), &record); err != nil {
		return auth.RefreshGraceRecord{}, err
	}
	return record, nil
}

// DeleteRefreshGrace 删除刷新宽限记录。
func (s *RedisStore) DeleteRefreshGrace(ctx context.Context, oldTokenID string) error {
	keys, err := s.extendedKeys()
	if err != nil {
		return err
	}
	_, err = s.client.Del(keys.RefreshGraceKey(oldTokenID))
	return err
}

// RotateRefreshSessionWithGrace 原子完成 refresh 轮换与 grace 记录写入。
func (s *RedisStore) RotateRefreshSessionWithGrace(ctx context.Context, oldTokenID string, newSession auth.RefreshSession, record auth.RefreshGraceRecord, sessionTTL, graceTTL time.Duration) (bool, error) {
	keys, err := s.extendedKeys()
	if err != nil {
		return false, err
	}
	sessionJSON, err := json.Marshal(newSession)
	if err != nil {
		return false, err
	}
	graceJSON, err := json.Marshal(record)
	if err != nil {
		return false, err
	}
	result, err := s.client.Eval(
		`if not redis.call("GET", KEYS[1]) then
  return 0
end
redis.call("DEL", KEYS[1])
redis.call("SETEX", KEYS[2], ARGV[1], ARGV[2])
redis.call("SETEX", KEYS[3], ARGV[3], ARGV[4])
return 1`,
		[]string{
			keys.RefreshKey(oldTokenID),
			keys.RefreshKey(newSession.TokenID),
			keys.RefreshGraceKey(oldTokenID),
		},
		seconds(sessionTTL),
		string(sessionJSON),
		seconds(graceTTL),
		string(graceJSON),
	)
	if err != nil {
		return false, err
	}
	return toBool(result)
}

func parseSessionRefs(result any) ([]auth.SessionRef, error) {
	values, err := toStringSlice(result)
	if err != nil {
		return nil, err
	}
	refs := make([]auth.SessionRef, 0, len(values))
	for _, value := range values {
		var ref auth.SessionRef
		if err := json.Unmarshal([]byte(value), &ref); err != nil {
			continue
		}
		refs = append(refs, ref)
	}
	return refs, nil
}

func toStringSlice(result any) ([]string, error) {
	switch value := result.(type) {
	case nil:
		return nil, nil
	case []string:
		return value, nil
	case []any:
		values := make([]string, 0, len(value))
		for _, item := range value {
			text, ok := item.(string)
			if !ok {
				return nil, fmt.Errorf("unexpected redis result item: %T", item)
			}
			values = append(values, text)
		}
		return values, nil
	default:
		return nil, fmt.Errorf("unexpected redis result: %T", result)
	}
}
