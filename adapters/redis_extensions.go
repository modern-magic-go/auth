package adapters

import (
	"context"
	"encoding/json"
	"fmt"
	"sort"
	"time"

	"github.com/modern-magic-go/auth"
)

type redisSessionRecord struct {
	Ref        auth.SessionRef `json:"ref"`
	AccessKey  string          `json:"access_key"`
	RefreshKey string          `json:"refresh_key"`
	SessionKey string          `json:"session_key"`
}

func (s *RedisStore) extendedKeys() (ExtendedKeyStrategy, error) {
	keys, ok := s.keyStrategy.(ExtendedKeyStrategy)
	if !ok {
		return nil, auth.ErrInvalidConfig
	}
	return keys, nil
}

func (s *RedisStore) refsKey(subject string, keys ExtendedKeyStrategy) string {
	return keys.SubjectSessionsKey(subject) + ":refs"
}

func (s *RedisStore) newSessionRecord(keys ExtendedKeyStrategy, ref auth.SessionRef) redisSessionRecord {
	return redisSessionRecord{
		Ref:        ref,
		AccessKey:  keys.AccessKey(ref.AccessTokenID),
		RefreshKey: keys.RefreshKey(ref.RefreshTokenID),
		SessionKey: keys.SessionKey(ref.SessionID),
	}
}

// CreateSession 原子保存 access/refresh 会话、session 记录、subject 索引并裁剪。
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
	record := s.newSessionRecord(keys, ref)
	accessJSON, err := s.serializer.Marshal(access)
	if err != nil {
		return nil, err
	}
	refreshJSON, err := s.serializer.Marshal(refresh)
	if err != nil {
		return nil, err
	}
	recordJSON, err := json.Marshal(record)
	if err != nil {
		return nil, err
	}

	result, err := s.client.Eval(
		`redis.call("SETEX", KEYS[1], ARGV[1], ARGV[2])
redis.call("SETEX", KEYS[2], ARGV[3], ARGV[4])
redis.call("SETEX", KEYS[3], ARGV[3], ARGV[5])
redis.call("HSET", KEYS[5], ARGV[6], ARGV[5])
redis.call("ZADD", KEYS[4], ARGV[7], ARGV[6])
local removed = {}
local max = tonumber(ARGV[8])
if max > 0 then
  local evicted = redis.call("ZRANGE", KEYS[4], 0, -(max + 1))
  for _, sid in ipairs(evicted) do
    local rec = redis.call("HGET", KEYS[5], sid)
    if rec then
      local ok, decoded = pcall(cjson.decode, rec)
      if ok then
        redis.call("DEL", decoded.access_key, decoded.refresh_key, decoded.session_key)
      end
      table.insert(removed, rec)
      redis.call("HDEL", KEYS[5], sid)
    end
  end
  if #evicted > 0 then
    redis.call("ZREM", KEYS[4], unpack(evicted))
  end
end
redis.call("EXPIRE", KEYS[4], ARGV[9])
redis.call("EXPIRE", KEYS[5], ARGV[9])
return removed`,
		[]string{
			keys.AccessKey(access.TokenID),
			keys.RefreshKey(refresh.TokenID),
			keys.SessionKey(sessionID),
			keys.SubjectSessionsKey(access.Subject),
			s.refsKey(access.Subject, keys),
		},
		seconds(accessTTL),
		accessJSON,
		seconds(refreshTTL),
		refreshJSON,
		string(recordJSON),
		sessionID,
		access.IssuedAt.UnixNano(),
		maxPerSubject,
		seconds(refreshTTL),
	)
	if err != nil {
		return nil, err
	}
	return parseEvictedRefs(result)
}

// ListBySubject 返回有效会话，并顺手清理已过期的索引记录。
func (s *RedisStore) ListBySubject(ctx context.Context, subject string) ([]auth.SessionRef, error) {
	keys, err := s.extendedKeys()
	if err != nil {
		return nil, err
	}
	result, err := s.client.Eval(
		`return redis.call("HGETALL", KEYS[1])`,
		[]string{s.refsKey(subject, keys)},
	)
	if err != nil {
		return nil, err
	}
	values, err := toStringSlice(result)
	if err != nil {
		return nil, err
	}

	now := time.Now().UTC()
	refs := make([]auth.SessionRef, 0, len(values)/2)
	for index := 0; index+1 < len(values); index += 2 {
		sessionID := values[index]
		var record redisSessionRecord
		if err := json.Unmarshal([]byte(values[index+1]), &record); err != nil {
			_ = s.removeSession(ctx, keys, subject, sessionID)
			continue
		}
		if !record.Ref.ExpiresAt.IsZero() && !now.Before(record.Ref.ExpiresAt) {
			_ = s.removeSession(ctx, keys, subject, sessionID)
			continue
		}
		refs = append(refs, record.Ref)
	}
	sort.Slice(refs, func(i, j int) bool {
		if refs[i].IssuedAt.Equal(refs[j].IssuedAt) {
			return refs[i].SessionID < refs[j].SessionID
		}
		return refs[i].IssuedAt.Before(refs[j].IssuedAt)
	})
	return refs, nil
}

// RemoveSession 原子删除 session、索引与关联 key。
func (s *RedisStore) RemoveSession(ctx context.Context, subject, sessionID string) error {
	keys, err := s.extendedKeys()
	if err != nil {
		return err
	}
	return s.removeSession(ctx, keys, subject, sessionID)
}

func (s *RedisStore) removeSession(ctx context.Context, keys ExtendedKeyStrategy, subject, sessionID string) error {
	_, err := s.client.Eval(
		`local rec = redis.call("HGET", KEYS[1], ARGV[1])
if rec then
  local ok, decoded = pcall(cjson.decode, rec)
  if ok then
    redis.call("DEL", decoded.access_key, decoded.refresh_key, decoded.session_key)
  end
  redis.call("HDEL", KEYS[1], ARGV[1])
end
redis.call("ZREM", KEYS[2], ARGV[1])
return 1`,
		[]string{s.refsKey(subject, keys), keys.SubjectSessionsKey(subject)},
		sessionID,
	)
	return err
}

// TouchSession 单条 Lua 更新 session 记录、索引成员与 TTL。
func (s *RedisStore) TouchSession(ctx context.Context, ref auth.SessionRef, ttl time.Duration) error {
	keys, err := s.extendedKeys()
	if err != nil {
		return err
	}
	if ref.IssuedAt.IsZero() {
		ref.IssuedAt = time.Now().UTC()
	}
	record := s.newSessionRecord(keys, ref)
	recordJSON, err := json.Marshal(record)
	if err != nil {
		return err
	}
	_, err = s.client.Eval(
		`redis.call("SETEX", KEYS[1], ARGV[2], ARGV[1])
redis.call("HSET", KEYS[2], ARGV[3], ARGV[1])
redis.call("ZADD", KEYS[3], ARGV[4], ARGV[3])
redis.call("EXPIRE", KEYS[2], ARGV[2])
redis.call("EXPIRE", KEYS[3], ARGV[2])
return 1`,
		[]string{
			keys.SessionKey(ref.SessionID),
			s.refsKey(ref.Subject, keys),
			keys.SubjectSessionsKey(ref.Subject),
		},
		string(recordJSON),
		seconds(ttl),
		ref.SessionID,
		ref.IssuedAt.UnixNano(),
	)
	return err
}

// RotateRefreshSessionWithIndex 单条 Lua 完成 refresh 轮换与索引更新。
func (s *RedisStore) RotateRefreshSessionWithIndex(ctx context.Context, oldTokenID string, newSession auth.RefreshSession, newRef auth.SessionRef, ttl time.Duration) (bool, error) {
	keys, err := s.extendedKeys()
	if err != nil {
		return false, err
	}
	if newRef.IssuedAt.IsZero() {
		newRef.IssuedAt = time.Now().UTC()
	}
	record := s.newSessionRecord(keys, newRef)
	recordJSON, err := json.Marshal(record)
	if err != nil {
		return false, err
	}
	sessionJSON, err := s.serializer.Marshal(newSession)
	if err != nil {
		return false, err
	}
	result, err := s.client.Eval(
		`if not redis.call("GET", KEYS[1]) then
  return 0
end
redis.call("DEL", KEYS[1])
redis.call("SETEX", KEYS[2], ARGV[1], ARGV[2])
redis.call("SETEX", KEYS[3], ARGV[1], ARGV[3])
redis.call("HSET", KEYS[4], ARGV[4], ARGV[3])
redis.call("ZADD", KEYS[5], ARGV[5], ARGV[4])
redis.call("EXPIRE", KEYS[4], ARGV[1])
redis.call("EXPIRE", KEYS[5], ARGV[1])
return 1`,
		[]string{
			keys.RefreshKey(oldTokenID),
			keys.RefreshKey(newSession.TokenID),
			keys.SessionKey(newRef.SessionID),
			s.refsKey(newRef.Subject, keys),
			keys.SubjectSessionsKey(newRef.Subject),
		},
		seconds(ttl),
		sessionJSON,
		string(recordJSON),
		newRef.SessionID,
		newRef.IssuedAt.UnixNano(),
	)
	if err != nil {
		return false, err
	}
	return toBool(result)
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
	sessionJSON, err := s.serializer.Marshal(newSession)
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
		sessionJSON,
		seconds(graceTTL),
		string(graceJSON),
	)
	if err != nil {
		return false, err
	}
	return toBool(result)
}

// RotateRefreshSessionWithGraceAndIndex 单条 Lua 完成 grace 轮换与索引更新。
func (s *RedisStore) RotateRefreshSessionWithGraceAndIndex(ctx context.Context, oldTokenID string, newSession auth.RefreshSession, newRef auth.SessionRef, record auth.RefreshGraceRecord, sessionTTL, graceTTL time.Duration) (bool, error) {
	keys, err := s.extendedKeys()
	if err != nil {
		return false, err
	}
	if newRef.IssuedAt.IsZero() {
		newRef.IssuedAt = time.Now().UTC()
	}
	sessionJSON, err := s.serializer.Marshal(newSession)
	if err != nil {
		return false, err
	}
	graceJSON, err := json.Marshal(record)
	if err != nil {
		return false, err
	}
	recordJSON, err := json.Marshal(s.newSessionRecord(keys, newRef))
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
redis.call("SETEX", KEYS[4], ARGV[1], ARGV[5])
redis.call("HSET", KEYS[5], ARGV[6], ARGV[5])
redis.call("ZADD", KEYS[6], ARGV[7], ARGV[6])
redis.call("EXPIRE", KEYS[5], ARGV[1])
redis.call("EXPIRE", KEYS[6], ARGV[1])
return 1`,
		[]string{
			keys.RefreshKey(oldTokenID),
			keys.RefreshKey(newSession.TokenID),
			keys.RefreshGraceKey(oldTokenID),
			keys.SessionKey(newRef.SessionID),
			s.refsKey(newRef.Subject, keys),
			keys.SubjectSessionsKey(newRef.Subject),
		},
		seconds(sessionTTL),
		sessionJSON,
		seconds(graceTTL),
		graceJSON,
		recordJSON,
		newRef.SessionID,
		newRef.IssuedAt.UnixNano(),
	)
	if err != nil {
		return false, err
	}
	return toBool(result)
}

func parseEvictedRefs(result any) ([]auth.SessionRef, error) {
	values, err := toStringSlice(result)
	if err != nil {
		return nil, err
	}
	refs := make([]auth.SessionRef, 0, len(values))
	for _, value := range values {
		var record redisSessionRecord
		if err := json.Unmarshal([]byte(value), &record); err != nil {
			continue
		}
		refs = append(refs, record.Ref)
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
