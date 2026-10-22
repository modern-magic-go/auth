package redisinterop

import (
	"context"
	"fmt"
	"testing"
	"time"

	"github.com/modern-magic-go/auth"
	"github.com/modern-magic-go/auth/adapters"
	"github.com/redis/go-redis/v9"
)

type redisClient struct {
	rdb *redis.Client
}

func (c *redisClient) Get(key string) (string, error) {
	return c.rdb.Get(context.Background(), key).Result()
}

func (c *redisClient) Setex(key, value string, seconds int) error {
	return c.rdb.Set(context.Background(), key, value, time.Duration(seconds)*time.Second).Err()
}

func (c *redisClient) Del(keys ...string) (int, error) {
	return int(c.rdb.Del(context.Background(), keys...).Val()), nil
}

func (c *redisClient) Eval(script string, keys []string, args ...any) (any, error) {
	return c.rdb.Eval(context.Background(), script, keys, args...).Result()
}

func (c *redisClient) Expire(key string, seconds int) error {
	return c.rdb.Expire(context.Background(), key, time.Duration(seconds)*time.Second).Err()
}

func newRedis(t *testing.T) (*redis.Client, string) {
	t.Helper()
	rdb := redis.NewClient(&redis.Options{Addr: "127.0.0.1:6379"})
	if err := rdb.Ping(context.Background()).Err(); err != nil {
		_ = rdb.Close()
		t.Skipf("redis unavailable: %v", err)
	}
	prefix := fmt.Sprintf("authtest:%d:", time.Now().UnixNano())
	t.Cleanup(func() {
		keys, _ := rdb.Keys(context.Background(), prefix+"*").Result()
		if len(keys) > 0 {
			_ = rdb.Del(context.Background(), keys...).Err()
		}
		_ = rdb.Close()
	})
	return rdb, prefix
}

func newStore(rdb *redis.Client, prefix string) *adapters.RedisStore {
	return adapters.NewRedisStore(
		&redisClient{rdb: rdb},
		adapters.RedisStoreConfig{KeyStrategy: adapters.NewPrefixedKeyStrategy(prefix)},
	)
}

func TestRedisIndexCleansExpiredRefs(t *testing.T) {
	rdb, prefix := newRedis(t)
	store := newStore(rdb, prefix)
	ctx := context.Background()
	now := time.Now().UTC()

	accessA := auth.AccessSession{TokenID: "a1", Subject: "u", SessionID: "s1", IssuedAt: now, ExpiresAt: now.Add(time.Minute)}
	refreshA := auth.RefreshSession{TokenID: "r1", Subject: "u", SessionID: "s1", IssuedAt: now, ExpiresAt: now.Add(2 * time.Second)}
	accessB := auth.AccessSession{TokenID: "a2", Subject: "u", SessionID: "s2", IssuedAt: now, ExpiresAt: now.Add(time.Minute)}
	refreshB := auth.RefreshSession{TokenID: "r2", Subject: "u", SessionID: "s2", IssuedAt: now, ExpiresAt: now.Add(100 * time.Second)}

	_, err := store.CreateSession(ctx, accessA, refreshA, time.Minute, 2*time.Second, 0)
	if err != nil {
		t.Fatalf("create A: %v", err)
	}
	_, err = store.CreateSession(ctx, accessB, refreshB, time.Minute, 100*time.Second, 0)
	if err != nil {
		t.Fatalf("create B: %v", err)
	}

	time.Sleep(3 * time.Second)
	refs, err := store.ListBySubject(ctx, "u")
	if err != nil {
		t.Fatalf("list: %v", err)
	}
	if len(refs) != 1 || refs[0].SessionID != "s2" {
		t.Fatalf("expected only s2 after expiry cleanup, got %+v", refs)
	}
	if _, err := store.GetRefreshSession(ctx, "r1"); err == nil {
		t.Fatal("expired refresh session should be gone")
	}
}

func TestRedisIndexMaxSessionsAndSessionKeyCleanup(t *testing.T) {
	rdb, prefix := newRedis(t)
	store := newStore(rdb, prefix)
	ctx := context.Background()
	now := time.Now().UTC()

	create := func(index int, issuedAt time.Time) {
		suffix := fmt.Sprintf("%d", index)
		access := auth.AccessSession{TokenID: "a" + suffix, Subject: "u", SessionID: "s" + suffix, IssuedAt: issuedAt, ExpiresAt: issuedAt.Add(time.Minute)}
		refresh := auth.RefreshSession{TokenID: "r" + suffix, Subject: "u", SessionID: "s" + suffix, IssuedAt: issuedAt, ExpiresAt: issuedAt.Add(time.Hour)}
		evicted, err := store.CreateSession(ctx, access, refresh, time.Minute, time.Hour, 2)
		if err != nil {
			t.Fatalf("create %d: %v", index, err)
		}
		if index < 3 && len(evicted) != 0 {
			t.Fatalf("unexpected eviction on %d: %+v", index, evicted)
		}
	}

	create(1, now)
	create(2, now.Add(time.Second))
	create(3, now.Add(2*time.Second))

	refs, err := store.ListBySubject(ctx, "u")
	if err != nil {
		t.Fatalf("list: %v", err)
	}
	if len(refs) != 2 || refs[0].SessionID != "s2" || refs[1].SessionID != "s3" {
		t.Fatalf("unexpected refs: %+v", refs)
	}
	for _, key := range []string{
		prefix + "access:a1",
		prefix + "refresh:r1",
		prefix + "session:s1",
	} {
		if rdb.Exists(ctx, key).Val() != 0 {
			t.Fatalf("evicted key still exists: %s", key)
		}
	}
}

func TestServiceLogoutCleansIndex(t *testing.T) {
	rdb, prefix := newRedis(t)
	store := newStore(rdb, prefix)
	ctx := context.Background()
	svc, err := auth.NewService(
		auth.Config{
			AccessTokenTTL:        5 * time.Minute,
			RefreshTokenTTL:       time.Hour,
			RefreshPolicy:         auth.RefreshPolicyReuseUntilExpiry,
			MaxSessionsPerSubject: 2,
		},
		store,
	)
	if err != nil {
		t.Fatalf("new service: %v", err)
	}

	first, err := svc.IssueTokenPair(ctx, auth.IssueRequest{Subject: "u"})
	if err != nil {
		t.Fatalf("issue first: %v", err)
	}
	second, err := svc.IssueTokenPair(ctx, auth.IssueRequest{Subject: "u"})
	if err != nil {
		t.Fatalf("issue second: %v", err)
	}
	refs, err := store.ListBySubject(ctx, "u")
	if err != nil || len(refs) != 2 {
		t.Fatalf("expected 2 sessions, got %+v err=%v", refs, err)
	}

	if err := svc.Logout(ctx, first.AccessToken, time.Hour); err != nil {
		t.Fatalf("logout: %v", err)
	}
	refs, err = store.ListBySubject(ctx, "u")
	if err != nil || len(refs) != 1 || refs[0].SessionID != second.SessionID {
		t.Fatalf("unexpected refs after logout: %+v err=%v", refs, err)
	}
	if _, err := svc.ValidateAccessToken(ctx, first.AccessToken); err == nil {
		t.Fatal("old access token should be invalid after logout")
	}
	if _, err := svc.RefreshAccessToken(ctx, first.RefreshToken); err == nil {
		t.Fatal("old refresh token should be invalid after logout")
	}
	if _, err := svc.ValidateAccessToken(ctx, second.AccessToken); err != nil {
		t.Fatalf("other session should stay valid: %v", err)
	}
}

func TestServiceRevokeRotatedRefreshFollowsGrace(t *testing.T) {
	rdb, prefix := newRedis(t)
	store := newStore(rdb, prefix)
	ctx := context.Background()
	svc, err := auth.NewService(
		auth.Config{
			AccessTokenTTL:        5 * time.Minute,
			RefreshTokenTTL:       time.Hour,
			RefreshPolicy:         auth.RefreshPolicyOneTimeRotation,
			RefreshGracePeriod:    time.Minute,
			MaxSessionsPerSubject: 2,
		},
		store,
		auth.WithGraceEncryptionKey([]byte("0123456789abcdef0123456789abcdef")),
	)
	if err != nil {
		t.Fatalf("new service: %v", err)
	}

	pair, err := svc.IssueTokenPair(ctx, auth.IssueRequest{Subject: "u"})
	if err != nil {
		t.Fatalf("issue: %v", err)
	}
	refreshed, err := svc.RefreshAccessToken(ctx, pair.RefreshToken)
	if err != nil {
		t.Fatalf("refresh: %v", err)
	}
	if err := svc.RevokeRefreshToken(ctx, pair.RefreshToken); err != nil {
		t.Fatalf("revoke rotated token: %v", err)
	}
	refs, err := store.ListBySubject(ctx, "u")
	if err != nil || len(refs) != 0 {
		t.Fatalf("expected empty index after revoke, got %+v err=%v", refs, err)
	}
	if _, err := svc.RefreshAccessToken(ctx, refreshed.RefreshToken); err == nil {
		t.Fatal("new refresh token should be revoked")
	}
}
