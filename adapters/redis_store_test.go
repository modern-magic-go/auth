package adapters

import (
	"context"
	"fmt"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/modern-magic-go/auth"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

type fakeRedisClient struct {
	mu   sync.Mutex
	data map[string]string
}

func newFakeRedisClient() *fakeRedisClient {
	return &fakeRedisClient{data: make(map[string]string)}
}

func (f *fakeRedisClient) Get(key string) (string, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	v, ok := f.data[key]
	if !ok {
		return "", fmt.Errorf("redis: nil")
	}
	return v, nil
}

func (f *fakeRedisClient) Setex(key, value string, _ int) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.data[key] = value
	return nil
}

func (f *fakeRedisClient) Del(keys ...string) (int, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	c := 0
	for _, k := range keys {
		if _, ok := f.data[k]; ok {
			delete(f.data, k)
			c++
		}
	}
	return c, nil
}

func (f *fakeRedisClient) Eval(_ string, keys []string, args ...any) (any, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if len(keys) != 2 {
		return int64(0), nil
	}
	oldKey := keys[0]
	newKey := keys[1]
	if _, ok := f.data[oldKey]; !ok {
		return int64(0), nil
	}
	delete(f.data, oldKey)
	if len(args) > 0 {
		f.data[newKey] = fmt.Sprint(args[0])
	}
	return int64(1), nil
}

func (f *fakeRedisClient) Expire(key string, _ int) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if _, ok := f.data[key]; !ok {
		return fmt.Errorf("redis: nil")
	}
	return nil
}

func TestRedisStore_BasicLifecycleAndRotate(t *testing.T) {
	client := newFakeRedisClient()
	store := NewRedisStore(client, RedisStoreConfig{KeyStrategy: NewPrefixedKeyStrategy("t:")})
	ctx := context.Background()

	access := auth.AccessSession{TokenID: "a1", Subject: "u1", ExpiresAt: time.Now().UTC().Add(time.Hour)}
	refresh := auth.RefreshSession{TokenID: "r1", Subject: "u1", ExpiresAt: time.Now().UTC().Add(2 * time.Hour)}

	require.NoError(t, store.SaveAccessSession(ctx, "a1", access, time.Hour))
	require.NoError(t, store.SaveRefreshSession(ctx, "r1", refresh, 2*time.Hour))

	ga, err := store.GetAccessSession(ctx, "a1")
	require.NoError(t, err)
	assert.Equal(t, "u1", ga.Subject)

	gr, err := store.GetRefreshSession(ctx, "r1")
	require.NoError(t, err)
	assert.Equal(t, "u1", gr.Subject)

	ok, err := store.RotateRefreshSession(ctx, "r1", "r2", auth.RefreshSession{TokenID: "r2", Subject: "u1", ExpiresAt: time.Now().UTC().Add(time.Hour)}, time.Hour)
	require.NoError(t, err)
	assert.True(t, ok)

	_, err = store.GetRefreshSession(ctx, "r1")
	assert.ErrorIs(t, err, auth.ErrSessionNotFound)
	_, err = store.GetRefreshSession(ctx, "r2")
	require.NoError(t, err)
}

func TestRedisStore_Helpers(t *testing.T) {
	assert.Equal(t, 1, seconds(0))
	assert.Equal(t, 1, seconds(500*time.Millisecond))
	assert.Equal(t, 2, seconds(2*time.Second))

	b, err := toBool(int64(1))
	require.NoError(t, err)
	assert.True(t, b)

	b, err = toBool("0")
	require.NoError(t, err)
	assert.False(t, b)

	_, err = toBool("xx")
	assert.Error(t, err)

	assert.True(t, isRedisNil(fmt.Errorf("redis: nil")))
	assert.False(t, isRedisNil(fmt.Errorf("other")))

	for _, s := range []string{"(1)", "[1]", " 1 "} {
		v, err := toBool(strings.TrimSpace(s))
		require.NoError(t, err)
		assert.True(t, v)
	}

	v, err := strconv.ParseInt("1", 10, 64)
	require.NoError(t, err)
	assert.Equal(t, int64(1), v)
}
