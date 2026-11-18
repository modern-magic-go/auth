package adapters

import (
	"context"
	"testing"
	"time"

	"github.com/modern-magic-go/auth"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestPrefixedKeyStrategy_ExtendedKeys(t *testing.T) {
	keys := NewPrefixedKeyStrategy("app:auth:")
	assert.Equal(t, "app:auth:access:a1", keys.AccessKey("a1"))
	assert.Equal(t, "app:auth:refresh:r1", keys.RefreshKey("r1"))
	assert.Equal(t, "app:auth:session:s1", keys.SessionKey("s1"))
	assert.Equal(t, "app:auth:subject:u1:sessions", keys.SubjectSessionsKey("u1"))
	assert.Equal(t, "app:auth:grace:g1", keys.RefreshGraceKey("g1"))
	assert.Equal(t, "app:auth:revoked:session:s1", keys.RevokedSessionKey("s1"))
	assert.Equal(t, "app:auth:revoked:subject:u1", keys.RevokedSubjectKey("u1"))
}

func TestRedisRevocationStore(t *testing.T) {
	client := newFakeRedisClient()
	store := NewRedisRevocationStore(client, NewPrefixedKeyStrategy("t:"))
	ctx := context.Background()

	revoked, err := store.IsRevoked(ctx, "sid-1", "user-1")
	require.NoError(t, err)
	assert.False(t, revoked)

	require.NoError(t, store.RevokeSession(ctx, "sid-1", time.Minute))
	revoked, err = store.IsRevoked(ctx, "sid-1", "user-1")
	require.NoError(t, err)
	assert.True(t, revoked)

	revoked, err = store.IsRevoked(ctx, "sid-2", "user-1")
	require.NoError(t, err)
	assert.False(t, revoked)

	require.NoError(t, store.RevokeSubject(ctx, "user-2", time.Minute))
	revoked, err = store.IsRevoked(ctx, "sid-3", "user-2")
	require.NoError(t, err)
	assert.True(t, revoked)
}

func TestRedisStoreRefreshGrace(t *testing.T) {
	client := newFakeRedisClient()
	store := NewRedisStore(client, RedisStoreConfig{KeyStrategy: NewPrefixedKeyStrategy("t:")})
	ctx := context.Background()

	record := auth.RefreshGraceRecord{
		OldTokenID:             "old",
		NewTokenID:             "new",
		SessionID:              "sid",
		Subject:                "user",
		AccessTokenCiphertext:  "access-ciphertext",
		RefreshTokenCiphertext: "ciphertext",
		AccessExpiresAt:        time.Now().UTC().Add(time.Minute),
		RefreshExpiresAt:       time.Now().UTC().Add(time.Hour),
	}
	require.NoError(t, store.SaveRefreshGrace(ctx, record, time.Minute))

	got, err := store.GetRefreshGrace(ctx, "old")
	require.NoError(t, err)
	assert.Equal(t, record.NewTokenID, got.NewTokenID)
	assert.Equal(t, record.RefreshTokenCiphertext, got.RefreshTokenCiphertext)

	require.NoError(t, store.DeleteRefreshGrace(ctx, "old"))
	_, err = store.GetRefreshGrace(ctx, "old")
	assert.ErrorIs(t, err, auth.ErrSessionNotFound)
}
