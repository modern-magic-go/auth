package adapters

import (
	"context"
	"testing"
	"time"

	"github.com/modern-magic-go/auth"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestMemoryStore_BasicLifecycle(t *testing.T) {
	store := NewMemoryStore()
	ctx := context.Background()

	access := auth.AccessSession{TokenID: "a1", Subject: "u1", ExpiresAt: time.Now().UTC().Add(time.Hour)}
	refresh := auth.RefreshSession{TokenID: "r1", Subject: "u1", ExpiresAt: time.Now().UTC().Add(2 * time.Hour)}

	require.NoError(t, store.SaveAccessSession(ctx, "a1", access, time.Hour))
	require.NoError(t, store.SaveRefreshSession(ctx, "r1", refresh, 2*time.Hour))

	gotA, err := store.GetAccessSession(ctx, "a1")
	require.NoError(t, err)
	assert.Equal(t, "u1", gotA.Subject)

	gotR, err := store.GetRefreshSession(ctx, "r1")
	require.NoError(t, err)
	assert.Equal(t, "u1", gotR.Subject)

	require.NoError(t, store.DeleteAccessSession(ctx, "a1"))
	_, err = store.GetAccessSession(ctx, "a1")
	assert.ErrorIs(t, err, auth.ErrSessionNotFound)
}

func TestMemoryStore_ExpireAndRotate(t *testing.T) {
	store := NewMemoryStore()
	ctx := context.Background()

	refresh := auth.RefreshSession{TokenID: "old", Subject: "u2", ExpiresAt: time.Now().UTC().Add(time.Millisecond)}
	require.NoError(t, store.SaveRefreshSession(ctx, "old", refresh, time.Millisecond))
	time.Sleep(8 * time.Millisecond)

	_, err := store.GetRefreshSession(ctx, "old")
	assert.ErrorIs(t, err, auth.ErrSessionNotFound)

	refresh2 := auth.RefreshSession{TokenID: "old2", Subject: "u2", ExpiresAt: time.Now().UTC().Add(time.Minute)}
	require.NoError(t, store.SaveRefreshSession(ctx, "old2", refresh2, time.Minute))

	ok, err := store.RotateRefreshSession(ctx, "old2", "new2", auth.RefreshSession{TokenID: "new2", Subject: "u2", ExpiresAt: time.Now().UTC().Add(time.Minute)}, time.Minute)
	require.NoError(t, err)
	assert.True(t, ok)

	_, err = store.GetRefreshSession(ctx, "old2")
	assert.ErrorIs(t, err, auth.ErrSessionNotFound)
	_, err = store.GetRefreshSession(ctx, "new2")
	require.NoError(t, err)
}
