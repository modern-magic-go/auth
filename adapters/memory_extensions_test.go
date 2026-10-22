package adapters

import (
	"context"
	"testing"
	"time"

	"github.com/modern-magic-go/auth"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestMemoryStoreSessionIndex(t *testing.T) {
	store := NewMemoryStore()
	ctx := context.Background()
	now := time.Now().UTC()

	newSession := func(index int, issuedAt time.Time) (auth.AccessSession, auth.RefreshSession) {
		suffix := string(rune('0' + index))
		sessionID := "s" + suffix
		access := auth.AccessSession{
			TokenID:        "a" + suffix,
			Subject:        "user-index",
			IssuedAt:       issuedAt,
			ExpiresAt:      issuedAt.Add(time.Minute),
			RefreshTokenID: "r" + suffix,
			SessionID:      sessionID,
		}
		refresh := auth.RefreshSession{
			TokenID:   "r" + suffix,
			Subject:   "user-index",
			IssuedAt:  issuedAt,
			ExpiresAt: issuedAt.Add(time.Hour),
			SessionID: sessionID,
		}
		return access, refresh
	}

	access1, refresh1 := newSession(1, now)
	evicted, err := store.CreateSession(ctx, access1, refresh1, time.Minute, time.Hour, 2)
	require.NoError(t, err)
	assert.Empty(t, evicted)

	access2, refresh2 := newSession(2, now.Add(time.Second))
	_, err = store.CreateSession(ctx, access2, refresh2, time.Minute, time.Hour, 2)
	require.NoError(t, err)

	access3, refresh3 := newSession(3, now.Add(2*time.Second))
	evicted, err = store.CreateSession(ctx, access3, refresh3, time.Minute, time.Hour, 2)
	require.NoError(t, err)
	require.Len(t, evicted, 1)
	assert.Equal(t, "s1", evicted[0].SessionID)

	refs, err := store.ListBySubject(ctx, "user-index")
	require.NoError(t, err)
	require.Len(t, refs, 2)
	assert.Equal(t, "s2", refs[0].SessionID)
	assert.Equal(t, "s3", refs[1].SessionID)

	_, err = store.GetRefreshSession(ctx, "r1")
	assert.ErrorIs(t, err, auth.ErrSessionNotFound)

	updatedRef := refs[0]
	updatedRef.AccessTokenID = "a2-new"
	require.NoError(t, store.TouchSession(ctx, updatedRef, time.Hour))
	refs, err = store.ListBySubject(ctx, "user-index")
	require.NoError(t, err)
	assert.Equal(t, "a2-new", refs[0].AccessTokenID)

	rotatedRef := refs[0]
	rotatedRef.RefreshTokenID = "r2-new"
	rotatedRef.ExpiresAt = now.Add(2 * time.Hour)
	ok, err := store.RotateRefreshSessionWithIndex(
		ctx,
		"r2",
		auth.RefreshSession{
			TokenID:   "r2-new",
			Subject:   "user-index",
			IssuedAt:  now.Add(time.Second),
			ExpiresAt: now.Add(2 * time.Hour),
			SessionID: "s2",
		},
		rotatedRef,
		time.Hour,
	)
	require.NoError(t, err)
	assert.True(t, ok)

	require.NoError(t, store.RemoveSession(ctx, "user-index", "s2"))
	refs, err = store.ListBySubject(ctx, "user-index")
	require.NoError(t, err)
	require.Len(t, refs, 1)
	assert.Equal(t, "s3", refs[0].SessionID)
}

func TestMemoryStoreRefreshGrace(t *testing.T) {
	store := NewMemoryStore()
	ctx := context.Background()
	now := time.Now().UTC()

	record := auth.RefreshGraceRecord{
		OldTokenID:             "old",
		NewTokenID:             "new",
		SessionID:              "sid",
		Subject:                "user",
		AccessToken:            "access",
		RefreshTokenCiphertext: "ciphertext",
		AccessExpiresAt:        now.Add(time.Minute),
		RefreshExpiresAt:       now.Add(time.Hour),
	}
	require.NoError(t, store.SaveRefreshGrace(ctx, record, time.Minute))
	got, err := store.GetRefreshGrace(ctx, "old")
	require.NoError(t, err)
	assert.Equal(t, record.NewTokenID, got.NewTokenID)

	require.NoError(t, store.DeleteRefreshGrace(ctx, "old"))
	_, err = store.GetRefreshGrace(ctx, "old")
	assert.ErrorIs(t, err, auth.ErrSessionNotFound)

	require.NoError(t, store.SaveRefreshSession(ctx, "old", auth.RefreshSession{
		TokenID:   "old",
		Subject:   "user",
		IssuedAt:  now,
		ExpiresAt: now.Add(time.Hour),
		SessionID: "sid",
	}, time.Hour))
	ok, err := store.RotateRefreshSessionWithGrace(
		ctx,
		"old",
		auth.RefreshSession{
			TokenID:   "new",
			Subject:   "user",
			IssuedAt:  now,
			ExpiresAt: now.Add(time.Hour),
			SessionID: "sid",
		},
		record,
		time.Hour,
		time.Minute,
	)
	require.NoError(t, err)
	assert.True(t, ok)
	_, err = store.GetRefreshSession(ctx, "old")
	assert.ErrorIs(t, err, auth.ErrSessionNotFound)
	_, err = store.GetRefreshSession(ctx, "new")
	require.NoError(t, err)
	got, err = store.GetRefreshGrace(ctx, "old")
	require.NoError(t, err)
	assert.Equal(t, "new", got.NewTokenID)
}

func TestMemoryRevocationStore(t *testing.T) {
	store := NewMemoryRevocationStore()
	ctx := context.Background()

	require.NoError(t, store.RevokeSession(ctx, "sid-1", time.Minute))
	revoked, err := store.IsRevoked(ctx, "sid-1", "user-1")
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
