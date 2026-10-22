package auth_test

import (
	"context"
	"testing"
	"time"

	"github.com/modern-magic-go/auth"
	"github.com/modern-magic-go/auth/adapters"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestService_RotateNearExpiryRatio(t *testing.T) {
	clk := newFakeClock(time.Date(2026, 3, 18, 0, 0, 0, 0, time.UTC))
	svc := newTestService(t, auth.Config{
		AccessTokenTTL:        5 * time.Minute,
		RefreshTokenTTL:       10 * time.Minute,
		RefreshPolicy:         auth.RefreshPolicyRotateNearExpiry,
		RotateNearExpiryRatio: 0.5,
	}, clk)

	pair, err := svc.IssueTokenPair(context.Background(), auth.IssueRequest{Subject: "user-ratio"})
	require.NoError(t, err)

	clk.Add(4*time.Minute + 59*time.Second)
	notYet, err := svc.RefreshAccessToken(context.Background(), pair.RefreshToken)
	require.NoError(t, err)
	assert.False(t, notYet.Rotated)

	clk.Add(time.Second)
	rotated, err := svc.RefreshAccessToken(context.Background(), pair.RefreshToken)
	require.NoError(t, err)
	assert.True(t, rotated.Rotated)
	assert.NotEqual(t, pair.RefreshToken, rotated.RefreshToken)
}

func TestService_RefreshGraceIdempotent(t *testing.T) {
	clk := newFakeClock(time.Date(2026, 3, 18, 0, 0, 0, 0, time.UTC))
	svc, err := auth.NewService(
		auth.Config{
			AccessTokenTTL:     5 * time.Minute,
			RefreshTokenTTL:    time.Hour,
			RefreshPolicy:      auth.RefreshPolicyOneTimeRotation,
			RefreshGracePeriod: 50 * time.Millisecond,
		},
		adapters.NewMemoryStore(),
		auth.WithClock(clk),
		auth.WithRandomSource(&fakeRandomSource{}),
		auth.WithGraceEncryptionKey([]byte("0123456789abcdef0123456789abcdef")),
	)
	require.NoError(t, err)

	pair, err := svc.IssueTokenPair(context.Background(), auth.IssueRequest{Subject: "user-grace"})
	require.NoError(t, err)

	first, err := svc.RefreshAccessToken(context.Background(), pair.RefreshToken)
	require.NoError(t, err)
	assert.True(t, first.Rotated)

	replayed, err := svc.RefreshAccessToken(context.Background(), pair.RefreshToken)
	require.NoError(t, err)
	assert.True(t, replayed.Rotated)
	assert.Equal(t, first.AccessToken, replayed.AccessToken)
	assert.Equal(t, first.RefreshToken, replayed.RefreshToken)
	assert.Equal(t, first.SessionID, replayed.SessionID)

	time.Sleep(80 * time.Millisecond)
	_, err = svc.RefreshAccessToken(context.Background(), pair.RefreshToken)
	assert.ErrorIs(t, err, auth.ErrRefreshTokenReplayed)
}

func TestService_GraceRequiresEncryptionKeyAndStore(t *testing.T) {
	clk := newFakeClock(time.Date(2026, 3, 18, 0, 0, 0, 0, time.UTC))
	_, err := auth.NewService(
		auth.Config{RefreshGracePeriod: time.Minute},
		adapters.NewMemoryStore(),
		auth.WithClock(clk),
	)
	assert.ErrorIs(t, err, auth.ErrInvalidConfig)

	_, err = auth.NewService(
		auth.Config{RefreshGracePeriod: time.Minute},
		&sessionOnlyStore{SessionStore: adapters.NewMemoryStore()},
		auth.WithClock(clk),
		auth.WithGraceEncryptionKey([]byte("0123456789abcdef0123456789abcdef")),
	)
	assert.ErrorIs(t, err, auth.ErrInvalidConfig)
}

type sessionOnlyStore struct {
	auth.SessionStore
}
