package auth_test

import (
	"context"
	"crypto/rand"
	"testing"
	"time"

	"github.com/modern-magic-go/auth"
	"github.com/modern-magic-go/auth/adapters"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestSignedTokenFormatAdapter(t *testing.T) {
	secret := make([]byte, 32)
	_, err := rand.Read(secret)
	require.NoError(t, err)

	adapter := auth.NewSignedTokenFormatAdapter(secret)
	clk := newFakeClock(time.Date(2026, 3, 18, 0, 0, 0, 0, time.UTC))
	svc, err := auth.NewService(
		auth.Config{
			AccessTokenTTL:  10 * time.Minute,
			RefreshTokenTTL: time.Hour,
		},
		adapters.NewMemoryStore(),
		auth.WithClock(clk),
		auth.WithTokenFormat(adapter),
	)
	require.NoError(t, err)

	t.Run("issue and validate signed tokens", func(t *testing.T) {
		pair, err := svc.IssueTokenPair(context.Background(), auth.IssueRequest{Subject: "user-1"})
		require.NoError(t, err)
		require.NotEmpty(t, pair.AccessToken)
		require.NotEmpty(t, pair.RefreshToken)

		result, err := svc.ValidateAccessToken(context.Background(), pair.AccessToken)
		require.NoError(t, err)
		assert.Equal(t, "user-1", result.Subject)
	})

	t.Run("reject tampered token", func(t *testing.T) {
		pair, err := svc.IssueTokenPair(context.Background(), auth.IssueRequest{Subject: "user-2"})
		require.NoError(t, err)

		tamperedToken := pair.AccessToken + "tampered"
		_, err = svc.ValidateAccessToken(context.Background(), tamperedToken)
		assert.ErrorIs(t, err, auth.ErrInvalidTokenFormat)
	})

	t.Run("reject token with wrong signature", func(t *testing.T) {
		pair, err := svc.IssueTokenPair(context.Background(), auth.IssueRequest{Subject: "user-3"})
		require.NoError(t, err)

		wrongSecret := make([]byte, 32)
		rand.Read(wrongSecret)
		wrongAdapter := auth.NewSignedTokenFormatAdapter(wrongSecret)
		wrongSvc, _ := auth.NewService(
			auth.Config{
				AccessTokenTTL:  10 * time.Minute,
				RefreshTokenTTL: time.Hour,
			},
			adapters.NewMemoryStore(),
			auth.WithClock(clk),
			auth.WithTokenFormat(wrongAdapter),
		)

		_, err = wrongSvc.ValidateAccessToken(context.Background(), pair.AccessToken)
		assert.ErrorIs(t, err, auth.ErrInvalidTokenFormat)
	})
}

func TestRollbackFailureHandler(t *testing.T) {
	clk := newFakeClock(time.Date(2026, 3, 18, 0, 0, 0, 0, time.UTC))

	var rollbackCalled bool
	var rollbackOp string
	var rollbackTokenID string

	handler := func(ctx context.Context, op string, tokenID string, err error) {
		rollbackCalled = true
		rollbackOp = op
		rollbackTokenID = tokenID
	}

	svc, err := auth.NewService(
		auth.Config{
			AccessTokenTTL:  10 * time.Minute,
			RefreshTokenTTL: time.Hour,
		},
		adapters.NewMemoryStore(),
		auth.WithClock(clk),
		auth.WithRandomSource(&fakeRandomSource{}),
		auth.WithRollbackFailureHandler(handler),
	)
	require.NoError(t, err)

	_, err = svc.IssueTokenPair(context.Background(), auth.IssueRequest{Subject: "test"})
	require.NoError(t, err)

	assert.False(t, rollbackCalled, "rollback should not be called on success")
	assert.Empty(t, rollbackOp)
	assert.Empty(t, rollbackTokenID)
}

func TestNewSignedTokenFormatAdapter_PanicOnEmptySecret(t *testing.T) {
	assert.Panics(t, func() {
		auth.NewSignedTokenFormatAdapter([]byte{})
	})
}
