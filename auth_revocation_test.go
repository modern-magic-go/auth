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

func TestService_StatefulRevocation(t *testing.T) {
	clk := newFakeClock(time.Date(2026, 3, 18, 0, 0, 0, 0, time.UTC))
	revocation := adapters.NewMemoryRevocationStore()
	svc, err := auth.NewService(
		auth.Config{
			AccessTokenTTL:  5 * time.Minute,
			RefreshTokenTTL: time.Hour,
			RefreshPolicy:   auth.RefreshPolicyReuseUntilExpiry,
		},
		adapters.NewMemoryStore(),
		auth.WithClock(clk),
		auth.WithRandomSource(&fakeRandomSource{}),
		auth.WithRevocationStore(revocation),
	)
	require.NoError(t, err)

	first, err := svc.IssueTokenPair(context.Background(), auth.IssueRequest{Subject: "user-1"})
	require.NoError(t, err)
	second, err := svc.IssueTokenPair(context.Background(), auth.IssueRequest{Subject: "user-1"})
	require.NoError(t, err)

	_, err = svc.ValidateAccessToken(context.Background(), first.AccessToken)
	require.NoError(t, err)

	require.NoError(t, svc.RevokeSession(context.Background(), first.SessionID, time.Hour))
	_, err = svc.ValidateAccessToken(context.Background(), first.AccessToken)
	assert.ErrorIs(t, err, auth.ErrTokenRevoked)
	_, err = svc.RefreshAccessToken(context.Background(), first.RefreshToken)
	assert.ErrorIs(t, err, auth.ErrTokenRevoked)

	_, err = svc.ValidateAccessToken(context.Background(), second.AccessToken)
	require.NoError(t, err, "other sessions must not be affected")

	require.NoError(t, svc.RevokeSubject(context.Background(), "user-1", time.Hour))
	_, err = svc.ValidateAccessToken(context.Background(), second.AccessToken)
	assert.ErrorIs(t, err, auth.ErrTokenRevoked)
}

func TestService_RevocationNotConfigured(t *testing.T) {
	clk := newFakeClock(time.Date(2026, 3, 18, 0, 0, 0, 0, time.UTC))
	svc := newTestService(t, auth.DefaultConfig(), clk)

	assert.ErrorIs(t, svc.RevokeSession(context.Background(), "sid", time.Minute), auth.ErrRevocationNotConfigured)
	assert.ErrorIs(t, svc.RevokeSubject(context.Background(), "user", time.Minute), auth.ErrRevocationNotConfigured)
}
