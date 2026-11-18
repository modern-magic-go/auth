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

	pair, err := svc.IssueTokenPair(context.Background(), auth.IssueRequest{Subject: "user"})
	require.NoError(t, err)
	assert.ErrorIs(t, svc.Logout(context.Background(), pair.AccessToken, time.Minute), auth.ErrRevocationNotConfigured)
}

func TestService_LogoutWithRefreshToken(t *testing.T) {
	clk := newFakeClock(time.Date(2026, 3, 18, 0, 0, 0, 0, time.UTC))
	store := adapters.NewMemoryStore()
	svc, err := auth.NewService(
		auth.DefaultConfig(),
		store,
		auth.WithClock(clk),
		auth.WithRandomSource(&fakeRandomSource{}),
		auth.WithRevocationStore(adapters.NewMemoryRevocationStore()),
	)
	require.NoError(t, err)

	pair, err := svc.IssueTokenPair(context.Background(), auth.IssueRequest{Subject: "user"})
	require.NoError(t, err)
	refreshed, err := svc.RefreshAccessToken(context.Background(), pair.RefreshToken)
	require.NoError(t, err)
	validated, err := svc.ValidateAccessToken(context.Background(), refreshed.AccessToken)
	require.NoError(t, err)

	require.NoError(t, svc.Logout(context.Background(), refreshed.RefreshToken, time.Hour))
	_, err = store.GetAccessSession(context.Background(), validated.AccessTokenID)
	assert.ErrorIs(t, err, auth.ErrSessionNotFound)
	_, err = svc.ValidateAccessToken(context.Background(), refreshed.AccessToken)
	assert.ErrorIs(t, err, auth.ErrTokenRevoked)
	_, err = svc.RefreshAccessToken(context.Background(), refreshed.RefreshToken)
	assert.ErrorIs(t, err, auth.ErrTokenRevoked)
}

func TestService_RevokeSubjectWritesDenylistBeforeIndexCleanup(t *testing.T) {
	clk := newFakeClock(time.Now().UTC().Truncate(time.Second))
	store := adapters.NewMemoryStore()
	svc, err := auth.NewService(
		auth.Config{MaxSessionsPerSubject: 2},
		store,
		auth.WithClock(clk),
		auth.WithRandomSource(&fakeRandomSource{}),
		auth.WithRevocationStore(failingRevocationStore{}),
	)
	require.NoError(t, err)

	_, err = svc.IssueTokenPair(context.Background(), auth.IssueRequest{Subject: "user-order"})
	require.NoError(t, err)
	_, err = svc.IssueTokenPair(context.Background(), auth.IssueRequest{Subject: "user-order"})
	require.NoError(t, err)

	assert.Error(t, svc.RevokeSubject(context.Background(), "user-order", time.Hour))
	refs, err := store.ListBySubject(context.Background(), "user-order")
	require.NoError(t, err)
	assert.Len(t, refs, 2, "index must not be cleaned before denylist succeeds")
}

func TestService_LogoutFallsBackWhenIndexRecordMissing(t *testing.T) {
	clk := newFakeClock(time.Date(2026, 3, 18, 0, 0, 0, 0, time.UTC))
	base := adapters.NewMemoryStore()
	store := &noopRemoveStore{MemoryStore: base}
	svc, err := auth.NewService(
		auth.Config{MaxSessionsPerSubject: 1},
		store,
		auth.WithClock(clk),
		auth.WithRandomSource(&fakeRandomSource{}),
		auth.WithRevocationStore(adapters.NewMemoryRevocationStore()),
	)
	require.NoError(t, err)

	pair, err := svc.IssueTokenPair(context.Background(), auth.IssueRequest{Subject: "user-fallback"})
	require.NoError(t, err)
	validated, err := svc.ValidateAccessToken(context.Background(), pair.AccessToken)
	require.NoError(t, err)

	require.NoError(t, svc.Logout(context.Background(), pair.AccessToken, time.Hour))
	_, err = base.GetAccessSession(context.Background(), validated.AccessTokenID)
	assert.ErrorIs(t, err, auth.ErrSessionNotFound)
}

func TestService_LogoutInvalidatesOldAccessTokens(t *testing.T) {
	clk := newFakeClock(time.Date(2026, 3, 18, 0, 0, 0, 0, time.UTC))
	revocation := adapters.NewMemoryRevocationStore()
	svc, err := auth.NewService(
		auth.DefaultConfig(),
		adapters.NewMemoryStore(),
		auth.WithClock(clk),
		auth.WithRandomSource(&fakeRandomSource{}),
		auth.WithRevocationStore(revocation),
	)
	require.NoError(t, err)

	pair, err := svc.IssueTokenPair(context.Background(), auth.IssueRequest{Subject: "user"})
	require.NoError(t, err)
	refreshed, err := svc.RefreshAccessToken(context.Background(), pair.RefreshToken)
	require.NoError(t, err)

	require.NoError(t, svc.Logout(context.Background(), refreshed.AccessToken, time.Hour))
	_, err = svc.ValidateAccessToken(context.Background(), pair.AccessToken)
	assert.ErrorIs(t, err, auth.ErrTokenRevoked)
	_, err = svc.ValidateAccessToken(context.Background(), refreshed.AccessToken)
	assert.ErrorIs(t, err, auth.ErrTokenRevoked)
	_, err = svc.RefreshAccessToken(context.Background(), refreshed.RefreshToken)
	assert.ErrorIs(t, err, auth.ErrTokenRevoked)
}
