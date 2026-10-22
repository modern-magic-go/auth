package auth_test

import (
	"context"
	"sync"
	"testing"
	"time"

	"github.com/modern-magic-go/auth"
	"github.com/modern-magic-go/auth/adapters"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestService_MaxSessionsPerSubjectEvictsOldest(t *testing.T) {
	clk := newFakeClock(time.Now().UTC().Truncate(time.Second))
	store := adapters.NewMemoryStore()
	var (
		mu      sync.Mutex
		evicted []auth.SessionRef
	)
	svc, err := auth.NewService(
		auth.Config{
			AccessTokenTTL:        5 * time.Minute,
			RefreshTokenTTL:       time.Hour,
			RefreshPolicy:         auth.RefreshPolicyReuseUntilExpiry,
			MaxSessionsPerSubject: 2,
		},
		store,
		auth.WithClock(clk),
		auth.WithRandomSource(&fakeRandomSource{}),
		auth.WithSessionEvictionHandler(func(_ context.Context, refs []auth.SessionRef) {
			mu.Lock()
			evicted = append(evicted, refs...)
			mu.Unlock()
		}),
	)
	require.NoError(t, err)

	first, err := svc.IssueTokenPair(context.Background(), auth.IssueRequest{Subject: "user-1"})
	require.NoError(t, err)
	clk.Add(time.Second)
	second, err := svc.IssueTokenPair(context.Background(), auth.IssueRequest{Subject: "user-1"})
	require.NoError(t, err)
	clk.Add(time.Second)
	third, err := svc.IssueTokenPair(context.Background(), auth.IssueRequest{Subject: "user-1"})
	require.NoError(t, err)

	refs, err := store.ListBySubject(context.Background(), "user-1")
	require.NoError(t, err)
	require.Len(t, refs, 2)
	assert.Equal(t, second.SessionID, refs[0].SessionID)
	assert.Equal(t, third.SessionID, refs[1].SessionID)

	mu.Lock()
	require.Len(t, evicted, 1)
	assert.Equal(t, first.SessionID, evicted[0].SessionID)
	mu.Unlock()

	_, err = svc.ValidateAccessToken(context.Background(), first.AccessToken)
	assert.ErrorIs(t, err, auth.ErrTokenRevoked)
	_, err = svc.RefreshAccessToken(context.Background(), first.RefreshToken)
	assert.ErrorIs(t, err, auth.ErrTokenRevoked)

	_, err = svc.ValidateAccessToken(context.Background(), second.AccessToken)
	require.NoError(t, err)
	_, err = svc.ValidateAccessToken(context.Background(), third.AccessToken)
	require.NoError(t, err)

	refreshed, err := svc.RefreshAccessToken(context.Background(), third.RefreshToken)
	require.NoError(t, err)
	assert.Equal(t, third.SessionID, refreshed.SessionID)
	refs, err = store.ListBySubject(context.Background(), "user-1")
	require.NoError(t, err)
	assert.Len(t, refs, 2)

	require.NoError(t, svc.RevokeRefreshToken(context.Background(), refreshed.RefreshToken))
	refs, err = store.ListBySubject(context.Background(), "user-1")
	require.NoError(t, err)
	assert.Len(t, refs, 1)
}

func TestService_MaxSessionsConcurrent(t *testing.T) {
	clk := newFakeClock(time.Now().UTC().Truncate(time.Second))
	store := adapters.NewMemoryStore()
	svc, err := auth.NewService(
		auth.Config{
			AccessTokenTTL:        5 * time.Minute,
			RefreshTokenTTL:       time.Hour,
			RefreshPolicy:         auth.RefreshPolicyReuseUntilExpiry,
			MaxSessionsPerSubject: 5,
		},
		store,
		auth.WithClock(clk),
		auth.WithRandomSource(&fakeRandomSource{}),
	)
	require.NoError(t, err)

	const logins = 6
	var wg sync.WaitGroup
	wg.Add(logins)
	errs := make([]error, logins)
	for index := 0; index < logins; index++ {
		idx := index
		go func() {
			defer wg.Done()
			_, errs[idx] = svc.IssueTokenPair(context.Background(), auth.IssueRequest{Subject: "user-concurrent"})
		}()
	}
	wg.Wait()
	for _, err := range errs {
		require.NoError(t, err)
	}

	refs, err := store.ListBySubject(context.Background(), "user-concurrent")
	require.NoError(t, err)
	assert.Len(t, refs, 5)
}
