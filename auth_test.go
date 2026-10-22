package auth_test

import (
	"context"
	"fmt"
	"sync"
	"testing"
	"time"

	"github.com/modern-magic-go/auth"
	"github.com/modern-magic-go/auth/adapters"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

type fakeClock struct {
	mu  sync.RWMutex
	now time.Time
}

func newFakeClock(now time.Time) *fakeClock {
	return &fakeClock{now: now.UTC()}
}

func (c *fakeClock) Now() time.Time {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.now
}

func (c *fakeClock) Add(d time.Duration) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.now = c.now.Add(d)
}

type fakeRandomSource struct {
	mu sync.Mutex
	n  int
}

func (r *fakeRandomSource) NewID(_ int) (string, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.n++
	return fmt.Sprintf("id-%d", r.n), nil
}

func newTestService(t *testing.T, cfg auth.Config, clk *fakeClock) *auth.Service {
	t.Helper()
	svc, err := auth.NewService(
		cfg,
		adapters.NewMemoryStore(),
		auth.WithClock(clk),
		auth.WithRandomSource(&fakeRandomSource{}),
	)
	require.NoError(t, err)
	return svc
}

func TestService_IssueAndValidate(t *testing.T) {
	clk := newFakeClock(time.Date(2026, 3, 18, 0, 0, 0, 0, time.UTC))
	svc := newTestService(t, auth.Config{
		AccessTokenTTL:  10 * time.Minute,
		RefreshTokenTTL: time.Hour,
	}, clk)

	pair, err := svc.IssueTokenPair(context.Background(), auth.IssueRequest{
		Subject: "123",
		Metadata: auth.SessionMetadata{
			"platform": "app",
			"tenant":   "t-1",
		},
	})
	require.NoError(t, err)
	require.NotEmpty(t, pair.AccessToken)
	require.NotEmpty(t, pair.RefreshToken)

	validated, err := svc.ValidateAccessToken(context.Background(), pair.AccessToken)
	require.NoError(t, err)
	assert.Equal(t, "123", validated.Subject)
	assert.Equal(t, "app", validated.Metadata["platform"])
	assert.Equal(t, "t-1", validated.Metadata["tenant"])
}

func TestService_ValidateBearerHeader_Invalid(t *testing.T) {
	clk := newFakeClock(time.Now())
	svc := newTestService(t, auth.DefaultConfig(), clk)

	_, err := svc.ValidateBearerHeader(context.Background(), "")
	assert.ErrorIs(t, err, auth.ErrInvalidBearerToken)

	_, err = svc.ValidateBearerHeader(context.Background(), "Basic abc")
	assert.ErrorIs(t, err, auth.ErrInvalidBearerToken)
}

func TestService_ExpiredAccessToken(t *testing.T) {
	clk := newFakeClock(time.Date(2026, 3, 18, 0, 0, 0, 0, time.UTC))
	svc := newTestService(t, auth.Config{
		AccessTokenTTL:  time.Minute,
		RefreshTokenTTL: time.Hour,
	}, clk)

	pair, err := svc.IssueTokenPair(context.Background(), auth.IssueRequest{Subject: "100"})
	require.NoError(t, err)

	clk.Add(2 * time.Minute)
	_, err = svc.ValidateAccessToken(context.Background(), pair.AccessToken)
	assert.ErrorIs(t, err, auth.ErrTokenExpired)
}

func TestService_RevokeAccessToken(t *testing.T) {
	clk := newFakeClock(time.Now())
	svc := newTestService(t, auth.DefaultConfig(), clk)

	pair, err := svc.IssueTokenPair(context.Background(), auth.IssueRequest{Subject: "7"})
	require.NoError(t, err)

	require.NoError(t, svc.RevokeAccessToken(context.Background(), pair.AccessToken))
	_, err = svc.ValidateAccessToken(context.Background(), pair.AccessToken)
	assert.ErrorIs(t, err, auth.ErrTokenRevoked)
}

func TestService_RefreshPolicies(t *testing.T) {
	t.Run("reuse until expiry", func(t *testing.T) {
		clk := newFakeClock(time.Date(2026, 3, 18, 0, 0, 0, 0, time.UTC))
		svc := newTestService(t, auth.Config{
			AccessTokenTTL:  5 * time.Minute,
			RefreshTokenTTL: time.Hour,
			RefreshPolicy:   auth.RefreshPolicyReuseUntilExpiry,
		}, clk)

		pair, err := svc.IssueTokenPair(context.Background(), auth.IssueRequest{Subject: "9"})
		require.NoError(t, err)

		refreshed, err := svc.RefreshAccessToken(context.Background(), pair.RefreshToken)
		require.NoError(t, err)
		assert.False(t, refreshed.Rotated)
		assert.Equal(t, pair.RefreshToken, refreshed.RefreshToken)
	})

	t.Run("rotate near expiry", func(t *testing.T) {
		clk := newFakeClock(time.Date(2026, 3, 18, 0, 0, 0, 0, time.UTC))
		svc := newTestService(t, auth.Config{
			AccessTokenTTL:   5 * time.Minute,
			RefreshTokenTTL:  10 * time.Minute,
			RefreshPolicy:    auth.RefreshPolicyRotateNearExpiry,
			RotateNearExpiry: 2 * time.Minute,
		}, clk)

		pair, err := svc.IssueTokenPair(context.Background(), auth.IssueRequest{Subject: "10"})
		require.NoError(t, err)

		first, err := svc.RefreshAccessToken(context.Background(), pair.RefreshToken)
		require.NoError(t, err)
		assert.False(t, first.Rotated)

		clk.Add(9 * time.Minute)
		second, err := svc.RefreshAccessToken(context.Background(), pair.RefreshToken)
		require.NoError(t, err)
		assert.True(t, second.Rotated)
		assert.NotEqual(t, pair.RefreshToken, second.RefreshToken)
	})

	t.Run("one-time rotation concurrent single winner", func(t *testing.T) {
		clk := newFakeClock(time.Date(2026, 3, 18, 0, 0, 0, 0, time.UTC))
		svc := newTestService(t, auth.Config{
			AccessTokenTTL:  5 * time.Minute,
			RefreshTokenTTL: time.Hour,
			RefreshPolicy:   auth.RefreshPolicyOneTimeRotation,
		}, clk)

		pair, err := svc.IssueTokenPair(context.Background(), auth.IssueRequest{Subject: "11"})
		require.NoError(t, err)

		var wg sync.WaitGroup
		wg.Add(2)
		errs := make([]error, 2)
		for i := 0; i < 2; i++ {
			idx := i
			go func() {
				defer wg.Done()
				_, errs[idx] = svc.RefreshAccessToken(context.Background(), pair.RefreshToken)
			}()
		}
		wg.Wait()

		success := 0
		replayed := 0
		for _, e := range errs {
			if e == nil {
				success++
				continue
			}
			if assert.Error(t, e) && assert.ErrorIs(t, e, auth.ErrRefreshTokenReplayed) {
				replayed++
			}
		}
		assert.Equal(t, 1, success)
		assert.Equal(t, 1, replayed)
	})
}
