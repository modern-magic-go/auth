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

type noAccessLookupStore struct {
	*adapters.MemoryStore
	mu    sync.Mutex
	calls int
}

func (s *noAccessLookupStore) GetAccessSession(ctx context.Context, tokenID string) (auth.AccessSession, error) {
	s.mu.Lock()
	s.calls++
	s.mu.Unlock()
	return s.MemoryStore.GetAccessSession(ctx, tokenID)
}

func (s *noAccessLookupStore) callCount() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.calls
}

func TestService_StatelessAccessToken(t *testing.T) {
	clk := newFakeClock(time.Date(2026, 3, 18, 0, 0, 0, 0, time.UTC))
	store := &noAccessLookupStore{MemoryStore: adapters.NewMemoryStore()}
	jwtFormat := auth.NewJWTHS256FormatAdapter(
		[]byte(jwtTestSecret),
		auth.WithJWTClock(clk),
		auth.WithJWTIssuer("auth-service"),
	)
	svc, err := auth.NewService(
		auth.Config{
			AccessTokenTTL:  5 * time.Minute,
			RefreshTokenTTL: time.Hour,
			RefreshPolicy:   auth.RefreshPolicyReuseUntilExpiry,
			AccessTokenMode: auth.AccessTokenStateless,
		},
		store,
		auth.WithClock(clk),
		auth.WithRandomSource(&fakeRandomSource{}),
		auth.WithAccessTokenFormat(jwtFormat),
	)
	require.NoError(t, err)

	pair, err := svc.IssueTokenPair(context.Background(), auth.IssueRequest{
		Subject:     "user-stateless",
		ExtraClaims: map[string]any{"role": "admin"},
	})
	require.NoError(t, err)

	result, err := svc.ValidateAccessToken(context.Background(), pair.AccessToken)
	require.NoError(t, err)
	assert.Equal(t, "user-stateless", result.Subject)
	assert.Equal(t, pair.SessionID, result.SessionID)
	assert.Equal(t, "admin", result.ExtraClaims["role"])
	assert.Empty(t, result.RefreshTokenID)
	assert.Equal(t, 0, store.callCount(), "stateless validation must not read access sessions")

	err = svc.RenewAccessToken(context.Background(), pair.AccessToken, time.Minute)
	assert.ErrorIs(t, err, auth.ErrUnsupportedMode)
}

func TestService_StatelessRequiresSignedFormatAndNoSliding(t *testing.T) {
	clk := newFakeClock(time.Date(2026, 3, 18, 0, 0, 0, 0, time.UTC))
	_, err := auth.NewService(
		auth.Config{AccessTokenMode: auth.AccessTokenStateless},
		adapters.NewMemoryStore(),
		auth.WithClock(clk),
	)
	assert.ErrorIs(t, err, auth.ErrInvalidConfig)

	_, err = auth.NewService(
		auth.Config{
			AccessTokenMode:   auth.AccessTokenStateless,
			SlidingExpiration: true,
		},
		adapters.NewMemoryStore(),
		auth.WithClock(clk),
		auth.WithAccessTokenFormat(auth.NewSignedTokenFormatAdapter([]byte(jwtTestSecret))),
	)
	assert.ErrorIs(t, err, auth.ErrInvalidConfig)
}

func TestService_StatelessRevocation(t *testing.T) {
	clk := newFakeClock(time.Date(2026, 3, 18, 0, 0, 0, 0, time.UTC))
	revocation := adapters.NewMemoryRevocationStore()
	jwtFormat := auth.NewJWTHS256FormatAdapter(
		[]byte(jwtTestSecret),
		auth.WithJWTClock(clk),
	)
	svc, err := auth.NewService(
		auth.Config{
			AccessTokenTTL:  5 * time.Minute,
			RefreshTokenTTL: time.Hour,
			RefreshPolicy:   auth.RefreshPolicyReuseUntilExpiry,
			AccessTokenMode: auth.AccessTokenStateless,
		},
		adapters.NewMemoryStore(),
		auth.WithClock(clk),
		auth.WithRandomSource(&fakeRandomSource{}),
		auth.WithAccessTokenFormat(jwtFormat),
		auth.WithRevocationStore(revocation),
	)
	require.NoError(t, err)

	pair, err := svc.IssueTokenPair(context.Background(), auth.IssueRequest{Subject: "user-revoke"})
	require.NoError(t, err)

	logoutPair, err := svc.IssueTokenPair(context.Background(), auth.IssueRequest{Subject: "user-logout"})
	require.NoError(t, err)
	require.NoError(t, svc.Logout(context.Background(), logoutPair.AccessToken, time.Hour))
	_, err = svc.ValidateAccessToken(context.Background(), logoutPair.AccessToken)
	assert.ErrorIs(t, err, auth.ErrTokenRevoked)

	require.NoError(t, svc.RevokeSession(context.Background(), pair.SessionID, time.Hour))
	_, err = svc.ValidateAccessToken(context.Background(), pair.AccessToken)
	assert.ErrorIs(t, err, auth.ErrTokenRevoked)
	_, err = svc.RefreshAccessToken(context.Background(), pair.RefreshToken)
	assert.ErrorIs(t, err, auth.ErrTokenRevoked)

	require.NoError(t, svc.RevokeSubject(context.Background(), "user-revoke", time.Hour))
	_, err = svc.ValidateAccessToken(context.Background(), pair.AccessToken)
	assert.ErrorIs(t, err, auth.ErrTokenRevoked)
}

func TestService_StatelessRevokeWithoutStore(t *testing.T) {
	clk := newFakeClock(time.Date(2026, 3, 18, 0, 0, 0, 0, time.UTC))
	svc, err := auth.NewService(
		auth.Config{
			AccessTokenMode: auth.AccessTokenStateless,
			AccessTokenTTL:  5 * time.Minute,
		},
		adapters.NewMemoryStore(),
		auth.WithClock(clk),
		auth.WithRandomSource(&fakeRandomSource{}),
		auth.WithAccessTokenFormat(auth.NewJWTHS256FormatAdapter(
			[]byte(jwtTestSecret),
			auth.WithJWTClock(clk),
		)),
	)
	require.NoError(t, err)

	pair, err := svc.IssueTokenPair(context.Background(), auth.IssueRequest{Subject: "user"})
	require.NoError(t, err)
	assert.ErrorIs(t, svc.RevokeAccessToken(context.Background(), pair.AccessToken), auth.ErrRevocationNotConfigured)
	assert.ErrorIs(t, svc.Logout(context.Background(), pair.AccessToken, time.Minute), auth.ErrRevocationNotConfigured)
}
