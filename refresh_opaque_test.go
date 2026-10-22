package auth_test

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/modern-magic-go/auth"
	"github.com/modern-magic-go/auth/adapters"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

type sequenceRandomSource struct {
	mu     sync.Mutex
	values []string
	index  int
}

func (r *sequenceRandomSource) NewID(_ int) (string, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.index >= len(r.values) {
		return "", fmt.Errorf("sequence random source exhausted")
	}
	value := r.values[r.index]
	r.index++
	return value, nil
}

type recordingStore struct {
	*adapters.MemoryStore

	mu              sync.Mutex
	refreshIDs      []string
	refreshSessions []auth.RefreshSession
}

func newRecordingStore() *recordingStore {
	return &recordingStore{MemoryStore: adapters.NewMemoryStore()}
}

func (s *recordingStore) SaveRefreshSession(ctx context.Context, tokenID string, session auth.RefreshSession, ttl time.Duration) error {
	s.mu.Lock()
	s.refreshIDs = append(s.refreshIDs, tokenID)
	s.refreshSessions = append(s.refreshSessions, session)
	s.mu.Unlock()
	return s.MemoryStore.SaveRefreshSession(ctx, tokenID, session, ttl)
}

func (s *recordingStore) RotateRefreshSession(ctx context.Context, oldTokenID, newTokenID string, newSession auth.RefreshSession, ttl time.Duration) (bool, error) {
	s.mu.Lock()
	s.refreshIDs = append(s.refreshIDs, newTokenID)
	s.refreshSessions = append(s.refreshSessions, newSession)
	s.mu.Unlock()
	return s.MemoryStore.RotateRefreshSession(ctx, oldTokenID, newTokenID, newSession, ttl)
}

func TestOpaqueRefreshTokenFormat(t *testing.T) {
	first := opaqueRefreshTestToken(1)
	second := opaqueRefreshTestToken(2)
	format := auth.NewOpaqueRefreshTokenFormat(
		auth.WithOpaqueRandomSource(&sequenceRandomSource{values: []string{first, second}}),
	)

	token, id, err := format.Generate()
	require.NoError(t, err)
	assert.Equal(t, first, token)
	assert.Len(t, token, 43)
	assert.NotContains(t, token, ".")
	assert.Equal(t, opaqueRefreshTestID(token), id)

	parsedID, err := format.Parse(token)
	require.NoError(t, err)
	assert.Equal(t, id, parsedID)

	nextToken, nextID, err := format.Generate()
	require.NoError(t, err)
	assert.Equal(t, second, nextToken)
	assert.NotEqual(t, id, nextID)

	for _, invalid := range []string{
		"",
		"not-a-token",
		first + ".jwt",
		base64.RawURLEncoding.EncodeToString([]byte("too-short")),
	} {
		_, err := format.Parse(invalid)
		assert.ErrorIs(t, err, auth.ErrInvalidTokenFormat)
	}

	broken := auth.NewOpaqueRefreshTokenFormat(
		auth.WithOpaqueRandomSource(&sequenceRandomSource{values: []string{"too-short"}}),
	)
	_, _, err = broken.Generate()
	assert.ErrorIs(t, err, auth.ErrInvalidTokenFormat)
}

func TestService_JWTAndOpaqueRefresh(t *testing.T) {
	clk := newFakeClock(time.Date(2026, 3, 18, 0, 0, 0, 0, time.UTC))
	firstRefresh := opaqueRefreshTestToken(10)
	secondRefresh := opaqueRefreshTestToken(20)
	thirdRefresh := opaqueRefreshTestToken(30)
	jwtAdapter := auth.NewJWTHS256FormatAdapter(
		[]byte(jwtTestSecret),
		auth.WithJWTIssuer("auth-service"),
		auth.WithJWTAudience("admin-api"),
		auth.WithJWTClock(clk),
	)
	svc, err := auth.NewService(
		auth.Config{
			AccessTokenTTL:  5 * time.Minute,
			RefreshTokenTTL: time.Hour,
			RefreshPolicy:   auth.RefreshPolicyOneTimeRotation,
		},
		adapters.NewMemoryStore(),
		auth.WithClock(clk),
		auth.WithRandomSource(&fakeRandomSource{}),
		auth.WithAccessTokenFormat(jwtAdapter),
		auth.WithOpaqueRefreshToken(
			auth.WithOpaqueRandomSource(&sequenceRandomSource{values: []string{firstRefresh, secondRefresh, thirdRefresh}}),
		),
	)
	require.NoError(t, err)

	pair, err := svc.IssueTokenPair(context.Background(), auth.IssueRequest{
		Subject: "user-1",
		Metadata: auth.SessionMetadata{
			"platform": "web",
		},
	})
	require.NoError(t, err)

	assert.Len(t, strings.Split(pair.AccessToken, "."), 3)
	assert.Equal(t, firstRefresh, pair.RefreshToken)
	assert.Len(t, pair.RefreshToken, 43)
	assert.NotContains(t, pair.RefreshToken, ".")

	validated, err := svc.ValidateAccessToken(context.Background(), pair.AccessToken)
	require.NoError(t, err)
	assert.Equal(t, "user-1", validated.Subject)
	assert.Equal(t, "web", validated.Metadata["platform"])
	assert.Equal(t, opaqueRefreshTestID(pair.RefreshToken), validated.RefreshTokenID)

	refreshed, err := svc.RefreshAccessToken(context.Background(), pair.RefreshToken)
	require.NoError(t, err)
	assert.True(t, refreshed.Rotated)
	assert.Equal(t, secondRefresh, refreshed.RefreshToken)
	assert.Len(t, strings.Split(refreshed.AccessToken, "."), 3)

	_, err = svc.ValidateAccessToken(context.Background(), refreshed.AccessToken)
	require.NoError(t, err)

	_, err = svc.RefreshAccessToken(context.Background(), pair.RefreshToken)
	assert.ErrorIs(t, err, auth.ErrRefreshTokenReplayed)

	_, err = svc.RefreshAccessToken(context.Background(), refreshed.RefreshToken)
	require.NoError(t, err)
}

func TestService_OpaqueRefreshReuseAndRevoke(t *testing.T) {
	clk := newFakeClock(time.Date(2026, 3, 18, 0, 0, 0, 0, time.UTC))
	refreshTokenValue := opaqueRefreshTestToken(30)
	svc, err := auth.NewService(
		auth.Config{
			AccessTokenTTL:  5 * time.Minute,
			RefreshTokenTTL: time.Hour,
			RefreshPolicy:   auth.RefreshPolicyReuseUntilExpiry,
		},
		adapters.NewMemoryStore(),
		auth.WithClock(clk),
		auth.WithRandomSource(&fakeRandomSource{}),
		auth.WithOpaqueRefreshToken(
			auth.WithOpaqueRandomSource(&sequenceRandomSource{values: []string{refreshTokenValue}}),
		),
	)
	require.NoError(t, err)

	pair, err := svc.IssueTokenPair(context.Background(), auth.IssueRequest{Subject: "user-2"})
	require.NoError(t, err)

	refreshed, err := svc.RefreshAccessToken(context.Background(), pair.RefreshToken)
	require.NoError(t, err)
	assert.False(t, refreshed.Rotated)
	assert.Equal(t, pair.RefreshToken, refreshed.RefreshToken)

	require.NoError(t, svc.RevokeRefreshToken(context.Background(), pair.RefreshToken))
	_, err = svc.RefreshAccessToken(context.Background(), pair.RefreshToken)
	assert.ErrorIs(t, err, auth.ErrTokenRevoked)
}

func TestService_OpaqueRefreshExpired(t *testing.T) {
	clk := newFakeClock(time.Date(2026, 3, 18, 0, 0, 0, 0, time.UTC))
	svc, err := auth.NewService(
		auth.Config{
			AccessTokenTTL:  5 * time.Minute,
			RefreshTokenTTL: time.Hour,
			RefreshPolicy:   auth.RefreshPolicyReuseUntilExpiry,
		},
		adapters.NewMemoryStore(),
		auth.WithClock(clk),
		auth.WithRandomSource(&fakeRandomSource{}),
		auth.WithOpaqueRefreshToken(
			auth.WithOpaqueRandomSource(&sequenceRandomSource{values: []string{opaqueRefreshTestToken(40)}}),
		),
	)
	require.NoError(t, err)

	pair, err := svc.IssueTokenPair(context.Background(), auth.IssueRequest{Subject: "user-3"})
	require.NoError(t, err)

	clk.Add(2 * time.Hour)
	_, err = svc.RefreshAccessToken(context.Background(), pair.RefreshToken)
	assert.ErrorIs(t, err, auth.ErrTokenExpired)
}

func TestService_AccessFormatOnlyFallsBackToJWTRefresh(t *testing.T) {
	clk := newFakeClock(time.Date(2026, 3, 18, 0, 0, 0, 0, time.UTC))
	jwtAdapter := auth.NewJWTHS256FormatAdapter(
		[]byte(jwtTestSecret),
		auth.WithJWTClock(clk),
	)
	svc, err := auth.NewService(
		auth.Config{
			AccessTokenTTL:  5 * time.Minute,
			RefreshTokenTTL: time.Hour,
			RefreshPolicy:   auth.RefreshPolicyReuseUntilExpiry,
		},
		adapters.NewMemoryStore(),
		auth.WithClock(clk),
		auth.WithRandomSource(&fakeRandomSource{}),
		auth.WithAccessTokenFormat(jwtAdapter),
	)
	require.NoError(t, err)

	pair, err := svc.IssueTokenPair(context.Background(), auth.IssueRequest{Subject: "user-4"})
	require.NoError(t, err)
	assert.Len(t, strings.Split(pair.AccessToken, "."), 3)
	assert.Len(t, strings.Split(pair.RefreshToken, "."), 3)

	refreshed, err := svc.RefreshAccessToken(context.Background(), pair.RefreshToken)
	require.NoError(t, err)
	assert.False(t, refreshed.Rotated)
	assert.Equal(t, pair.RefreshToken, refreshed.RefreshToken)
}

func TestService_WithTokenFormatStillUsesSingleFormat(t *testing.T) {
	clk := newFakeClock(time.Date(2026, 3, 18, 0, 0, 0, 0, time.UTC))
	svc, err := auth.NewService(
		auth.Config{
			AccessTokenTTL:  5 * time.Minute,
			RefreshTokenTTL: time.Hour,
			RefreshPolicy:   auth.RefreshPolicyReuseUntilExpiry,
		},
		adapters.NewMemoryStore(),
		auth.WithClock(clk),
		auth.WithRandomSource(&fakeRandomSource{}),
		auth.WithTokenFormat(auth.NewSignedTokenFormatAdapter([]byte(jwtTestSecret))),
	)
	require.NoError(t, err)

	pair, err := svc.IssueTokenPair(context.Background(), auth.IssueRequest{Subject: "user-5"})
	require.NoError(t, err)
	assert.Len(t, strings.Split(pair.AccessToken, "."), 2)
	assert.Len(t, strings.Split(pair.RefreshToken, "."), 2)

	refreshed, err := svc.RefreshAccessToken(context.Background(), pair.RefreshToken)
	require.NoError(t, err)
	assert.Equal(t, pair.RefreshToken, refreshed.RefreshToken)
}

func TestService_OpaqueRefreshConcurrentSingleWinner(t *testing.T) {
	clk := newFakeClock(time.Date(2026, 3, 18, 0, 0, 0, 0, time.UTC))
	svc, err := auth.NewService(
		auth.Config{
			AccessTokenTTL:  5 * time.Minute,
			RefreshTokenTTL: time.Hour,
			RefreshPolicy:   auth.RefreshPolicyOneTimeRotation,
		},
		adapters.NewMemoryStore(),
		auth.WithClock(clk),
		auth.WithRandomSource(&fakeRandomSource{}),
		auth.WithOpaqueRefreshToken(
			auth.WithOpaqueRandomSource(&sequenceRandomSource{values: []string{
				opaqueRefreshTestToken(50),
				opaqueRefreshTestToken(51),
				opaqueRefreshTestToken(52),
			}}),
		),
	)
	require.NoError(t, err)

	pair, err := svc.IssueTokenPair(context.Background(), auth.IssueRequest{Subject: "user-6"})
	require.NoError(t, err)

	var wg sync.WaitGroup
	wg.Add(2)
	errs := make([]error, 2)
	for index := 0; index < 2; index++ {
		idx := index
		go func() {
			defer wg.Done()
			_, errs[idx] = svc.RefreshAccessToken(context.Background(), pair.RefreshToken)
		}()
	}
	wg.Wait()

	success := 0
	replayed := 0
	for _, refreshErr := range errs {
		if refreshErr == nil {
			success++
			continue
		}
		if assert.ErrorIs(t, refreshErr, auth.ErrRefreshTokenReplayed) {
			replayed++
		}
	}
	assert.Equal(t, 1, success)
	assert.Equal(t, 1, replayed)
}

func TestService_OpaqueRefreshStoresOnlyHash(t *testing.T) {
	clk := newFakeClock(time.Date(2026, 3, 18, 0, 0, 0, 0, time.UTC))
	store := newRecordingStore()
	refreshTokenValue := opaqueRefreshTestToken(60)
	svc, err := auth.NewService(
		auth.Config{
			AccessTokenTTL:  5 * time.Minute,
			RefreshTokenTTL: time.Hour,
			RefreshPolicy:   auth.RefreshPolicyReuseUntilExpiry,
		},
		store,
		auth.WithClock(clk),
		auth.WithRandomSource(&fakeRandomSource{}),
		auth.WithOpaqueRefreshToken(
			auth.WithOpaqueRandomSource(&sequenceRandomSource{values: []string{refreshTokenValue}}),
		),
	)
	require.NoError(t, err)

	pair, err := svc.IssueTokenPair(context.Background(), auth.IssueRequest{Subject: "user-7"})
	require.NoError(t, err)
	require.Equal(t, refreshTokenValue, pair.RefreshToken)

	store.mu.Lock()
	recordedIDs := append([]string(nil), store.refreshIDs...)
	recordedSessions := append([]auth.RefreshSession(nil), store.refreshSessions...)
	store.mu.Unlock()

	require.NotEmpty(t, recordedIDs)
	expectedID := opaqueRefreshTestID(pair.RefreshToken)
	assert.Equal(t, expectedID, recordedIDs[0])
	assert.NotEqual(t, pair.RefreshToken, recordedIDs[0])
	assert.Equal(t, expectedID, recordedSessions[0].TokenID)
	assert.NotContains(t, fmt.Sprintf("%+v", recordedSessions[0]), pair.RefreshToken)
}

func opaqueRefreshTestToken(seed byte) string {
	bytes := make([]byte, 32)
	for index := range bytes {
		bytes[index] = seed + byte(index)
	}
	return base64.RawURLEncoding.EncodeToString(bytes)
}

func opaqueRefreshTestID(token string) string {
	sum := sha256.Sum256([]byte(token))
	return base64.RawURLEncoding.EncodeToString(sum[:])
}
