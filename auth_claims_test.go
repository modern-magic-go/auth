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

func TestService_CustomClaimsAndStableSessionID(t *testing.T) {
	clk := newFakeClock(time.Date(2026, 3, 18, 0, 0, 0, 0, time.UTC))
	svc := newTestService(t, auth.Config{
		AccessTokenTTL:  5 * time.Minute,
		RefreshTokenTTL: time.Hour,
		RefreshPolicy:   auth.RefreshPolicyOneTimeRotation,
	}, clk)

	extra := map[string]any{"role": "admin", "tenant": "t-1"}
	pair, err := svc.IssueTokenPair(context.Background(), auth.IssueRequest{
		Subject:     "user-1",
		ExtraClaims: extra,
	})
	require.NoError(t, err)
	require.NotEmpty(t, pair.SessionID)

	validated, err := svc.ValidateAccessToken(context.Background(), pair.AccessToken)
	require.NoError(t, err)
	assert.Equal(t, pair.SessionID, validated.SessionID)
	assert.Equal(t, "admin", validated.ExtraClaims["role"])
	assert.Equal(t, "t-1", validated.ExtraClaims["tenant"])

	refreshToken := pair.RefreshToken
	for index := 0; index < 3; index++ {
		refreshed, err := svc.RefreshAccessToken(context.Background(), refreshToken)
		require.NoError(t, err)
		assert.True(t, refreshed.Rotated)
		assert.Equal(t, pair.SessionID, refreshed.SessionID)
		refreshToken = refreshed.RefreshToken

		validated, err = svc.ValidateAccessToken(context.Background(), refreshed.AccessToken)
		require.NoError(t, err)
		assert.Equal(t, pair.SessionID, validated.SessionID)
		assert.Equal(t, "admin", validated.ExtraClaims["role"])
	}

	second, err := svc.IssueTokenPair(context.Background(), auth.IssueRequest{Subject: "user-1"})
	require.NoError(t, err)
	assert.NotEqual(t, pair.SessionID, second.SessionID)

	_, err = svc.IssueTokenPair(context.Background(), auth.IssueRequest{
		Subject:     "user-1",
		ExtraClaims: map[string]any{"sub": "override"},
	})
	assert.ErrorIs(t, err, auth.ErrReservedClaim)
}

func TestService_TokenVersion(t *testing.T) {
	clk := newFakeClock(time.Date(2026, 3, 18, 0, 0, 0, 0, time.UTC))
	svc := newTestService(t, auth.Config{
		AccessTokenTTL:  5 * time.Minute,
		RefreshTokenTTL: time.Hour,
		RefreshPolicy:   auth.RefreshPolicyOneTimeRotation,
		TokenVersion:    "1",
	}, clk)

	pair, err := svc.IssueTokenPair(context.Background(), auth.IssueRequest{Subject: "user-2"})
	require.NoError(t, err)
	validated, err := svc.ValidateAccessToken(context.Background(), pair.AccessToken)
	require.NoError(t, err)
	assert.Equal(t, "1", validated.Version)

	refreshed, err := svc.RefreshAccessToken(context.Background(), pair.RefreshToken)
	require.NoError(t, err)
	validated, err = svc.ValidateAccessToken(context.Background(), refreshed.AccessToken)
	require.NoError(t, err)
	assert.Equal(t, "1", validated.Version)

	override, err := svc.IssueTokenPair(context.Background(), auth.IssueRequest{
		Subject: "user-2",
		Version: "2",
	})
	require.NoError(t, err)
	validated, err = svc.ValidateAccessToken(context.Background(), override.AccessToken)
	require.NoError(t, err)
	assert.Equal(t, "2", validated.Version)
}

func TestService_OpaqueRefreshPreservesClaimsAndVersion(t *testing.T) {
	clk := newFakeClock(time.Date(2026, 3, 18, 0, 0, 0, 0, time.UTC))
	svc, err := auth.NewService(
		auth.Config{
			AccessTokenTTL:  5 * time.Minute,
			RefreshTokenTTL: time.Hour,
			RefreshPolicy:   auth.RefreshPolicyOneTimeRotation,
			TokenVersion:    "1",
		},
		adapters.NewMemoryStore(),
		auth.WithClock(clk),
		auth.WithRandomSource(&fakeRandomSource{}),
		auth.WithTokenFormat(auth.NewDefaultTokenFormatAdapter()),
		auth.WithOpaqueRefreshToken(
			auth.WithOpaqueRandomSource(&sequenceRandomSource{values: []string{
				opaqueRefreshTestToken(70),
				opaqueRefreshTestToken(71),
			}}),
		),
	)
	require.NoError(t, err)

	pair, err := svc.IssueTokenPair(context.Background(), auth.IssueRequest{
		Subject:     "user-opaque-claims",
		ExtraClaims: map[string]any{"role": "admin"},
	})
	require.NoError(t, err)

	refreshed, err := svc.RefreshAccessToken(context.Background(), pair.RefreshToken)
	require.NoError(t, err)
	assert.Equal(t, pair.SessionID, refreshed.SessionID)

	result, err := svc.ValidateAccessToken(context.Background(), refreshed.AccessToken)
	require.NoError(t, err)
	assert.Equal(t, pair.SessionID, result.SessionID)
	assert.Equal(t, "1", result.Version)
	assert.Equal(t, "admin", result.ExtraClaims["role"])
}

func TestTokenFormatsPreserveSessionIDAndExtraClaims(t *testing.T) {
	clk := newFakeClock(time.Date(2026, 3, 18, 0, 0, 0, 0, time.UTC))
	formats := []struct {
		name   string
		format auth.TokenFormatAdapter
	}{
		{name: "default", format: auth.NewDefaultTokenFormatAdapter()},
		{name: "signed", format: auth.NewSignedTokenFormatAdapter([]byte(jwtTestSecret))},
		{name: "jwt", format: auth.NewJWTHS256FormatAdapter([]byte(jwtTestSecret), auth.WithJWTClock(clk))},
	}

	claims := auth.TokenClaims{
		TokenID:     "jti-1",
		TokenType:   auth.TokenTypeAccess,
		Subject:     "user-3",
		IssuedAt:    clk.Now(),
		ExpiresAt:   clk.Now().Add(10 * time.Minute),
		Version:     "v1.0.0",
		SessionID:   "sid-1",
		ExtraClaims: map[string]any{"role": "admin"},
	}

	for _, testCase := range formats {
		t.Run(testCase.name, func(t *testing.T) {
			token, err := testCase.format.Encode(claims)
			require.NoError(t, err)

			decoded, err := testCase.format.Decode(token)
			require.NoError(t, err)
			assert.Equal(t, claims.TokenID, decoded.TokenID)
			assert.Equal(t, claims.Subject, decoded.Subject)
			assert.Equal(t, claims.SessionID, decoded.SessionID)
			assert.Equal(t, claims.Version, decoded.Version)
			assert.Equal(t, "admin", decoded.ExtraClaims["role"])
		})
	}
}
