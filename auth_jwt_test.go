package auth_test

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/modern-magic-go/auth"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const jwtTestSecret = "0123456789abcdef0123456789abcdef"

func TestJWTHS256FormatAdapter_RoundTrip(t *testing.T) {
	clk := newFakeClock(time.Date(2026, 3, 18, 0, 0, 0, 0, time.UTC))
	adapter := auth.NewJWTHS256FormatAdapter(
		[]byte(jwtTestSecret),
		auth.WithJWTIssuer("auth-service"),
		auth.WithJWTAudience("admin-api", "merchant-api"),
		auth.WithJWTClock(clk),
	)

	claims := auth.TokenClaims{
		TokenID:   "jti-1",
		TokenType: auth.TokenTypeAccess,
		Subject:   "user-1",
		IssuedAt:  clk.Now(),
		ExpiresAt: clk.Now().Add(10 * time.Minute),
		Version:   "v1.0.0",
	}
	token, err := adapter.Encode(claims)
	require.NoError(t, err)

	parts := strings.Split(token, ".")
	require.Len(t, parts, 3)

	headerBytes, err := base64.RawURLEncoding.DecodeString(parts[0])
	require.NoError(t, err)
	var header map[string]any
	require.NoError(t, json.Unmarshal(headerBytes, &header))
	assert.Equal(t, "HS256", header["alg"])
	assert.Equal(t, "JWT", header["typ"])

	payloadBytes, err := base64.RawURLEncoding.DecodeString(parts[1])
	require.NoError(t, err)
	var payload map[string]any
	require.NoError(t, json.Unmarshal(payloadBytes, &payload))
	assert.Equal(t, "jti-1", payload["jti"])
	assert.Equal(t, "access", payload["typ"])
	assert.Equal(t, "user-1", payload["sub"])
	assert.Equal(t, "v1.0.0", payload["ver"])
	assert.Equal(t, "auth-service", payload["iss"])
	assert.ElementsMatch(t, []any{"admin-api", "merchant-api"}, payload["aud"])

	decoded, err := adapter.Decode(token)
	require.NoError(t, err)
	assert.Equal(t, claims.TokenID, decoded.TokenID)
	assert.Equal(t, claims.TokenType, decoded.TokenType)
	assert.Equal(t, claims.Subject, decoded.Subject)
	assert.Equal(t, claims.IssuedAt, decoded.IssuedAt)
	assert.Equal(t, claims.ExpiresAt, decoded.ExpiresAt)
	assert.Equal(t, claims.Version, decoded.Version)
}

func TestJWTHS256FormatAdapter_Audience(t *testing.T) {
	clk := newFakeClock(time.Date(2026, 3, 18, 0, 0, 0, 0, time.UTC))
	adapter := auth.NewJWTHS256FormatAdapter(
		[]byte(jwtTestSecret),
		auth.WithJWTAudience("admin-api"),
		auth.WithJWTClock(clk),
	)

	base := func() map[string]any {
		return map[string]any{
			"jti": "jti-1",
			"typ": "access",
			"sub": "user-1",
			"iat": clk.Now().Unix(),
			"exp": clk.Now().Add(10 * time.Minute).Unix(),
			"ver": "v1.0.0",
			"iss": "auth-service",
		}
	}

	t.Run("string audience", func(t *testing.T) {
		payload := base()
		payload["aud"] = "admin-api"
		_, err := adapter.Decode(signJWTTestToken(t, []byte(jwtTestSecret), jwtTestHeader(), payload, false))
		require.NoError(t, err)
	})

	t.Run("array audience", func(t *testing.T) {
		payload := base()
		payload["aud"] = []string{"merchant-api", "admin-api"}
		_, err := adapter.Decode(signJWTTestToken(t, []byte(jwtTestSecret), jwtTestHeader(), payload, false))
		require.NoError(t, err)
	})

	t.Run("missing audience", func(t *testing.T) {
		_, err := adapter.Decode(signJWTTestToken(t, []byte(jwtTestSecret), jwtTestHeader(), base(), false))
		assert.ErrorIs(t, err, auth.ErrInvalidTokenFormat)
	})

	t.Run("wrong audience", func(t *testing.T) {
		payload := base()
		payload["aud"] = "other-api"
		_, err := adapter.Decode(signJWTTestToken(t, []byte(jwtTestSecret), jwtTestHeader(), payload, false))
		assert.ErrorIs(t, err, auth.ErrInvalidTokenFormat)
	})

	t.Run("invalid audience type", func(t *testing.T) {
		payload := base()
		payload["aud"] = 123
		_, err := adapter.Decode(signJWTTestToken(t, []byte(jwtTestSecret), jwtTestHeader(), payload, false))
		assert.ErrorIs(t, err, auth.ErrInvalidTokenFormat)
	})
}

func TestJWTHS256FormatAdapter_RejectsInvalidClaimsAndHeaders(t *testing.T) {
	clk := newFakeClock(time.Date(2026, 3, 18, 0, 0, 0, 0, time.UTC))
	adapter := auth.NewJWTHS256FormatAdapter([]byte(jwtTestSecret), auth.WithJWTClock(clk))

	basePayload := func() map[string]any {
		return map[string]any{
			"jti": "jti-1",
			"typ": "access",
			"sub": "user-1",
			"iat": clk.Now().Unix(),
			"exp": clk.Now().Add(10 * time.Minute).Unix(),
			"ver": "v1.0.0",
		}
	}
	baseHeader := func() map[string]any {
		return map[string]any{"alg": "HS256", "typ": "JWT"}
	}

	tests := []struct {
		name    string
		header  map[string]any
		payload map[string]any
	}{
		{
			name:    "alg none",
			header:  map[string]any{"alg": "none", "typ": "JWT"},
			payload: basePayload(),
		},
		{
			name:    "alg RS256",
			header:  map[string]any{"alg": "RS256", "typ": "JWT"},
			payload: basePayload(),
		},
		{
			name:    "wrong header typ",
			header:  map[string]any{"alg": "HS256", "typ": "JWS"},
			payload: basePayload(),
		},
		{
			name:    "missing header typ",
			header:  map[string]any{"alg": "HS256"},
			payload: basePayload(),
		},
		{
			name:   "missing ver",
			header: baseHeader(),
			payload: func() map[string]any {
				p := basePayload()
				delete(p, "ver")
				return p
			}(),
		},
		{
			name:   "missing jti",
			header: baseHeader(),
			payload: func() map[string]any {
				p := basePayload()
				delete(p, "jti")
				return p
			}(),
		},
		{
			name:   "missing subject",
			header: baseHeader(),
			payload: func() map[string]any {
				p := basePayload()
				delete(p, "sub")
				return p
			}(),
		},
		{
			name:   "missing iat",
			header: baseHeader(),
			payload: func() map[string]any {
				p := basePayload()
				delete(p, "iat")
				return p
			}(),
		},
		{
			name:   "missing exp",
			header: baseHeader(),
			payload: func() map[string]any {
				p := basePayload()
				delete(p, "exp")
				return p
			}(),
		},
		{
			name:   "invalid token type",
			header: baseHeader(),
			payload: func() map[string]any {
				p := basePayload()
				p["typ"] = "other"
				return p
			}(),
		},
		{
			name:   "exp before iat",
			header: baseHeader(),
			payload: func() map[string]any {
				p := basePayload()
				p["exp"] = p["iat"].(int64) - 1
				return p
			}(),
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			token := signJWTTestToken(t, []byte(jwtTestSecret), tc.header, tc.payload, false)
			_, err := adapter.Decode(token)
			assert.ErrorIs(t, err, auth.ErrInvalidTokenFormat)
		})
	}

	t.Run("wrong signature", func(t *testing.T) {
		token := signJWTTestToken(t, []byte("another-secret-another-secret-32"), baseHeader(), basePayload(), false)
		_, err := adapter.Decode(token)
		assert.ErrorIs(t, err, auth.ErrInvalidTokenFormat)
	})

	t.Run("tampered payload", func(t *testing.T) {
		token := signJWTTestToken(t, []byte(jwtTestSecret), baseHeader(), basePayload(), false)
		parts := strings.Split(token, ".")
		parts[1] = parts[1] + "a"
		_, err := adapter.Decode(strings.Join(parts, "."))
		assert.ErrorIs(t, err, auth.ErrInvalidTokenFormat)
	})

	for _, token := range []string{
		"",
		"a.b",
		"a.b.c.d",
		"..",
		"!!!.???.$$$",
	} {
		_, err := adapter.Decode(token)
		assert.ErrorIs(t, err, auth.ErrInvalidTokenFormat)
	}
}

func TestJWTHS256FormatAdapter_TimeValidation(t *testing.T) {
	clk := newFakeClock(time.Date(2026, 3, 18, 0, 0, 0, 0, time.UTC))

	t.Run("default leeway allows recent expiry", func(t *testing.T) {
		adapter := auth.NewJWTHS256FormatAdapter([]byte(jwtTestSecret), auth.WithJWTClock(clk))
		payload := map[string]any{
			"jti": "jti-1",
			"typ": "access",
			"sub": "user-1",
			"iat": clk.Now().Add(-time.Hour).Unix(),
			"exp": clk.Now().Add(-10 * time.Second).Unix(),
			"ver": "v1.0.0",
		}
		_, err := adapter.Decode(signJWTTestToken(t, []byte(jwtTestSecret), jwtTestHeader(), payload, false))
		require.NoError(t, err)
	})

	t.Run("default leeway rejects expiry beyond 30s", func(t *testing.T) {
		adapter := auth.NewJWTHS256FormatAdapter([]byte(jwtTestSecret), auth.WithJWTClock(clk))
		payload := map[string]any{
			"jti": "jti-1",
			"typ": "access",
			"sub": "user-1",
			"iat": clk.Now().Add(-time.Hour).Unix(),
			"exp": clk.Now().Add(-31 * time.Second).Unix(),
			"ver": "v1.0.0",
		}
		_, err := adapter.Decode(signJWTTestToken(t, []byte(jwtTestSecret), jwtTestHeader(), payload, false))
		assert.ErrorIs(t, err, auth.ErrTokenExpired)
	})

	t.Run("zero leeway rejects immediately expired token", func(t *testing.T) {
		adapter := auth.NewJWTHS256FormatAdapter(
			[]byte(jwtTestSecret),
			auth.WithJWTClock(clk),
			auth.WithJWTLeeway(0),
		)
		payload := map[string]any{
			"jti": "jti-1",
			"typ": "access",
			"sub": "user-1",
			"iat": clk.Now().Add(-time.Hour).Unix(),
			"exp": clk.Now().Add(-time.Second).Unix(),
			"ver": "v1.0.0",
		}
		_, err := adapter.Decode(signJWTTestToken(t, []byte(jwtTestSecret), jwtTestHeader(), payload, false))
		assert.ErrorIs(t, err, auth.ErrTokenExpired)
	})

	t.Run("future issued at", func(t *testing.T) {
		adapter := auth.NewJWTHS256FormatAdapter([]byte(jwtTestSecret), auth.WithJWTClock(clk))
		payload := map[string]any{
			"jti": "jti-1",
			"typ": "access",
			"sub": "user-1",
			"iat": clk.Now().Add(time.Minute).Unix(),
			"exp": clk.Now().Add(10 * time.Minute).Unix(),
			"ver": "v1.0.0",
		}
		_, err := adapter.Decode(signJWTTestToken(t, []byte(jwtTestSecret), jwtTestHeader(), payload, false))
		assert.ErrorIs(t, err, auth.ErrInvalidTokenFormat)
	})

	t.Run("not before in future", func(t *testing.T) {
		adapter := auth.NewJWTHS256FormatAdapter([]byte(jwtTestSecret), auth.WithJWTClock(clk))
		payload := map[string]any{
			"jti": "jti-1",
			"typ": "access",
			"sub": "user-1",
			"iat": clk.Now().Unix(),
			"nbf": clk.Now().Add(time.Minute).Unix(),
			"exp": clk.Now().Add(10 * time.Minute).Unix(),
			"ver": "v1.0.0",
		}
		_, err := adapter.Decode(signJWTTestToken(t, []byte(jwtTestSecret), jwtTestHeader(), payload, false))
		assert.ErrorIs(t, err, auth.ErrInvalidTokenFormat)
	})

	t.Run("not before in past", func(t *testing.T) {
		adapter := auth.NewJWTHS256FormatAdapter([]byte(jwtTestSecret), auth.WithJWTClock(clk))
		payload := map[string]any{
			"jti": "jti-1",
			"typ": "access",
			"sub": "user-1",
			"iat": clk.Now().Unix(),
			"nbf": clk.Now().Add(-time.Minute).Unix(),
			"exp": clk.Now().Add(10 * time.Minute).Unix(),
			"ver": "v1.0.0",
		}
		_, err := adapter.Decode(signJWTTestToken(t, []byte(jwtTestSecret), jwtTestHeader(), payload, false))
		require.NoError(t, err)
	})
}

func TestJWTHS256FormatAdapter_IssuerAndPadding(t *testing.T) {
	clk := newFakeClock(time.Date(2026, 3, 18, 0, 0, 0, 0, time.UTC))
	adapter := auth.NewJWTHS256FormatAdapter(
		[]byte(jwtTestSecret),
		auth.WithJWTIssuer("auth-service"),
		auth.WithJWTClock(clk),
	)
	payload := map[string]any{
		"jti": "jti-1",
		"typ": "access",
		"sub": "user-1",
		"iat": clk.Now().Unix(),
		"exp": clk.Now().Add(10 * time.Minute).Unix(),
		"ver": "v1.0.0",
		"iss": "auth-service",
	}
	header := jwtTestHeader()

	t.Run("correct issuer", func(t *testing.T) {
		_, err := adapter.Decode(signJWTTestToken(t, []byte(jwtTestSecret), header, payload, false))
		require.NoError(t, err)
	})

	t.Run("wrong issuer", func(t *testing.T) {
		p := copyStringAnyMap(payload)
		p["iss"] = "other-service"
		_, err := adapter.Decode(signJWTTestToken(t, []byte(jwtTestSecret), header, p, false))
		assert.ErrorIs(t, err, auth.ErrInvalidTokenFormat)
	})

	t.Run("padded base64url segments", func(t *testing.T) {
		_, err := adapter.Decode(signJWTTestToken(t, []byte(jwtTestSecret), header, payload, true))
		require.NoError(t, err)
	})
}

func TestJWTHS256FormatAdapter_PanicsOnEmptySecret(t *testing.T) {
	assert.Panics(t, func() {
		auth.NewJWTHS256FormatAdapter(nil)
	})
}

func jwtTestHeader() map[string]any {
	return map[string]any{"alg": "HS256", "typ": "JWT"}
}

func signJWTTestToken(t *testing.T, secret []byte, header, payload map[string]any, padded bool) string {
	t.Helper()

	encode := func(value any) string {
		bytes, err := json.Marshal(value)
		require.NoError(t, err)
		if padded {
			return base64.URLEncoding.EncodeToString(bytes)
		}
		return base64.RawURLEncoding.EncodeToString(bytes)
	}

	headerSegment := encode(header)
	payloadSegment := encode(payload)
	mac := hmac.New(sha256.New, secret)
	_, err := mac.Write([]byte(headerSegment + "." + payloadSegment))
	require.NoError(t, err)

	signature := mac.Sum(nil)
	signatureSegment := base64.RawURLEncoding.EncodeToString(signature)
	if padded {
		signatureSegment = base64.URLEncoding.EncodeToString(signature)
	}
	return headerSegment + "." + payloadSegment + "." + signatureSegment
}

func copyStringAnyMap(input map[string]any) map[string]any {
	output := make(map[string]any, len(input))
	for key, value := range input {
		output[key] = value
	}
	return output
}
