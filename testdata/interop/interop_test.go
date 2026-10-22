package interop

import (
	"fmt"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v4"
	"github.com/modern-magic-go/auth"
)

const interopSecret = "0123456789abcdef0123456789abcdef"

type fixedClock struct {
	now time.Time
}

func (c fixedClock) Now() time.Time {
	return c.now
}

func TestGolangJWTToAuth(t *testing.T) {
	now := time.Date(2026, 3, 18, 0, 0, 0, 0, time.UTC)
	adapter := auth.NewJWTHS256FormatAdapter(
		[]byte(interopSecret),
		auth.WithJWTIssuer("auth-service"),
		auth.WithJWTAudience("admin-api"),
		auth.WithJWTClock(fixedClock{now: now}),
	)

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
		"jti": "jti-interop",
		"typ": "access",
		"sub": "user-interop",
		"iat": now.Unix(),
		"exp": now.Add(10 * time.Minute).Unix(),
		"ver": "v1.0.0",
		"iss": "auth-service",
		"aud": "admin-api",
	})
	signed, err := token.SignedString([]byte(interopSecret))
	if err != nil {
		t.Fatalf("sign token with golang-jwt: %v", err)
	}

	claims, err := adapter.Decode(signed)
	if err != nil {
		t.Fatalf("decode golang-jwt token with auth: %v", err)
	}
	if claims.TokenID != "jti-interop" || claims.Subject != "user-interop" {
		t.Fatalf("unexpected claims: %+v", claims)
	}
}

func TestAuthToGolangJWT(t *testing.T) {
	now := time.Date(2026, 3, 18, 0, 0, 0, 0, time.UTC)
	adapter := auth.NewJWTHS256FormatAdapter(
		[]byte(interopSecret),
		auth.WithJWTIssuer("auth-service"),
		auth.WithJWTAudience("admin-api"),
		auth.WithJWTClock(fixedClock{now: now}),
	)

	signed, err := adapter.Encode(auth.TokenClaims{
		TokenID:   "jti-interop",
		TokenType: auth.TokenTypeAccess,
		Subject:   "user-interop",
		IssuedAt:  now,
		ExpiresAt: now.Add(10 * time.Minute),
		Version:   "v1.0.0",
	})
	if err != nil {
		t.Fatalf("encode token with auth: %v", err)
	}

	parser := jwt.NewParser(jwt.WithoutClaimsValidation())
	parsed, err := parser.Parse(signed, func(token *jwt.Token) (any, error) {
		if token.Method != jwt.SigningMethodHS256 {
			return nil, fmt.Errorf("unexpected signing method: %s", token.Method.Alg())
		}
		return []byte(interopSecret), nil
	})
	if err != nil || !parsed.Valid {
		t.Fatalf("parse auth token with golang-jwt: %v", err)
	}

	claims, ok := parsed.Claims.(jwt.MapClaims)
	if !ok {
		t.Fatalf("unexpected claims type: %T", parsed.Claims)
	}
	if claims["jti"] != "jti-interop" || claims["sub"] != "user-interop" {
		t.Fatalf("unexpected claims: %+v", claims)
	}
	if claims["iss"] != "auth-service" {
		t.Fatalf("unexpected issuer: %+v", claims["iss"])
	}
	if claims["aud"] != "admin-api" {
		t.Fatalf("unexpected audience: %+v", claims["aud"])
	}
}
