// Example demonstrates JWT access tokens with opaque refresh tokens.
//
// Run with: go run .
package main

import (
	"context"
	"fmt"
	"log"
	"strings"
	"time"

	"github.com/modern-magic-go/auth"
	"github.com/modern-magic-go/auth/adapters"
)

func main() {
	ctx := context.Background()

	// Demo secret only; use a crypto/rand generated secret of at least 32 bytes.
	jwtFormat := auth.NewJWTHS256FormatAdapter(
		[]byte("0123456789abcdef0123456789abcdef"),
		auth.WithJWTIssuer("auth-service"),
		auth.WithJWTAudience("admin-api"),
	)

	svc, err := auth.NewService(
		auth.Config{
			AccessTokenTTL:  15 * time.Minute,
			RefreshTokenTTL: 7 * 24 * time.Hour,
			RefreshPolicy:   auth.RefreshPolicyOneTimeRotation,
			ClockSkew:       30 * time.Second,
			TokenIDLength:   24,
		},
		adapters.NewMemoryStore(),
		auth.WithAccessTokenFormat(jwtFormat),
		auth.WithOpaqueRefreshToken(),
	)
	if err != nil {
		log.Fatalf("failed to create service: %v", err)
	}

	pair, err := svc.IssueTokenPair(ctx, auth.IssueRequest{
		Subject: "user-123",
		Metadata: auth.SessionMetadata{
			"platform": "web",
		},
	})
	if err != nil {
		log.Fatalf("failed to issue tokens: %v", err)
	}

	fmt.Printf("Access Token (JWT, %d segments): %s\n", len(strings.Split(pair.AccessToken, ".")), pair.AccessToken)
	fmt.Printf("Refresh Token (opaque, %d chars): %s\n", len(pair.RefreshToken), pair.RefreshToken)

	result, err := svc.ValidateAccessToken(ctx, pair.AccessToken)
	if err != nil {
		log.Fatalf("failed to validate access token: %v", err)
	}
	fmt.Printf("\nValidated Subject: %s\n", result.Subject)
	fmt.Printf("Refresh Token ID (hash): %s\n", result.RefreshTokenID)

	refreshed, err := svc.RefreshAccessToken(ctx, pair.RefreshToken)
	if err != nil {
		log.Fatalf("failed to refresh: %v", err)
	}
	fmt.Printf("\nRefreshed? %v\n", refreshed.Rotated)
	fmt.Printf("New Refresh Token: %s\n", refreshed.RefreshToken)

	_, err = svc.RefreshAccessToken(ctx, pair.RefreshToken)
	fmt.Printf("Reusing old refresh token: %v\n", err)
}
