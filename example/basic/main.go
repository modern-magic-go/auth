// Example demonstrates basic auth usage with memory store.
//
// Run with: go run .
package main

import (
	"context"
	"fmt"
	"log"
	"time"

	"github.com/modern-magic-go/auth"
	"github.com/modern-magic-go/auth/adapters"
)

func main() {
	ctx := context.Background()

	// 1. Build configuration.
	cfg := auth.Config{
		AccessTokenTTL:  15 * time.Minute,
		RefreshTokenTTL: 7 * 24 * time.Hour,
		RefreshPolicy:   auth.RefreshPolicyReuseUntilExpiry,
		ClockSkew:       30 * time.Second,
		TokenIDLength:   24,
	}

	// 2. Create session store (memory for demo, use RedisStore for production).
	store := adapters.NewMemoryStore()

	// 3. Create auth service.
	svc, err := auth.NewService(cfg, store)
	if err != nil {
		log.Fatalf("failed to create service: %v", err)
	}

	// 4. Issue token pair on login.
	pair, err := svc.IssueTokenPair(ctx, auth.IssueRequest{
		Subject: "user-123",
		Metadata: auth.SessionMetadata{
			"platform": "web",
			"role":     "admin",
		},
	})
	if err != nil {
		log.Fatalf("failed to issue tokens: %v", err)
	}
	fmt.Printf("Access Token:  %s\n", pair.AccessToken)
	fmt.Printf("Refresh Token: %s\n", pair.RefreshToken)
	fmt.Printf("Access Expiry:  %s\n", pair.AccessExpiry.Format(time.RFC3339))
	fmt.Printf("Refresh Expiry: %s\n", pair.RefreshExpiry.Format(time.RFC3339))

	// 5. Validate access token on each request.
	result, err := svc.ValidateAccessToken(ctx, pair.AccessToken)
	if err != nil {
		log.Fatalf("token validation failed: %v", err)
	}
	fmt.Printf("\nValidated Subject: %s\n", result.Subject)
	fmt.Printf("Metadata: %v\n", result.Metadata)

	// 6. Validate via Bearer header (typical middleware usage).
	authHeader := "Bearer " + pair.AccessToken
	bearerResult, err := svc.ValidateBearerHeader(ctx, authHeader)
	if err != nil {
		log.Fatalf("bearer validation failed: %v", err)
	}
	fmt.Printf("Bearer Subject: %s\n", bearerResult.Subject)

	// 7. Refresh access token.
	refreshed, err := svc.RefreshAccessToken(ctx, pair.RefreshToken)
	if err != nil {
		log.Fatalf("refresh failed: %v", err)
	}
	fmt.Printf("\nRefreshed Access Token:  %s\n", refreshed.AccessToken)
	fmt.Printf("Refreshed? %v\n", refreshed.Rotated)

	// 8. Revoke tokens on logout.
	if err := svc.RevokeAccessToken(ctx, pair.AccessToken); err != nil {
		log.Printf("failed to revoke access token: %v", err)
	}
	fmt.Println("\nAccess token revoked.")
}
