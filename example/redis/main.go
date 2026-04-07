// Example with Redis store demonstrates production-grade session storage.
//
// Run with: go run .
// Requires a running Redis instance on localhost:6379.
package main

import (
	"context"
	"fmt"
	"log"
	"time"

	"github.com/modern-magic-go/auth"
	"github.com/modern-magic-go/auth/adapters"
)

// redisClient is a minimal wrapper around your project's Redis client.
// Replace with your actual Redis client implementation.
type redisClient struct {
	// Add your Redis client fields here.
}

func (r *redisClient) Get(key string) (string, error) {
	// Implement using your Redis client.
	return "", fmt.Errorf("not implemented - replace with your Redis client")
}

func (r *redisClient) Setex(key, value string, seconds int) error {
	return fmt.Errorf("not implemented - replace with your Redis client")
}

func (r *redisClient) Del(keys ...string) (int, error) {
	return 0, fmt.Errorf("not implemented - replace with your Redis client")
}

func (r *redisClient) Eval(script string, keys []string, args ...any) (any, error) {
	return nil, fmt.Errorf("not implemented - replace with your Redis client")
}

func (r *redisClient) Expire(key string, seconds int) error {
	return fmt.Errorf("not implemented - replace with your Redis client")
}

func main() {
	ctx := context.Background()

	// 1. Build configuration with rotation policy.
	cfg := auth.Config{
		AccessTokenTTL:   15 * time.Minute,
		RefreshTokenTTL:  7 * 24 * time.Hour,
		RefreshPolicy:    auth.RefreshPolicyRotateNearExpiry,
		RotateNearExpiry: 12 * time.Hour,
		ClockSkew:        30 * time.Second,
		TokenIDLength:    24,
	}

	// 2. Create Redis client (replace with your actual client).
	client := &redisClient{}

	// 3. Create Redis store with custom key strategy.
	store := adapters.NewRedisStore(client, adapters.RedisStoreConfig{
		KeyStrategy: adapters.NewPrefixedKeyStrategy("myapp:auth:"),
	})

	// 4. Create auth service.
	svc, err := auth.NewService(cfg, store)
	if err != nil {
		log.Fatalf("failed to create service: %v", err)
	}

	// 5. Issue and validate tokens.
	pair, err := svc.IssueTokenPair(ctx, auth.IssueRequest{
		Subject: "user-456",
		Metadata: auth.SessionMetadata{
			"device_id": "iphone-15",
		},
	})
	if err != nil {
		log.Fatalf("failed to issue tokens: %v", err)
	}
	fmt.Printf("Issued tokens for user-456\n")
	fmt.Printf("Access Expiry:  %s\n", pair.AccessExpiry.Format(time.RFC3339))

	// 6. Validate.
	result, err := svc.ValidateAccessToken(ctx, pair.AccessToken)
	if err != nil {
		log.Printf("validation error (expected if Redis is not running): %v", err)
		return
	}
	fmt.Printf("Validated Subject: %s\n", result.Subject)
}
