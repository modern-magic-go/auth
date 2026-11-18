package main

import (
	"fmt"
	"log"
	"time"

	"github.com/modern-magic-go/auth"
)

const (
	secret = "0123456789abcdef0123456789abcdef"
)

func main() {
	adapter := auth.NewJWTHS256FormatAdapter(
		[]byte(secret),
		auth.WithJWTIssuer("auth-service"),
		auth.WithJWTAudience("admin-api"),
	)

	now := time.Now().UTC().Truncate(time.Second)
	token, err := adapter.Encode(auth.TokenClaims{
		TokenID:   "jti-php-interop",
		TokenType: auth.TokenTypeAccess,
		Subject:   "user-php-interop",
		IssuedAt:  now,
		ExpiresAt: now.Add(10 * time.Minute),
		Version:   "v1.0.0",
	})
	if err != nil {
		log.Fatalf("encode token: %v", err)
	}

	fmt.Println(token)
}
