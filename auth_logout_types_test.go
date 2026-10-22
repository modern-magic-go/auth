package auth_test

import (
	"context"
	"time"

	"github.com/modern-magic-go/auth"
	"github.com/modern-magic-go/auth/adapters"
)

type failingRevocationStore struct{}

func (failingRevocationStore) RevokeSession(context.Context, string, time.Duration) error {
	return auth.ErrInvalidConfig
}

func (failingRevocationStore) RevokeSubject(context.Context, string, time.Duration) error {
	return auth.ErrInvalidConfig
}

func (failingRevocationStore) IsRevoked(context.Context, string, string) (bool, error) {
	return false, nil
}

type noopRemoveStore struct {
	*adapters.MemoryStore
}

func (s *noopRemoveStore) RemoveSession(context.Context, string, string) error {
	return nil
}
