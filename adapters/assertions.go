package adapters

import "github.com/modern-magic-go/auth"

var (
	_ auth.SessionStore              = (*MemoryStore)(nil)
	_ auth.IndexedSessionStore       = (*MemoryStore)(nil)
	_ auth.RefreshGraceStore         = (*MemoryStore)(nil)
	_ auth.GraceRotationStore        = (*MemoryStore)(nil)
	_ auth.IndexedGraceRotationStore = (*MemoryStore)(nil)

	_ auth.SessionStore              = (*RedisStore)(nil)
	_ auth.IndexedSessionStore       = (*RedisStore)(nil)
	_ auth.RefreshGraceStore         = (*RedisStore)(nil)
	_ auth.GraceRotationStore        = (*RedisStore)(nil)
	_ auth.IndexedGraceRotationStore = (*RedisStore)(nil)

	_ auth.RevocationStore = (*MemoryRevocationStore)(nil)
)
