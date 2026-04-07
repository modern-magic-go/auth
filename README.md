# auth

A portable, framework-agnostic authentication library for Go. Provides Access/Refresh token lifecycle management with pluggable session storage.

## Features

- **Token Pair Issuance** — Access + Refresh tokens issued together.
- **Bearer Validation** — Parse `Authorization: Bearer <token>` and validate against session store.
- **Three Refresh Policies**:
  - `reuse_until_expiry` — Reuse refresh token until it expires (default).
  - `rotate_near_expiry` — Rotate only when nearing expiration.
  - `one_time_rotation` — Rotate on every refresh (concurrent single-winner).
- **Sliding Expiration** — Optional access token TTL extension on each validation.
- **Clock Skew Tolerance** — Configurable skew for distributed systems.
- **Pluggable Adapters** — Memory store for testing, Redis store for production.
- **Full Dependency Injection** — Clock, random source, serializer, and token format are all swappable.

## Installation

```bash
go get github.com/modern-magic-go/auth
```

## Quick Start

```go
import (
    "context"
    "time"

    "github.com/modern-magic-go/auth"
    "github.com/modern-magic-go/auth/adapters"
)

// 1. Configure
cfg := auth.Config{
    AccessTokenTTL:  15 * time.Minute,
    RefreshTokenTTL: 7 * 24 * time.Hour,
    RefreshPolicy:   auth.RefreshPolicyReuseUntilExpiry,
    TokenIDLength:   24,
}

// 2. Create store (use RedisStore for production)
store := adapters.NewMemoryStore()

// 3. Create service
svc, _ := auth.NewService(cfg, store)

// 4. Issue tokens on login
pair, _ := svc.IssueTokenPair(ctx, auth.IssueRequest{
    Subject: "user-123",
    Metadata: auth.SessionMetadata{
        "platform": "web",
    },
})

// 5. Validate on each request
result, _ := svc.ValidateAccessToken(ctx, pair.AccessToken)
// result.Subject == "user-123"

// 6. Refresh
refreshed, _ := svc.RefreshAccessToken(ctx, pair.RefreshToken)

// 7. Revoke on logout
svc.RevokeAccessToken(ctx, pair.AccessToken)
```

See [example/basic/main.go](example/basic/main.go) and [example/redis/main.go](example/redis/main.go) for complete examples.

## Architecture

```
┌─────────────────────────────────────────────┐
│                 Service                      │
│  (Issue / Validate / Refresh / Revoke)       │
├──────────────┬──────────────────────────────┤
│  Interfaces  │        Adapters              │
├──────────────┼──────────────────────────────┤
│ SessionStore │ MemoryStore / RedisStore     │
│ TokenFormat  │ DefaultTokenFormatAdapter    │
│ Clock        │ defaultClock / fakeClock     │
│ RandomSource │ defaultRandomSource          │
│ Serializer   │ jsonSerializer               │
└──────────────┴──────────────────────────────┘
```

## Token Design

This library uses a **"thin token, fat session"** approach:

- Tokens contain only minimal auth fields: `jti`, `typ`, `sub`, `iat`, `exp`, `ver`.
- Business extensions (device, platform, tenant) live in Session Metadata stored server-side.
- Default format is `Base64URL(JSON)` — **not JWT**.

## Refresh Policies

| Policy | Behavior | Use Case |
|--------|----------|----------|
| `reuse_until_expiry` | Same refresh token works until expiry | Simple apps, low churn |
| `rotate_near_expiry` | Rotates only when close to expiry | Balance security & UX |
| `one_time_rotation` | New refresh token on every use | High-security apps (detects token theft) |

## Documentation

- [CHANGELOG.md](CHANGELOG.md) — Version history
- [SECURITY.md](SECURITY.md) — Security policy & vulnerability reporting
- [GoDoc](https://pkg.go.dev/github.com/modern-magic-go/auth) — API reference

## License

MIT. See [LICENSE](LICENSE).
