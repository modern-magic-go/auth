# go-auth

一个可移植的、与框架无关的 Go 语言认证库。提供 Access/Refresh 令牌生命周期管理，支持可插拔的会话存储。

## 特性

- **令牌对签发** — 同时签发 Access Token 和 Refresh Token。
- **Bearer 验证** — 解析 `Authorization: Bearer <token>` 并针对会话存储进行验证。
- **三种刷新策略**：
  - `reuse_until_expiry` — 重用 Refresh Token 直到过期（默认）。
  - `rotate_near_expiry` — 仅在接近过期时轮换。
  - `one_time_rotation` — 每次刷新时轮换（并发单次获胜）。
- **滑动过期** — 每次验证时可选择延长 Access Token 的 TTL。
- **时钟偏移容差** — 为分布式系统提供可配置的偏移容差。
- **可插拔适配器** — 内存存储用于测试，Redis 存储用于生产环境。
- **完整的依赖注入** — Clock、随机源、序列化器和令牌格式均可替换。

## 安装

```bash
go get github.com/modern-magic-go/auth
```

## 快速开始

```go
import (
    "context"
    "time"

    "github.com/modern-magic-go/auth"
    "github.com/modern-magic-go/auth/adapters"
)

// 1. 配置
cfg := auth.Config{
    AccessTokenTTL:  15 * time.Minute,
    RefreshTokenTTL: 7 * 24 * time.Hour,
    RefreshPolicy:   auth.RefreshPolicyReuseUntilExpiry,
    TokenIDLength:   24,
}

// 2. 创建存储（生产环境使用 RedisStore）
store := adapters.NewMemoryStore()

// 3. 创建服务
svc, _ := auth.NewService(cfg, store)

// 4. 登录时签发令牌对
pair, _ := svc.IssueTokenPair(ctx, auth.IssueRequest{
    Subject: "user-123",
    Metadata: auth.SessionMetadata{
        "platform": "web",
    },
})

// 5. 每个请求时验证
result, _ := svc.ValidateAccessToken(ctx, pair.AccessToken)
// result.Subject == "user-123"

// 6. 刷新
refreshed, _ := svc.RefreshAccessToken(ctx, pair.RefreshToken)

// 7. 登出时撤销
svc.RevokeAccessToken(ctx, pair.AccessToken)
```

完整示例请参见 [example/basic/main.go](example/basic/main.go) 和 [example/redis/main.go](example/redis/main.go)。

## 架构

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

## 令牌设计

本库采用 **"瘦令牌，胖会话"** 的方法：

- 令牌仅包含最少的认证字段：`jti`、`typ`、`sub`、`iat`、`exp`、`ver`。
- 业务扩展（设备、平台、租户）存储在服务器端的会话元数据中。
- 默认格式为 `Base64URL(JSON)` — **不是 JWT**。

## 刷新策略

| 策略 | 行为 | 使用场景 |
|--------|----------|----------|
| `reuse_until_expiry` | 同一刷新令牌在过期前一直有效 | 简单应用，低变更率 |
| `rotate_near_expiry` | 仅在接近过期时轮换 | 平衡安全性与用户体验 |
| `one_time_rotation` | 每次使用生成新的刷新令牌 | 高安全性应用（检测令牌窃取） |

## 文档

- [CHANGELOG.md](CHANGELOG.md) — 版本历史
- [SECURITY.md](SECURITY.md) — 安全策略和漏洞报告
- [GoDoc](https://pkg.go.dev/github.com/modern-magic-go/auth) — API 参考

## 许可证

MIT。参见 [LICENSE](LICENSE)。
