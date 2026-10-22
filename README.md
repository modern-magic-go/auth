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
- **标准 JWT（HS256）格式** — 可选的 `NewJWTHS256FormatAdapter`，与 `golang-jwt`、PHP `lcobucci/jwt` 互操作。
- **access / refresh 格式分离** — JWT access + 不透明 refresh，refresh 仅以 SHA-256 哈希落库。
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

完整示例请参见 [example/basic/main.go](example/basic/main.go)、[example/redis/main.go](example/redis/main.go) 和 [example/jwt_opaque/main.go](example/jwt_opaque/main.go)。

## JWT 格式（HS256）

默认格式和两段式签名格式都不是标准 JWT。需要与 PHP / 其他语言互操作时，注入
`NewJWTHS256FormatAdapter`：

```go
jwtFormat := auth.NewJWTHS256FormatAdapter(
    []byte("replace-with-32-byte-secret"),
    auth.WithJWTIssuer("auth-service"),
    auth.WithJWTAudience("admin-api"),
    auth.WithJWTLeeway(30*time.Second), // 默认与服务默认 ClockSkew 一致
)

svc, err := auth.NewService(cfg, store,
    auth.WithTokenFormat(jwtFormat), // access 与 refresh 都用 JWT
)
```

- 输出标准三段式 JWT，`alg=HS256`、`typ=JWT`。
- Payload 保留 `jti/typ/sub/iat/exp/ver`，`iss/aud` 按选项写入。
- 外部系统签发 token 时必须包含 `jti/typ/sub/iat/exp/ver`，缺失或为空的 `ver`
  会被拒绝。
- `Decode` 拒绝 `alg=none`、非 HS256、错误签名、过期/未生效、错误 `iss/aud`。
- `ver` 目前固定为 `ModuleVersion`，`typ` 只能是 `access` / `refresh`。
- JWT 时间校验使用 `WithJWTClock`（默认真实时钟）；如果自定义了 `Config.ClockSkew`，请用
  `WithJWTLeeway` 设置相同容差。

跨语言互验见 [testdata/interop](testdata/interop)。

## JWT access + 不透明 refresh

推荐生产组合：access 用 JWT 给下游本地验签，refresh 保持不透明私有令牌：

```go
jwtFormat := auth.NewJWTHS256FormatAdapter(secret, auth.WithJWTIssuer("auth-service"))

svc, err := auth.NewService(cfg, store,
    auth.WithAccessTokenFormat(jwtFormat),
    auth.WithOpaqueRefreshToken(), // 32 字节 crypto/rand，Base64URL（43 字符）
)
```

- refresh token 不含 `.`，不能当 JWT 解析；`SessionStore` 只保存
  `Base64URL(SHA-256(token))`。
- `TokenIDLength` 只影响 `jti`，不影响不透明 refresh token 的固定 32 字节长度。
- `ValidateResult.RefreshTokenID` 在不透明模式下是哈希 ID，**不是**可用于刷新的 token。
- 轮换、并发单胜者、吊销与 claims 模式一致。
- 需要自定义随机源（测试）时用 `auth.WithOpaqueRandomSource`。

如果只设置 `WithAccessTokenFormat` 而不设置 refresh 格式，refresh 会继续使用 access
格式（兼容默认语义）；要避免 JWT refresh，请显式加 `WithOpaqueRefreshToken()`。

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
