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
- **自定义 claims 与稳定 SessionID** — 业务字段可进入 token，refresh 轮换后会话 ID 不变。
- **无状态 Access Token** — 可选仅验签模式，配合 denylist 撤销。
- **会话管理** — SID / subject 吊销、maxOnline 裁剪、刷新宽限与比例轮换。
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

// 7. 仅撤销当前 access token；完整登出请配置 RevocationStore 后调用 Logout
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
- `ver` 是**登录态凭据版本**，与模块发布版本、依赖版本无关；默认 `DefaultTokenVersion`（`v1`），
  由接入方用 `Config.TokenVersion` 或 `IssueRequest.Version` 自行控制；`typ` 只能是 `access` / `refresh`。
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

反过来，只设置 `WithOpaqueRefreshToken()` 而不指定 access 格式会返回
`ErrInvalidConfig`，避免 stateful 模式下静默发出非签名 access token；可以使用
`WithAccessTokenFormat(jwtFormat)` 或显式 `WithTokenFormat(defaultFormat)`。

## 自定义 claims 与稳定 SessionID

```go
pair, _ := svc.IssueTokenPair(ctx, auth.IssueRequest{
    Subject:     "user-123",
    SessionID:   "caller-provided-sid", // 可选；为空时由库生成
    ExtraClaims: map[string]any{"role": "admin", "tenant": "t-1"},
})

result, _ := svc.ValidateAccessToken(ctx, pair.AccessToken)
// result.SessionID, result.ExtraClaims
```

- `jti/typ/sub/iat/exp/ver/sid/iss/aud/nbf` 是保留字段，`ExtraClaims` 不能覆盖。
- 同一会话连续 refresh 轮换后 `SessionID` 不变；两次独立登录生成不同 ID。
- JWT 中 `ExtraClaims` 会平铺到 payload；默认/签名格式同样保留这些字段。
- 旧会话没有 `SessionID` 时继续按旧逻辑工作，但无法按 SID 吊销。

## 无状态 Access Token

```go
cfg := auth.Config{
    AccessTokenMode: auth.AccessTokenStateless,
}
svc, err := auth.NewService(cfg, store,
    auth.WithAccessTokenFormat(auth.NewJWTHS256FormatAdapter(secret)),
    auth.WithRevocationStore(revocationStore),
)
```

- 必须使用带签名的 access 格式（`SignedTokenFormatAdapter` 或 JWT）；默认无签名格式会返回 `ErrInvalidConfig`。
- `ValidateAccessToken` 只验签 + 校验 `exp`，不查 `SessionStore`；`Metadata` 不再返回，业务字段用 `ExtraClaims`。
- 撤销完全依赖 `RevocationStore`；没有配置时 `RevokeAccessToken` 返回 `ErrRevocationNotConfigured`。
- `SlidingExpiration` 与无状态模式互斥；`RenewAccessToken` 返回 `ErrUnsupportedMode`。

## 会话管理

### SID / subject 吊销

```go
revocation := adapters.NewRedisRevocationStore(client, keys)
svc, _ := auth.NewService(cfg, store,
    auth.WithRevocationStore(revocation),
)

svc.RevokeSession(ctx, sessionID, 0) // 0 = 使用默认 TTL
svc.RevokeSubject(ctx, subject, 0)
```

- 默认 TTL 为 `max(AccessTokenTTL, RefreshTokenTTL) + ClockSkew`，确保 refresh 也被拦住。
- `ValidateAccessToken` 与 `RefreshAccessToken` 都会检查吊销状态。
- 测试/单实例可用 `adapters.NewMemoryRevocationStore()`。

### maxOnline

```go
cfg.MaxSessionsPerSubject = 5
svc, _ := auth.NewService(cfg, indexedStore,
    auth.WithRevocationStore(revocationStore),
    auth.WithSessionEvictionHandler(func(ctx context.Context, evicted []auth.SessionRef) {
        // 可在这里写 denylist，保证无状态 access token 立即失效
    }),
)
```

- 需要存储实现 `IndexedSessionStore`；`MemoryStore` 与 `RedisStore` 已实现。
- 登录时原子完成「写会话 + 写索引 + 裁剪」，按 `IssuedAt` 踢最旧。
- 被踢会话的 session 会被删除；无状态 access token 需要通过回调写 denylist。
- 完整登出使用 `svc.Logout(ctx, accessToken, 0)`：清理 access/refresh/session 索引并写入 denylist。
  `Logout` 必须配置 `RevocationStore`，否则返回 `ErrRevocationNotConfigured`；
  `RevokeAccessToken` 仅吊销当前 access，`RevokeSession` 仅写 denylist，都不等同于完整登出。

### 比例轮换与刷新宽限

```go
cfg.RotateNearExpiryRatio = 0.5        // 剩余 50% 时轮换
cfg.RefreshGracePeriod = time.Minute   // 轮换后 1 分钟内旧 token 可幂等重放

svc, _ := auth.NewService(cfg, store,
    auth.WithGraceEncryptionKey([]byte("0123456789abcdef0123456789abcdef")),
)
```

- `RotateNearExpiryRatio` 按会话自身寿命计算；为 0 时继续使用 `RotateNearExpiry`。
- `RefreshGracePeriod` 需要存储实现 `RefreshGraceStore` + `GraceRotationStore`。
- grace 记录中的 refresh token 与 access token 都使用 AES-GCM 加密，密钥必须正好 32 字节。
- 宽限期内重复刷新返回同一对 token；超过宽限期后旧 token 失效。
- grace 重放同样会检查 revocation store。

### token version

```go
cfg.TokenVersion = "v1" // 为空时使用 DefaultTokenVersion
// 或在单次签发时覆盖：
pair, _ := svc.IssueTokenPair(ctx, auth.IssueRequest{Subject: "u", Version: "v2"})
```

- refresh 后版本保持不变；不透明 refresh 模式会把版本存在 session 中。
- 该版本只描述登录态凭据契约：提升它可让旧 token 整体失效，**不要**把它当作本库的发布版本。

## KeyStrategy

`adapters.NewPrefixedKeyStrategy` 现在实现 `ExtendedKeyStrategy`，除 access/refresh 外还提供：

```text
auth:session:<sid>
auth:subject:<sub>:sessions
auth:grace:<tokenID>
auth:revoked:session:<sid>
auth:revoked:subject:<sub>
```

新存储适配器（索引、grace、吊销）要求扩展策略；已有的自定义 `KeyStrategy` 仍可用于 access/refresh。Redis Cluster 场景需要用 hash tag 保证索引/session key 同槽。

## 集成测试

```bash
# golang-jwt / PHP 互验（独立 module）
cd testdata/interop && go test ./...

# 真实 Redis 索引/登出/grace（需要 127.0.0.1:6379）
cd testdata/redisinterop && go test ./...
```

`testdata/redisinterop` 使用独立 `go.mod` 和 `go-redis`，不会进入主模块依赖。

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
