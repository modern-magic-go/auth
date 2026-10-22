# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [v0.2.0] - 2026-10-22

### Added

- 新增 `NewJWTHS256FormatAdapter`：输出标准三段式 HS256 JWT，支持 `iss` / `aud` /
  leeway 配置，拒绝 `alg=none`、非 HS256、错误签名、过期/未生效与错误 `iss/aud`。
- 新增 `WithAccessTokenFormat` / `WithRefreshTokenFormat` / `WithOpaqueRefreshToken`：
  支持 access 与 refresh 使用不同 token 格式。
- 新增 `NewOpaqueRefreshTokenFormat`：32 字节随机、Base64URL 编码的不透明 refresh
  token，持久化 ID 为 `Base64URL(SHA-256(token))`，存储层不接触 token 明文。
- 新增 `example/jwt_opaque` 示例与 `testdata/interop` 跨语言互验模块（golang-jwt /
  PHP lcobucci/jwt）。
- 新增自定义 claims 与稳定 `SessionID`：`IssueRequest.ExtraClaims` /
  `IssueRequest.SessionID`，`TokenPair` / `ValidateResult` 返回 `SessionID` 与
  `ExtraClaims`。
- 新增 `Config.TokenVersion` 与 `IssueRequest.Version`，refresh 后保持版本不变。
- 新增无状态 Access Token 模式 `AccessTokenStateless`；要求签名格式，并支持
  `SigningFormat` 标记接口。
- 新增 `RevocationStore`、`RevokeSession`、`RevokeSubject` 与
  `adapters.RedisRevocationStore` / `adapters.MemoryRevocationStore`。
- 新增 `MaxSessionsPerSubject`、`IndexedSessionStore`、`WithSessionEvictionHandler`；
  `MemoryStore` / `RedisStore` 支持 subject 会话索引与最旧会话裁剪。
- 新增 `RotateNearExpiryRatio`、`RefreshGracePeriod`、`RefreshGraceStore`、
  `GraceRotationStore` 与 `WithGraceEncryptionKey`；grace 记录中的 refresh token
  使用 AES-GCM 加密。
- 新增 `ExtendedKeyStrategy`，覆盖 session 索引、grace 与吊销 key；默认
  `NewPrefixedKeyStrategy` 已实现。

### Fixed

- 修复 `WithOpaqueRefreshToken()` 单独使用时 access 静默退回非签名默认格式：现在返回
  `ErrInvalidConfig`，必须显式选择 access 格式。
- 修复不透明 refresh token 带 Base64 padding 时 SHA-256 ID 不一致的问题，统一按
  解码后的 RawURL 字符串计算。
- 修复 RedisStore 会话索引：过期 ref 清理、登出/吊销同步清理索引、session key
  落库、UnixNano 排序，以及 Create/Touch/Remove/轮换更新索引改为单条 Lua。
- 新增 `Logout` API：完整清理 access/refresh/session 索引并写入 denylist。
- 修复 `Logout` 在没有 `RevocationStore` 时静默成功的问题：现在返回
  `ErrRevocationNotConfigured`，避免旧 access token 仍可用。
- 修复 RedisStore 新增生命周期方法忽略 `RedisStoreConfig.Serializer` 的问题；
  `CreateSession`、索引轮换与 grace 轮换统一使用注入的 Serializer。
- 安全加固：grace 记录中的 access token 也改为 AES-GCM 密文，与 refresh token
  保持一致，不再明文落库。
- `RevokeSubject` 先写 denylist 再清理索引，避免清理失败时 stateless access 仍有效。
- 新增 `IndexedGraceRotationStore`，grace 轮换与 subject 索引更新在同一原子操作内完成。
- `RefreshSession` 记录 `AccessTokenID`，`Logout(refreshToken)` 可清理对应 access session。
- README 同步 `TokenVersion`、Logout 与 maxOnline 示例。

### Changed

- `RefreshGraceRecord.AccessToken` 重命名为 `AccessTokenCiphertext`。滚动升级时旧
  版本写入的 grace 记录无法解密重放；grace TTL 通常很短，升级后可让客户端重新
  refresh 或重新登录。
- `ModuleVersion`（`v1.0.0`）更名为 `DefaultTokenVersion`（`v1`），
  `VersionInfo.ModuleVersion` 字段同步更名为 `VersionInfo.DefaultTokenVersion`。
  `ver` 是**登录态凭据版本**，由接入方通过 `Config.TokenVersion` 或
  `IssueRequest.Version` 独立控制，与模块发布版本（git tag）和依赖版本无关；
  若之前依赖默认值，请显式配置 `TokenVersion` 以免升级后 `ver` 变化。

## [v1.0.0] - 2026-04-07

### Added

- Access Token / Refresh Token 成对签发 (`IssueTokenPair`)
- Bearer 请求头解析与 Access Token 校验 (`ValidateBearerHeader`, `ValidateAccessToken`)
- Refresh Token 换发、吊销与可选续期 (`RefreshAccessToken`, `RevokeAccessToken`, `RevokeRefreshToken`, `RenewAccessToken`)
- 三种 Refresh 策略：`reuse_until_expiry`、`rotate_near_expiry`、`one_time_rotation`
- Sliding Expiration 支持（默认关闭）
- Clock Skew 容错
- 并发刷新 single-winner 语义（one-time rotation 模式）
- 内存会话适配器 (`adapters.MemoryStore`)
- Redis 会话适配器 (`adapters.RedisStore`)，支持可注入 KeyStrategy 与 Serializer
- 可注入依赖：`Clock`、`RandomSource`、`Serializer`、`TokenFormatAdapter`
- 内置 Base64URL Token 格式适配器（瘦 Token、胖 Session）
- 完整测试覆盖：主流程、过期、吊销、策略切换、并发刷新
