# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

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
