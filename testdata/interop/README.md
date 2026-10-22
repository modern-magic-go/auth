# JWT 跨语言互验

本目录是**独立 Go module**，只用于验证 `auth.NewJWTHS256FormatAdapter` 与
`golang-jwt`、PHP `lcobucci/jwt` 的互操作性。主模块 `go test ./...` 不会包含这里，
也不会把 `golang-jwt` 带进 `github.com/modern-magic-go/auth` 的依赖。

## golang-jwt

```bash
cd testdata/interop
go test ./...
```

覆盖两个方向：

- `golang-jwt` 签发 → `auth` 解码；
- `auth` 签发 → `golang-jwt` 验签。

## PHP lcobucci/jwt

先生成一个测试 token：

```bash
cd testdata/interop
TOKEN="$(go run ./generate)"
```

再安装 PHP 依赖并验签：

```bash
cd testdata/interop/php
composer install
php verify.php "$TOKEN" "0123456789abcdef0123456789abcdef"
# 输出 verified
```

PHP 侧要求 token 包含以下 claims：`jti`、`typ=access|refresh`、`sub`、`iat`、
`exp`、`ver`；`iss` 为 `auth-service`，`aud` 包含 `admin-api`。
