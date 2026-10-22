package core

import (
	"crypto/sha256"
	"encoding/base64"
)

const opaqueRefreshTokenBytes = 32

// RefreshTokenFormat 定义不透明 refresh token 的生成与解析边界。
//
// 实现只返回 token 与持久化 ID，不承载任何 claims；服务端会话记录以 ID 为键，
// 因此存储层不会接触 token 明文。
type RefreshTokenFormat interface {
	Generate() (token string, id string, err error)
	Parse(token string) (id string, err error)
}

type opaqueRefreshTokenFormat struct {
	random RandomSource
}

// OpaqueRefreshOption 配置不透明 refresh token 生成器。
type OpaqueRefreshOption func(*opaqueRefreshTokenFormat)

// WithOpaqueRandomSource 指定不透明 token 使用的随机源（测试可注入 fake）。
func WithOpaqueRandomSource(random RandomSource) OpaqueRefreshOption {
	return func(format *opaqueRefreshTokenFormat) {
		format.random = random
	}
}

// NewOpaqueRefreshTokenFormat 创建 32 字节随机、Base64URL 编码的不透明 refresh token 生成器。
//
// token 形如 43 字符的 Base64URL 字符串，不含 "."；持久化 ID 为
// Base64URL(SHA-256(token))。调用方只需把 ID 交给 SessionStore，切勿存储 token 明文。
func NewOpaqueRefreshTokenFormat(opts ...OpaqueRefreshOption) RefreshTokenFormat {
	format := &opaqueRefreshTokenFormat{random: defaultRandomSource{}}
	for _, opt := range opts {
		if opt != nil {
			opt(format)
		}
	}
	if format.random == nil {
		format.random = defaultRandomSource{}
	}
	return format
}

func (f *opaqueRefreshTokenFormat) Generate() (string, string, error) {
	token, err := f.random.NewID(opaqueRefreshTokenBytes)
	if err != nil {
		return "", "", err
	}
	if _, err := decodeOpaqueRefreshToken(token); err != nil {
		return "", "", err
	}
	return token, opaqueRefreshTokenID(token), nil
}

func (f *opaqueRefreshTokenFormat) Parse(token string) (string, error) {
	if _, err := decodeOpaqueRefreshToken(token); err != nil {
		return "", err
	}
	return opaqueRefreshTokenID(token), nil
}

func decodeOpaqueRefreshToken(token string) ([]byte, error) {
	if token == "" {
		return nil, ErrInvalidTokenFormat
	}
	decoded, err := base64.RawURLEncoding.DecodeString(token)
	if err != nil {
		decoded, err = base64.URLEncoding.DecodeString(token)
	}
	if err != nil || len(decoded) != opaqueRefreshTokenBytes {
		return nil, ErrInvalidTokenFormat
	}
	return decoded, nil
}

func opaqueRefreshTokenID(token string) string {
	sum := sha256.Sum256([]byte(token))
	return base64.RawURLEncoding.EncodeToString(sum[:])
}
