package core

import (
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"time"
)

func (s *Service) buildGraceRecord(
	_ context.Context,
	oldTokenID, newTokenID, sessionID, subject, accessToken, refreshToken string,
	accessExpiresAt, refreshExpiresAt time.Time,
) (RefreshGraceRecord, error) {
	accessCiphertext, err := encryptGraceToken(s.graceKey, accessToken)
	if err != nil {
		return RefreshGraceRecord{}, err
	}
	refreshCiphertext, err := encryptGraceToken(s.graceKey, refreshToken)
	if err != nil {
		return RefreshGraceRecord{}, err
	}
	return RefreshGraceRecord{
		OldTokenID:             oldTokenID,
		NewTokenID:             newTokenID,
		SessionID:              sessionID,
		Subject:                subject,
		AccessTokenCiphertext:  accessCiphertext,
		RefreshTokenCiphertext: refreshCiphertext,
		AccessExpiresAt:        accessExpiresAt,
		RefreshExpiresAt:       refreshExpiresAt,
	}, nil
}

func (s *Service) replayFromGrace(ctx context.Context, _ string, oldTokenID string) (RefreshResult, bool, error) {
	if s.graceStore == nil {
		return RefreshResult{}, false, nil
	}
	record, err := s.graceStore.GetRefreshGrace(ctx, oldTokenID)
	if err != nil {
		if errors.Is(err, ErrSessionNotFound) {
			return RefreshResult{}, false, nil
		}
		return RefreshResult{}, false, err
	}
	if err := s.checkRevoked(ctx, record.SessionID, record.Subject); err != nil {
		return RefreshResult{}, false, err
	}
	if _, err := s.store.GetRefreshSession(ctx, record.NewTokenID); err != nil {
		if errors.Is(err, ErrSessionNotFound) {
			return RefreshResult{}, false, ErrTokenRevoked
		}
		return RefreshResult{}, false, err
	}
	refreshToken, err := decryptGraceToken(s.graceKey, record.RefreshTokenCiphertext)
	if err != nil {
		return RefreshResult{}, false, err
	}
	accessToken, err := decryptGraceToken(s.graceKey, record.AccessTokenCiphertext)
	if err != nil {
		return RefreshResult{}, false, err
	}
	if accessToken == "" || refreshToken == "" {
		return RefreshResult{}, false, ErrInvalidTokenFormat
	}
	return RefreshResult{
		AccessToken:   accessToken,
		RefreshToken:  refreshToken,
		AccessExpiry:  record.AccessExpiresAt,
		RefreshExpiry: record.RefreshExpiresAt,
		Rotated:       true,
		SessionID:     record.SessionID,
	}, true, nil
}

func encryptGraceToken(key []byte, token string) (string, error) {
	aead, err := newGraceAEAD(key)
	if err != nil {
		return "", err
	}
	nonce := make([]byte, aead.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return "", err
	}
	sealed := aead.Seal(nonce, nonce, []byte(token), nil)
	return base64.RawURLEncoding.EncodeToString(sealed), nil
}

func decryptGraceToken(key []byte, ciphertext string) (string, error) {
	aead, err := newGraceAEAD(key)
	if err != nil {
		return "", err
	}
	raw, err := base64.RawURLEncoding.DecodeString(ciphertext)
	if err != nil || len(raw) < aead.NonceSize() {
		return "", ErrInvalidTokenFormat
	}
	nonce, sealed := raw[:aead.NonceSize()], raw[aead.NonceSize():]
	plaintext, err := aead.Open(nil, nonce, sealed, nil)
	if err != nil {
		return "", fmt.Errorf("%w: grace token decrypt failed", ErrInvalidTokenFormat)
	}
	return string(plaintext), nil
}

func newGraceAEAD(key []byte) (cipher.AEAD, error) {
	if len(key) != 32 {
		return nil, ErrInvalidConfig
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	return cipher.NewGCM(block)
}
