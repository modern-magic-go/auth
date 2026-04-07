package core

import (
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"time"
)

type defaultClock struct{}

func (defaultClock) Now() time.Time { return time.Now() }

type defaultRandomSource struct{}

func (defaultRandomSource) NewID(length int) (string, error) {
	if length <= 0 {
		return "", fmt.Errorf("invalid length")
	}
	b := make([]byte, length)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(b), nil
}

type jsonSerializer struct{}

func (jsonSerializer) Marshal(v any) (string, error) {
	b, err := json.Marshal(v)
	if err != nil {
		return "", err
	}
	return string(b), nil
}

func (jsonSerializer) Unmarshal(data string, v any) error {
	if err := json.Unmarshal([]byte(data), v); err != nil {
		return fmt.Errorf("unmarshal json: %w", err)
	}
	return nil
}
