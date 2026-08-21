package client

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"os"
	"time"
)

type JWTHeader struct {
	Alg string `json:"alg"`
	Typ string `json:"typ"`
}

type JWTPayload struct {
	Sub         string                 `json:"sub"`
	Permissions map[string]bool        `json:"permissions,omitempty"`
	Exp         int64                  `json:"exp,omitempty"`
	Iat         int64                  `json:"iat"`
}

func GenerateToken(userID string, permissions map[string]bool, expiresIn *int, jwtSecret string) (string, error) {
	if jwtSecret == "" {
		return "", fmt.Errorf("JWT_SECRET required for token generation")
	}

	now := time.Now().Unix()
	header := JWTHeader{Alg: "HS256", Typ: "JWT"}
	payload := JWTPayload{
		Sub:         userID,
		Permissions: permissions,
		Iat:         now,
	}

	if expiresIn != nil && *expiresIn > 0 {
		payload.Exp = now + int64(*expiresIn)
	}

	headerJSON, _ := json.Marshal(header)
	payloadJSON, _ := json.Marshal(payload)

	headerB64 := base64.RawURLEncoding.EncodeToString(headerJSON)
	payloadB64 := base64.RawURLEncoding.EncodeToString(payloadJSON)

	message := headerB64 + "." + payloadB64

	sig := hmac.New(sha256.New, []byte(jwtSecret))
	sig.Write([]byte(message))
	sigB64 := base64.RawURLEncoding.EncodeToString(sig.Sum(nil))

	return message + "." + sigB64, nil
}

func ResolveJWTSecret(flagSecret string) string {
	if flagSecret != "" {
		return flagSecret
	}

	if envSecret := os.Getenv("JWT_SECRET"); envSecret != "" {
		return envSecret
	}

	cfg, err := LoadConfigFile()
	if err == nil && cfg.JWTSecret != "" {
		return cfg.JWTSecret
	}

	return ""
}
