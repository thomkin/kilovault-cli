package client

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"strings"
)

const encPrefix = "enc:v1:"

func deriveKey(secret string) [32]byte {
	return sha256.Sum256([]byte(secret))
}

// IsEncrypted reports whether value was produced by Encrypt.
func IsEncrypted(value string) bool {
	return strings.HasPrefix(value, encPrefix)
}

// Encrypt encrypts plaintext with AES-256-GCM using a key derived from
// secret. The secret never leaves the caller's machine. Output is
// "enc:v1:" + base64(nonce || ciphertext || tag).
func Encrypt(secret, plaintext string) (string, error) {
	key := deriveKey(secret)

	block, err := aes.NewCipher(key[:])
	if err != nil {
		return "", fmt.Errorf("failed to init cipher: %v", err)
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return "", fmt.Errorf("failed to init GCM: %v", err)
	}

	nonce := make([]byte, gcm.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return "", fmt.Errorf("failed to generate nonce: %v", err)
	}

	sealed := gcm.Seal(nonce, nonce, []byte(plaintext), nil)
	return encPrefix + base64.StdEncoding.EncodeToString(sealed), nil
}

// Decrypt decrypts a value produced by Encrypt using secret. Returns an
// error if secret is wrong or the value was tampered with.
func Decrypt(secret, stored string) (string, error) {
	plaintext, err := DecryptBytes(secret, stored)
	if err != nil {
		return "", err
	}
	return string(plaintext), nil
}

// DecryptBytes is like Decrypt but returns the raw plaintext bytes
// instead of a string. Prefer this over Decrypt when the plaintext is
// sensitive and short-lived (e.g. a batch file holding many secrets at
// once): a Go string is immutable and can't be wiped once created, but
// a []byte can be overwritten in place with ZeroBytes as soon as the
// caller is done with it.
func DecryptBytes(secret, stored string) ([]byte, error) {
	if !IsEncrypted(stored) {
		return nil, fmt.Errorf("value is not encrypted")
	}

	raw, err := base64.StdEncoding.DecodeString(strings.TrimPrefix(stored, encPrefix))
	if err != nil {
		return nil, fmt.Errorf("decryption failed: wrong secret or corrupted value")
	}

	key := deriveKey(secret)

	block, err := aes.NewCipher(key[:])
	if err != nil {
		return nil, fmt.Errorf("failed to init cipher: %v", err)
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("failed to init GCM: %v", err)
	}

	nonceSize := gcm.NonceSize()
	if len(raw) < nonceSize {
		return nil, fmt.Errorf("decryption failed: wrong secret or corrupted value")
	}

	nonce, ciphertext := raw[:nonceSize], raw[nonceSize:]
	plaintext, err := gcm.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return nil, fmt.Errorf("decryption failed: wrong secret or corrupted value")
	}

	return plaintext, nil
}

// ZeroBytes overwrites b with zeros in place. Best-effort defense in
// depth, not a guarantee: by the time this runs, Go's runtime may
// already have copied parts of b elsewhere (e.g. encoding/json
// allocates a fresh string per field when unmarshaling), and neither
// the language nor this function does anything about data swapped to
// disk or captured in a core dump.
func ZeroBytes(b []byte) {
	for i := range b {
		b[i] = 0
	}
}
