// Package securestore is the crypto and file-handling core for the
// admin-side encrypted store (credentials and profile files): turning a
// master password into keys, sealing/opening files bound to their
// purpose and name, and reading/writing them with strict permissions.
//
// It is deliberately separate from pkg/client's Encrypt/Decrypt, which
// derive keys with a single SHA-256 and are only suitable for
// high-entropy secrets, not human-chosen passwords.
package securestore

import (
	"crypto/rand"
	"crypto/sha256"
	"errors"
	"fmt"
	"io"
	"unicode/utf8"

	"golang.org/x/crypto/argon2"
	"golang.org/x/crypto/hkdf"
)

// KeySize is the size in bytes of the master key and every subkey
// (AES-256).
const KeySize = 32

// SaltSize is the size in bytes of the argon2id salt.
const SaltSize = 16

// MinPasswordLength is the minimum master password length, in characters.
const MinPasswordLength = 12

// KDFParams are the argon2id cost parameters. They're stored alongside
// the salt so they can be raised later without breaking existing files.
type KDFParams struct {
	Time      uint32 `json:"t"`
	MemoryKiB uint32 `json:"m"`
	Threads   uint8  `json:"p"`
}

// DefaultKDFParams costs 64 MiB of memory and 3 passes per derivation
// (above OWASP's argon2id minimums) — negligible once per unlock,
// expensive per guess for an attacker holding the file, since every
// guess needs its own 64 MiB.
var DefaultKDFParams = KDFParams{Time: 3, MemoryKiB: 64 * 1024, Threads: 4}

// Lower bounds accepted from a file header, so a tampered header can't
// silently downgrade the KDF to something trivially brute-forceable.
const (
	minKDFTime      = 1
	minKDFMemoryKiB = 19 * 1024
)

func (p KDFParams) validate() error {
	if p.Time < minKDFTime || p.MemoryKiB < minKDFMemoryKiB || p.Threads < 1 {
		return fmt.Errorf("argon2id parameters too weak (t=%d, m=%d KiB, p=%d)", p.Time, p.MemoryKiB, p.Threads)
	}
	return nil
}

// Key purposes. Each yields an independent subkey from the master key,
// so no key is ever used for two different jobs.
const (
	PurposeCredentials = "credentials"
	PurposeProfile     = "profile"
	// PurposeBackup keys a credentials backup, derived from its own
	// recovery passphrase rather than the master password.
	PurposeBackup = "credentials-backup"
)

// NewSalt returns a fresh random argon2id salt.
func NewSalt() ([]byte, error) {
	salt := make([]byte, SaltSize)
	if _, err := io.ReadFull(rand.Reader, salt); err != nil {
		return nil, fmt.Errorf("failed to generate salt: %v", err)
	}
	return salt, nil
}

// ValidateMasterPassword enforces the minimum master password policy.
func ValidateMasterPassword(password []byte) error {
	if !utf8.Valid(password) {
		return errors.New("master password must be valid UTF-8")
	}
	if n := utf8.RuneCount(password); n < MinPasswordLength {
		return fmt.Errorf("master password must be at least %d characters (got %d)", MinPasswordLength, n)
	}
	return nil
}

// MasterKey is the argon2id output for a master password. Callers
// derive per-purpose subkeys from it and should Wipe it when done.
type MasterKey struct {
	key []byte
}

// DeriveMasterKey runs argon2id over password with salt and params.
func DeriveMasterKey(password, salt []byte, params KDFParams) (*MasterKey, error) {
	if len(password) == 0 {
		return nil, errors.New("empty master password")
	}
	if len(salt) != SaltSize {
		return nil, fmt.Errorf("invalid salt length %d", len(salt))
	}
	if err := params.validate(); err != nil {
		return nil, err
	}
	return &MasterKey{key: argon2.IDKey(password, salt, params.Time, params.MemoryKiB, params.Threads, KeySize)}, nil
}

// Bytes returns the raw master key. The caller must not retain or log it.
func (m *MasterKey) Bytes() []byte {
	return m.key
}

// Subkey derives the independent key for purpose via HKDF-SHA256.
func (m *MasterKey) Subkey(purpose string) ([]byte, error) {
	return DeriveKey(m.key, purpose)
}

// DeriveKey derives the independent key for purpose from a high-entropy
// root key (a master key or the random data key) via HKDF-SHA256.
func DeriveKey(root []byte, purpose string) ([]byte, error) {
	if purpose == "" {
		return nil, errors.New("empty key purpose")
	}
	if len(root) != KeySize {
		return nil, fmt.Errorf("invalid root key length %d", len(root))
	}
	r := hkdf.New(sha256.New, root, nil, []byte("kilovault/v1/"+purpose))
	sub := make([]byte, KeySize)
	if _, err := io.ReadFull(r, sub); err != nil {
		return nil, fmt.Errorf("failed to derive %s key: %v", purpose, err)
	}
	return sub, nil
}

// Wipe overwrites the master key in memory.
func (m *MasterKey) Wipe() {
	Wipe(m.key)
}

// Wipe overwrites b with zeros (best effort: Go may already have copied
// it elsewhere, but the buffer we control no longer holds the secret).
func Wipe(b []byte) {
	for i := range b {
		b[i] = 0
	}
}
