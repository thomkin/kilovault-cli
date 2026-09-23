// Package session caches the key that opens credentials.enc for a
// limited time after `kilovault unlock`, so the master password isn't
// needed for every command.
//
// The key lives in the Linux kernel's per-user keyring with a kernel-
// enforced timeout: it is never written to disk, and it disappears when
// the timeout expires, on `kilovault lock`, or at reboot. While it's
// cached, any process running as the same user can read it — that is the
// trade-off for not re-typing the password, and why the timeout is short
// by default.
package session

import (
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"path/filepath"
	"time"
)

// DefaultTTL is how long `unlock` keeps the store unlocked by default.
const DefaultTTL = 15 * time.Minute

// MaxTTL caps how long a session may last.
const MaxTTL = 12 * time.Hour

// ErrUnavailable means the kernel keyring can't be used here (non-Linux,
// or keyring syscalls blocked, e.g. by a container's seccomp profile).
var ErrUnavailable = errors.New("the kernel keyring is not available here, so the store can't stay unlocked — every command will ask for the master password")

// Session is a cached, unexpired store key.
type Session struct {
	Key     []byte
	Expires time.Time
}

// ID returns the keyring description for the store at storePath, so
// different stores (e.g. different HOMEs) never share a session.
func ID(storePath string) (string, error) {
	abs, err := filepath.Abs(storePath)
	if err != nil {
		return "", err
	}
	sum := sha256.Sum256([]byte(abs))
	return "kilovault-cli:" + hex.EncodeToString(sum[:8]), nil
}

// ValidateTTL checks a requested session length.
func ValidateTTL(ttl time.Duration) error {
	if ttl < time.Second {
		return fmt.Errorf("timeout must be at least 1s")
	}
	if ttl > MaxTTL {
		return fmt.Errorf("timeout must be at most %s", MaxTTL)
	}
	return nil
}

// payload layout: 8-byte big-endian unix expiry, then the key. The
// kernel enforces the timeout; the embedded expiry lets us report the
// remaining time and double-check it on read.
func encode(key []byte, expires time.Time) []byte {
	buf := make([]byte, 8+len(key))
	binary.BigEndian.PutUint64(buf, uint64(expires.Unix()))
	copy(buf[8:], key)
	return buf
}

func decode(buf []byte) (*Session, error) {
	if len(buf) <= 8 {
		return nil, errors.New("malformed session")
	}
	expires := time.Unix(int64(binary.BigEndian.Uint64(buf)), 0)
	return &Session{Key: append([]byte(nil), buf[8:]...), Expires: expires}, nil
}
