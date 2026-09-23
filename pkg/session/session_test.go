package session

import (
	"bytes"
	"errors"
	"path/filepath"
	"testing"
	"time"
)

// testID returns a session id unique to this test, skipping the test when
// the kernel keyring isn't usable (e.g. a container's seccomp profile
// blocks keyctl).
func testID(t *testing.T) string {
	t.Helper()
	id, err := ID(filepath.Join(t.TempDir(), "credentials.enc"))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := Save(id, []byte("probe"), time.Minute); errors.Is(err, ErrUnavailable) {
		t.Skip("kernel keyring unavailable here")
	} else if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { Clear(id) })
	return id
}

func TestSaveLoadClear(t *testing.T) {
	id := testID(t)
	key := bytes.Repeat([]byte{0xab}, 32)

	expires, err := Save(id, key, 10*time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	s, err := Load(id)
	if err != nil || s == nil {
		t.Fatalf("Load = %v, %v", s, err)
	}
	if !bytes.Equal(s.Key, key) || !s.Expires.Equal(expires) {
		t.Errorf("Load = %x until %v, want %x until %v", s.Key, s.Expires, key, expires)
	}

	cleared, err := Clear(id)
	if err != nil || !cleared {
		t.Fatalf("Clear = %v, %v", cleared, err)
	}
	if s, err := Load(id); err != nil || s != nil {
		t.Errorf("after Clear: Load = %v, %v", s, err)
	}
	if cleared, _ := Clear(id); cleared {
		t.Error("second Clear reported a session")
	}
}

func TestSaveReplacesExisting(t *testing.T) {
	id := testID(t)
	Save(id, []byte("first-key-first-key-first-key-12"), time.Minute)
	Save(id, []byte("second-key-second-key-second-123"), time.Minute)
	s, err := Load(id)
	if err != nil || s == nil || string(s.Key) != "second-key-second-key-second-123" {
		t.Errorf("Load = %+v, %v", s, err)
	}
}

func TestExpires(t *testing.T) {
	id := testID(t)
	if _, err := Save(id, []byte("k"), time.Second); err != nil {
		t.Fatal(err)
	}
	time.Sleep(2100 * time.Millisecond)
	if s, err := Load(id); err != nil || s != nil {
		t.Errorf("expired session: Load = %+v, %v", s, err)
	}
}

func TestIDsDifferPerStore(t *testing.T) {
	a, _ := ID("/home/a/.config/kilovault/credentials.enc")
	b, _ := ID("/home/b/.config/kilovault/credentials.enc")
	if a == b {
		t.Error("different stores share a session id")
	}
}

func TestValidateTTL(t *testing.T) {
	for _, bad := range []time.Duration{0, -time.Minute, MaxTTL + time.Second} {
		if ValidateTTL(bad) == nil {
			t.Errorf("ValidateTTL(%v) = nil", bad)
		}
	}
	if err := ValidateTTL(DefaultTTL); err != nil {
		t.Error(err)
	}
}
