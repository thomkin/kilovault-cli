package credentials

import (
	"bytes"
	"errors"
	"os"
	"path/filepath"
	"testing"

	"github.com/thomkin/kilovault-cli/pkg/securestore"
)

const pw = "correct horse battery"

func newStore(t *testing.T) (*Store, string) {
	t.Helper()
	path := filepath.Join(t.TempDir(), "kv", FileName)
	s, err := Create(path, []byte(pw))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(s.Close)
	return s, path
}

func TestCreateUnlockRoundTrip(t *testing.T) {
	s, path := newStore(t)
	s.SetAdminToken("https://vault.example/", "tok")
	s.SetSecret("https://vault.example", "alice", "a-secret")
	if err := s.Save(); err != nil {
		t.Fatal(err)
	}

	u, err := Unlock(path, []byte(pw))
	if err != nil {
		t.Fatal(err)
	}
	defer u.Close()
	if u.AdminToken("https://vault.example") != "tok" || u.Secret("https://vault.example/", "alice") != "a-secret" {
		t.Errorf("payload not round-tripped: %+v", u.Payload.Vaults)
	}
	if !bytes.Equal(u.DataKey(), s.DataKey()) || len(u.DataKey()) != securestore.KeySize {
		t.Error("data key not preserved")
	}
	if got := u.Profiles("https://vault.example"); len(got) != 1 || got[0] != "alice" {
		t.Errorf("Profiles = %v", got)
	}
}

func TestCreate_RefusesExistingAndWeakPassword(t *testing.T) {
	_, path := newStore(t)
	if _, err := Create(path, []byte(pw)); err == nil {
		t.Error("Create overwrote an existing store")
	}
	if _, err := Create(filepath.Join(t.TempDir(), FileName), []byte("short")); err == nil {
		t.Error("weak password accepted")
	}
}

func TestUnlock_Errors(t *testing.T) {
	_, path := newStore(t)
	if _, err := Unlock(path, []byte("wrong password!!")); !errors.Is(err, securestore.ErrDecrypt) {
		t.Errorf("wrong password: err = %v", err)
	}
	if _, err := Unlock(filepath.Join(t.TempDir(), "missing.enc"), []byte(pw)); !errors.Is(err, ErrNotInitialized) {
		t.Errorf("missing file: err = %v", err)
	}
}

func TestChangePassword_KeepsDataKey(t *testing.T) {
	s, path := newStore(t)
	before := append([]byte(nil), s.DataKey()...)
	newPW := "another long password"
	if err := s.ChangePassword([]byte(newPW)); err != nil {
		t.Fatal(err)
	}
	if _, err := Unlock(path, []byte(pw)); err == nil {
		t.Error("old password still unlocks")
	}
	u, err := Unlock(path, []byte(newPW))
	if err != nil {
		t.Fatal(err)
	}
	defer u.Close()
	if !bytes.Equal(u.DataKey(), before) {
		t.Error("data key changed with the password — profile files would become unreadable")
	}
}

func TestBackupRestore(t *testing.T) {
	s, path := newStore(t)
	s.SetSecret("https://v", "alice", "a-secret")
	if err := s.Save(); err != nil {
		t.Fatal(err)
	}
	backup := filepath.Join(t.TempDir(), "backup")
	recovery := []byte("recovery passphrase")
	if err := s.WriteBackup(backup, recovery); err != nil {
		t.Fatal(err)
	}
	if s.Payload.BackupAt == "" {
		t.Error("BackupAt not set")
	}
	if err := s.WriteBackup(backup, recovery); err == nil {
		t.Error("backup overwrote an existing file")
	}

	// The master password must not open the backup, and vice versa.
	if _, err := OpenBackup(backup, []byte(pw)); err == nil {
		t.Error("master password opened the backup")
	}
	if _, err := Unlock(backup, recovery); err == nil {
		t.Error("backup opened as a credentials file")
	}

	payload, err := OpenBackup(backup, recovery)
	if err != nil {
		t.Fatal(err)
	}
	os.Remove(path)
	r, err := CreateFromBackup(path, payload, []byte("new master password"))
	if err != nil {
		t.Fatal(err)
	}
	defer r.Close()
	if r.Secret("https://v", "alice") != "a-secret" || !bytes.Equal(r.DataKey(), s.DataKey()) {
		t.Error("restore lost data")
	}
}

func TestGenerateSecret(t *testing.T) {
	a, _ := GenerateSecret()
	b, _ := GenerateSecret()
	if a == b || len(a) != 43 {
		t.Errorf("GenerateSecret = %q, %q", a, b)
	}
}
