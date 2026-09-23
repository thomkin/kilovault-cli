package securestore

import (
	"bytes"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// fastParams keeps tests quick while staying above the accepted minimum.
var fastParams = KDFParams{Time: 1, MemoryKiB: minKDFMemoryKiB, Threads: 1}

func testKey(t *testing.T, password string) *MasterKey {
	t.Helper()
	salt := bytes.Repeat([]byte{7}, SaltSize)
	mk, err := DeriveMasterKey([]byte(password), salt, fastParams)
	if err != nil {
		t.Fatal(err)
	}
	return mk
}

func TestDeriveMasterKey_DeterministicAndPasswordSensitive(t *testing.T) {
	a := testKey(t, "correct horse battery")
	b := testKey(t, "correct horse battery")
	c := testKey(t, "correct horse batterz")
	if !bytes.Equal(a.Bytes(), b.Bytes()) {
		t.Error("same password + salt must give the same key")
	}
	if bytes.Equal(a.Bytes(), c.Bytes()) {
		t.Error("different passwords must give different keys")
	}
}

func TestDeriveMasterKey_DefaultParams(t *testing.T) {
	salt, err := NewSalt()
	if err != nil {
		t.Fatal(err)
	}
	mk, err := DeriveMasterKey([]byte("correct horse battery"), salt, DefaultKDFParams)
	if err != nil {
		t.Fatal(err)
	}
	if len(mk.Bytes()) != KeySize {
		t.Errorf("key length = %d", len(mk.Bytes()))
	}
}

func TestDeriveMasterKey_RejectsBadInput(t *testing.T) {
	salt := make([]byte, SaltSize)
	if _, err := DeriveMasterKey(nil, salt, fastParams); err == nil {
		t.Error("empty password accepted")
	}
	if _, err := DeriveMasterKey([]byte("pw"), salt[:4], fastParams); err == nil {
		t.Error("short salt accepted")
	}
	weak := KDFParams{Time: 1, MemoryKiB: 8, Threads: 1}
	if _, err := DeriveMasterKey([]byte("pw"), salt, weak); err == nil {
		t.Error("weak KDF params accepted")
	}
}

func TestSubkeys_IndependentPerPurpose(t *testing.T) {
	mk := testKey(t, "correct horse battery")
	creds, _ := mk.Subkey(PurposeCredentials)
	prof, _ := mk.Subkey(PurposeProfile)
	again, _ := mk.Subkey(PurposeCredentials)
	if bytes.Equal(creds, prof) || bytes.Equal(creds, mk.Bytes()) {
		t.Error("subkeys must differ from each other and from the master key")
	}
	if !bytes.Equal(creds, again) {
		t.Error("subkey derivation must be deterministic")
	}
}

func TestMasterKey_Wipe(t *testing.T) {
	mk := testKey(t, "correct horse battery")
	mk.Wipe()
	if !bytes.Equal(mk.Bytes(), make([]byte, KeySize)) {
		t.Error("Wipe left key material behind")
	}
}

func TestValidateMasterPassword(t *testing.T) {
	if err := ValidateMasterPassword([]byte("short")); err == nil {
		t.Error("short password accepted")
	}
	if err := ValidateMasterPassword([]byte("ääääääääääää")); err != nil {
		t.Errorf("12 non-ASCII characters rejected: %v", err)
	}
	if err := ValidateMasterPassword([]byte{0xff, 0xfe, 'a', 'a', 'a', 'a', 'a', 'a', 'a', 'a', 'a', 'a'}); err == nil {
		t.Error("invalid UTF-8 accepted")
	}
}

func sealTestFile(t *testing.T, binding Binding, kdf *KDFHeader, plaintext string) ([]byte, []byte) {
	t.Helper()
	key, err := testKey(t, "correct horse battery").Subkey(binding.Purpose)
	if err != nil {
		t.Fatal(err)
	}
	sealed, err := Seal(key, binding, kdf, []byte(plaintext))
	if err != nil {
		t.Fatal(err)
	}
	return key, sealed
}

func TestSealOpen_RoundTrip(t *testing.T) {
	b := Binding{Purpose: PurposeProfile, Name: "alice"}
	key, sealed := sealTestFile(t, b, nil, `{"DB_PASSWORD":"hunter2"}`)

	if bytes.Contains(sealed, []byte("hunter2")) {
		t.Fatal("plaintext visible in sealed output")
	}
	got, err := Open(key, b, sealed)
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != `{"DB_PASSWORD":"hunter2"}` {
		t.Errorf("Open = %q", got)
	}
}

func TestSeal_FreshNonceEachTime(t *testing.T) {
	b := Binding{Purpose: PurposeProfile, Name: "alice"}
	key, first := sealTestFile(t, b, nil, "same")
	second, err := Seal(key, b, nil, []byte("same"))
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Equal(first, second) {
		t.Error("sealing the same plaintext twice must not produce identical output")
	}
}

func TestOpen_WrongKey(t *testing.T) {
	b := Binding{Purpose: PurposeProfile, Name: "alice"}
	_, sealed := sealTestFile(t, b, nil, "secret")
	wrong, _ := testKey(t, "wrong password!!").Subkey(PurposeProfile)
	if _, err := Open(wrong, b, sealed); !errors.Is(err, ErrDecrypt) {
		t.Errorf("err = %v, want ErrDecrypt", err)
	}
}

func TestOpen_RejectsSwappedFile(t *testing.T) {
	_, aliceFile := sealTestFile(t, Binding{Purpose: PurposeProfile, Name: "alice"}, nil, "alice's secrets")
	key, _ := testKey(t, "correct horse battery").Subkey(PurposeProfile)

	// Renamed file: asking for bob's profile must not return alice's.
	if _, err := Open(key, Binding{Purpose: PurposeProfile, Name: "bob"}, aliceFile); err == nil {
		t.Fatal("alice's file opened as bob's")
	}

	// Header edited to claim it's bob's: the binding is authenticated.
	var env map[string]json.RawMessage
	json.Unmarshal(aliceFile, &env)
	env["binding"] = json.RawMessage(`{"purpose":"profile","name":"bob"}`)
	forged, _ := json.Marshal(env)
	if _, err := Open(key, Binding{Purpose: PurposeProfile, Name: "bob"}, forged); !errors.Is(err, ErrDecrypt) {
		t.Errorf("forged binding: err = %v, want ErrDecrypt", err)
	}
}

func TestOpen_DetectsTampering(t *testing.T) {
	b := Binding{Purpose: PurposeProfile, Name: "alice"}
	key, sealed := sealTestFile(t, b, nil, "secret value")

	var env envelope
	if err := json.Unmarshal(sealed, &env); err != nil {
		t.Fatal(err)
	}
	env.Ciphertext[0] ^= 0x01
	tampered, _ := json.Marshal(env)
	if _, err := Open(key, b, tampered); !errors.Is(err, ErrDecrypt) {
		t.Errorf("err = %v, want ErrDecrypt", err)
	}
}

func TestKDFHeader_RoundTripAndAuthenticated(t *testing.T) {
	hdr, err := NewKDFHeader()
	if err != nil {
		t.Fatal(err)
	}
	hdr.Params = fastParams
	password := []byte("correct horse battery")

	mk, err := hdr.Derive(password)
	if err != nil {
		t.Fatal(err)
	}
	key, _ := mk.Subkey(PurposeCredentials)
	b := Binding{Purpose: PurposeCredentials, Name: "credentials"}
	sealed, err := Seal(key, b, hdr, []byte(`{"admin_token":"t"}`))
	if err != nil {
		t.Fatal(err)
	}

	// Unlock flow: read header → derive → open.
	readHdr, err := ReadKDFHeader(sealed)
	if err != nil || readHdr == nil {
		t.Fatalf("ReadKDFHeader: %v, %v", readHdr, err)
	}
	mk2, err := readHdr.Derive(password)
	if err != nil {
		t.Fatal(err)
	}
	key2, _ := mk2.Subkey(PurposeCredentials)
	if _, err := Open(key2, b, sealed); err != nil {
		t.Fatalf("Open after re-derive: %v", err)
	}

	// Raising the cost in the header (without the attacker knowing the
	// key) must make the file unopenable, not silently accepted.
	var env envelope
	json.Unmarshal(sealed, &env)
	env.KDF.Params.Time++
	edited, _ := json.Marshal(env)
	if _, err := Open(key2, b, edited); !errors.Is(err, ErrDecrypt) {
		t.Errorf("edited KDF header: err = %v, want ErrDecrypt", err)
	}
}

func TestReadKDFHeader_RejectsGarbageAndUnknownVersion(t *testing.T) {
	if _, err := ReadKDFHeader([]byte("not json")); err == nil {
		t.Error("garbage accepted")
	}
	if _, err := ReadKDFHeader([]byte(`{"v":99}`)); err == nil {
		t.Error("unknown version accepted")
	}
}

func TestWriteFileAtomic_PrivateModes(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "store")
	path := filepath.Join(dir, "credentials.enc")
	if err := WriteFileAtomic(path, []byte("one")); err != nil {
		t.Fatal(err)
	}
	if err := WriteFileAtomic(path, []byte("two")); err != nil {
		t.Fatal(err)
	}

	got, err := ReadPrivateFile(path)
	if err != nil || string(got) != "two" {
		t.Fatalf("ReadPrivateFile = %q, %v", got, err)
	}
	if info, _ := os.Stat(path); info.Mode().Perm() != 0600 {
		t.Errorf("file mode = %04o", info.Mode().Perm())
	}
	if info, _ := os.Stat(dir); info.Mode().Perm() != 0700 {
		t.Errorf("dir mode = %04o", info.Mode().Perm())
	}
	entries, _ := os.ReadDir(dir)
	if len(entries) != 1 {
		t.Errorf("temp files left behind: %v", entries)
	}
}

func TestReadPrivateFile_RefusesLoosePermissions(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "store")
	path := filepath.Join(dir, "credentials.enc")
	if err := WriteFileAtomic(path, []byte("x")); err != nil {
		t.Fatal(err)
	}

	os.Chmod(path, 0644)
	if _, err := ReadPrivateFile(path); err == nil || !strings.Contains(err.Error(), "chmod 600") {
		t.Errorf("0644 file: err = %v", err)
	}
	os.Chmod(path, 0600)

	os.Chmod(dir, 0755)
	if _, err := ReadPrivateFile(path); err == nil || !strings.Contains(err.Error(), "chmod 700") {
		t.Errorf("0755 dir: err = %v", err)
	}
	if err := EnsurePrivateDir(dir); err == nil {
		t.Error("EnsurePrivateDir accepted a 0755 dir")
	}
}

func TestPrivateChecks_RejectSymlinks(t *testing.T) {
	base := t.TempDir()
	dir := filepath.Join(base, "store")
	real := filepath.Join(dir, "real.enc")
	if err := WriteFileAtomic(real, []byte("x")); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(dir, "link.enc")
	if err := os.Symlink(real, link); err != nil {
		t.Fatal(err)
	}
	if _, err := ReadPrivateFile(link); err == nil {
		t.Error("ReadPrivateFile followed a symlink")
	}
	if err := WriteFileAtomic(link, []byte("y")); err == nil {
		t.Error("WriteFileAtomic replaced a symlink")
	}

	dirLink := filepath.Join(base, "storelink")
	os.Symlink(dir, dirLink)
	if err := EnsurePrivateDir(dirLink); err == nil {
		t.Error("EnsurePrivateDir accepted a symlinked dir")
	}
}

func TestIsRAMBacked(t *testing.T) {
	if ok, err := IsRAMBacked("/dev/shm"); err == nil && !ok {
		t.Error("/dev/shm should be tmpfs")
	}
	if _, err := IsRAMBacked("/nonexistent-dir-xyz"); err == nil {
		t.Error("missing dir should error")
	}
}

func TestHardenProcess(t *testing.T) {
	if err := HardenProcess(); err != nil {
		t.Fatalf("HardenProcess: %v", err)
	}
}
