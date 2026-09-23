// Package credentials manages credentials.enc: the master-password-
// protected file holding the admin token and one E2E secret per profile
// (vault user), for the admin-side `profiles` workflow.
//
// Key hierarchy:
//
//	master password ──argon2id──▶ master key ──HKDF──▶ credentials key
//	                                                     │ seals
//	                                                     ▼
//	                                credentials.enc payload: admin token,
//	                                per-profile secrets, and a random
//	                                data key ──HKDF──▶ profile file keys
//
// Profile files are sealed with keys derived from the random data key,
// not from the password, so changing the master password only
// re-encrypts credentials.enc, and a backup of it restores access to
// everything.
package credentials

import (
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/thomkin/kilovault-cli/pkg/securestore"
)

// FileName is the credentials file inside the kilovault config dir.
const FileName = "credentials.enc"

var (
	fileBinding   = securestore.Binding{Purpose: securestore.PurposeCredentials, Name: "credentials"}
	backupBinding = securestore.Binding{Purpose: securestore.PurposeBackup, Name: "credentials-backup"}
)

// ErrNotInitialized means credentials.enc doesn't exist yet.
var ErrNotInitialized = errors.New("no credentials store found — run `kilovault init` first")

// Vault holds the credentials for one kilovault endpoint.
type Vault struct {
	AdminToken string            `json:"admin_token,omitempty"`
	Secrets    map[string]string `json:"secrets,omitempty"`
}

// Payload is the decrypted content of credentials.enc.
type Payload struct {
	DataKey  []byte            `json:"data_key"`
	Vaults   map[string]*Vault `json:"vaults"`
	BackupAt string            `json:"backup_at,omitempty"`
}

// DefaultPath returns ~/.config/kilovault/credentials.enc.
func DefaultPath() (string, error) {
	home, err := os.UserHomeDir()
	if err != nil {
		return "", err
	}
	return filepath.Join(home, ".config", "kilovault", FileName), nil
}

// NormalizeEndpoint returns the form endpoints are keyed by, so
// "https://x/" and "https://x" share credentials.
func NormalizeEndpoint(endpoint string) string {
	return strings.TrimRight(strings.TrimSpace(endpoint), "/")
}

// Store is an unlocked credentials file. Mutate Payload through the
// helper methods, then Save. Call Close when done to wipe keys.
type Store struct {
	path    string
	kdf     *securestore.KDFHeader
	credKey []byte
	Payload *Payload
}

// Exists reports whether a credentials file is present at path.
func Exists(path string) bool {
	_, err := os.Lstat(path)
	return err == nil
}

// Create initializes a new credentials file at path, protected by
// password, with a fresh random data key. It refuses to overwrite an
// existing file.
func Create(path string, password []byte) (*Store, error) {
	if Exists(path) {
		return nil, fmt.Errorf("%s already exists", path)
	}
	dataKey, err := randomBytes(securestore.KeySize)
	if err != nil {
		return nil, err
	}
	return createWithPayload(path, password, &Payload{DataKey: dataKey, Vaults: map[string]*Vault{}})
}

func createWithPayload(path string, password []byte, payload *Payload) (*Store, error) {
	if err := securestore.ValidateMasterPassword(password); err != nil {
		return nil, err
	}
	s := &Store{path: path, Payload: payload}
	if err := s.rekey(password); err != nil {
		return nil, err
	}
	if err := s.Save(); err != nil {
		s.Close()
		return nil, err
	}
	return s, nil
}

// Unlock opens the credentials file at path with password.
func Unlock(path string, password []byte) (*Store, error) {
	data, hdr, err := readStoreFile(path)
	if err != nil {
		return nil, err
	}
	mk, err := hdr.Derive(password)
	if err != nil {
		return nil, err
	}
	defer mk.Wipe()
	credKey, err := mk.Subkey(securestore.PurposeCredentials)
	if err != nil {
		return nil, err
	}
	return openStoreData(path, data, hdr, credKey)
}

// UnlockWithKey opens the credentials file at path with a key previously
// obtained from Store.Key (e.g. cached by `kilovault unlock`). It fails
// with securestore.ErrDecrypt if the key is stale, e.g. after the master
// password was changed. key is copied.
func UnlockWithKey(path string, key []byte) (*Store, error) {
	data, hdr, err := readStoreFile(path)
	if err != nil {
		return nil, err
	}
	return openStoreData(path, data, hdr, append([]byte(nil), key...))
}

func readStoreFile(path string) ([]byte, *securestore.KDFHeader, error) {
	if !Exists(path) {
		return nil, nil, ErrNotInitialized
	}
	data, err := securestore.ReadPrivateFile(path)
	if err != nil {
		return nil, nil, err
	}
	hdr, err := securestore.ReadKDFHeader(data)
	if err != nil {
		return nil, nil, fmt.Errorf("%s: %v", path, err)
	}
	if hdr == nil {
		return nil, nil, fmt.Errorf("%s: missing key derivation header", path)
	}
	return data, hdr, nil
}

// openStoreData takes ownership of credKey (wiping it on failure).
func openStoreData(path string, data []byte, hdr *securestore.KDFHeader, credKey []byte) (*Store, error) {
	payload, err := openPayload(credKey, fileBinding, data)
	if err != nil {
		securestore.Wipe(credKey)
		return nil, err
	}
	return &Store{path: path, kdf: hdr, credKey: credKey, Payload: payload}, nil
}

// Path is the file this store was opened from.
func (s *Store) Path() string {
	return s.path
}

// Key returns the key that opens this store's file without the master
// password, for the unlock session cache. It changes when the master
// password changes. The caller must not retain or log it.
func (s *Store) Key() []byte {
	return s.credKey
}

func openPayload(key []byte, binding securestore.Binding, data []byte) (*Payload, error) {
	plain, err := securestore.Open(key, binding, data)
	if err != nil {
		return nil, err
	}
	defer securestore.Wipe(plain)

	var p Payload
	if err := json.Unmarshal(plain, &p); err != nil {
		return nil, fmt.Errorf("corrupt credentials payload: %v", err)
	}
	if len(p.DataKey) != securestore.KeySize {
		return nil, errors.New("corrupt credentials payload: invalid data key")
	}
	if p.Vaults == nil {
		p.Vaults = map[string]*Vault{}
	}
	return &p, nil
}

// rekey derives a new credentials key from password with a fresh salt.
func (s *Store) rekey(password []byte) error {
	hdr, err := securestore.NewKDFHeader()
	if err != nil {
		return err
	}
	mk, err := hdr.Derive(password)
	if err != nil {
		return err
	}
	defer mk.Wipe()
	credKey, err := mk.Subkey(securestore.PurposeCredentials)
	if err != nil {
		return err
	}
	securestore.Wipe(s.credKey)
	s.kdf, s.credKey = hdr, credKey
	return nil
}

// Save re-encrypts and atomically writes the payload.
func (s *Store) Save() error {
	return writeSealed(s.path, s.credKey, fileBinding, s.kdf, s.Payload)
}

func writeSealed(path string, key []byte, binding securestore.Binding, kdf *securestore.KDFHeader, p *Payload) error {
	plain, err := json.Marshal(p)
	if err != nil {
		return err
	}
	defer securestore.Wipe(plain)
	sealed, err := securestore.Seal(key, binding, kdf, plain)
	if err != nil {
		return err
	}
	return securestore.WriteFileAtomic(path, sealed)
}

// ChangePassword re-encrypts the file under newPassword (fresh salt).
// The data key, and thus every profile file, is unaffected.
func (s *Store) ChangePassword(newPassword []byte) error {
	if err := securestore.ValidateMasterPassword(newPassword); err != nil {
		return err
	}
	if err := s.rekey(newPassword); err != nil {
		return err
	}
	return s.Save()
}

// Close wipes the keys held in memory.
func (s *Store) Close() {
	securestore.Wipe(s.credKey)
	if s.Payload != nil {
		securestore.Wipe(s.Payload.DataKey)
	}
}

// DataKey returns the random key profile files are sealed under.
func (s *Store) DataKey() []byte {
	return s.Payload.DataKey
}

// Vault returns the credentials for endpoint, or nil if none are stored.
func (s *Store) Vault(endpoint string) *Vault {
	return s.Payload.Vaults[NormalizeEndpoint(endpoint)]
}

func (s *Store) vaultForWrite(endpoint string) *Vault {
	key := NormalizeEndpoint(endpoint)
	v := s.Payload.Vaults[key]
	if v == nil {
		v = &Vault{}
		s.Payload.Vaults[key] = v
	}
	if v.Secrets == nil {
		v.Secrets = map[string]string{}
	}
	return v
}

// SetAdminToken stores the admin token for endpoint.
func (s *Store) SetAdminToken(endpoint, token string) {
	s.vaultForWrite(endpoint).AdminToken = token
}

// AdminToken returns the admin token for endpoint, or "".
func (s *Store) AdminToken(endpoint string) string {
	if v := s.Vault(endpoint); v != nil {
		return v.AdminToken
	}
	return ""
}

// SetSecret stores the E2E secret for profile (vault user) on endpoint.
func (s *Store) SetSecret(endpoint, profile, secret string) {
	s.vaultForWrite(endpoint).Secrets[profile] = secret
}

// RemoveSecret deletes profile's secret, reporting whether it existed.
func (s *Store) RemoveSecret(endpoint, profile string) bool {
	v := s.Vault(endpoint)
	if v == nil {
		return false
	}
	_, ok := v.Secrets[profile]
	delete(v.Secrets, profile)
	return ok
}

// Secret returns profile's E2E secret on endpoint, or "".
func (s *Store) Secret(endpoint, profile string) string {
	if v := s.Vault(endpoint); v != nil {
		return v.Secrets[profile]
	}
	return ""
}

// Profiles returns the profiles with a stored secret on endpoint, sorted.
func (s *Store) Profiles(endpoint string) []string {
	v := s.Vault(endpoint)
	if v == nil {
		return nil
	}
	names := make([]string, 0, len(v.Secrets))
	for name := range v.Secrets {
		names = append(names, name)
	}
	sort.Strings(names)
	return names
}

// WriteBackup writes a copy of the payload to path, protected by its own
// recovery passphrase (independent salt and key), and records the
// backup time in the store.
func (s *Store) WriteBackup(path string, recoveryPassphrase []byte) error {
	if err := securestore.ValidateMasterPassword(recoveryPassphrase); err != nil {
		return fmt.Errorf("recovery passphrase: %v", err)
	}
	hdr, err := securestore.NewKDFHeader()
	if err != nil {
		return err
	}
	mk, err := hdr.Derive(recoveryPassphrase)
	if err != nil {
		return err
	}
	defer mk.Wipe()
	key, err := mk.Subkey(securestore.PurposeBackup)
	if err != nil {
		return err
	}
	defer securestore.Wipe(key)

	prevBackupAt := s.Payload.BackupAt
	s.Payload.BackupAt = time.Now().UTC().Format(time.RFC3339)
	if err := writeBackupFile(path, key, hdr, s.Payload); err != nil {
		s.Payload.BackupAt = prevBackupAt
		return err
	}
	return s.Save()
}

// writeBackupFile creates path exclusively (never overwriting) with mode
// 0600. Unlike the store itself it doesn't require a private directory:
// backups are meant to go to removable media or a password manager, and
// the content is sealed under the recovery passphrase anyway.
func writeBackupFile(path string, key []byte, hdr *securestore.KDFHeader, p *Payload) error {
	plain, err := json.Marshal(p)
	if err != nil {
		return err
	}
	defer securestore.Wipe(plain)
	sealed, err := securestore.Seal(key, backupBinding, hdr, plain)
	if err != nil {
		return err
	}
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
	if err != nil {
		return err
	}
	if _, err := f.Write(sealed); err != nil {
		f.Close()
		os.Remove(path)
		return err
	}
	if err := f.Sync(); err != nil {
		f.Close()
		os.Remove(path)
		return err
	}
	return f.Close()
}

// OpenBackup decrypts a backup written by WriteBackup. The returned
// payload holds the data key; wipe it (or pass it to CreateFromBackup,
// whose Store.Close wipes it) when done.
func OpenBackup(backupPath string, recoveryPassphrase []byte) (*Payload, error) {
	data, err := os.ReadFile(backupPath)
	if err != nil {
		return nil, err
	}
	hdr, err := securestore.ReadKDFHeader(data)
	if err != nil {
		return nil, fmt.Errorf("%s: %v", backupPath, err)
	}
	if hdr == nil {
		return nil, fmt.Errorf("%s: missing key derivation header", backupPath)
	}
	mk, err := hdr.Derive(recoveryPassphrase)
	if err != nil {
		return nil, err
	}
	defer mk.Wipe()
	key, err := mk.Subkey(securestore.PurposeBackup)
	if err != nil {
		return nil, err
	}
	defer securestore.Wipe(key)

	payload, err := openPayload(key, backupBinding, data)
	if err != nil {
		if errors.Is(err, securestore.ErrDecrypt) {
			return nil, errors.New("can't open backup: wrong recovery passphrase, or the file is not a credentials backup or was modified")
		}
		return nil, err
	}
	return payload, nil
}

// CreateFromBackup creates a credentials file at path holding payload
// (from OpenBackup), protected by newPassword.
func CreateFromBackup(path string, payload *Payload, newPassword []byte) (*Store, error) {
	if Exists(path) {
		return nil, fmt.Errorf("%s already exists — move it aside first", path)
	}
	return createWithPayload(path, newPassword, payload)
}

// GenerateSecret returns a new random E2E secret (32 bytes, base64url).
func GenerateSecret() (string, error) {
	b, err := randomBytes(32)
	if err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(b), nil
}

func randomBytes(n int) ([]byte, error) {
	b := make([]byte, n)
	if _, err := io.ReadFull(rand.Reader, b); err != nil {
		return nil, fmt.Errorf("failed to generate random bytes: %v", err)
	}
	return b, nil
}
