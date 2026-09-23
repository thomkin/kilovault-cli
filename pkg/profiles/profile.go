// Package profiles implements the admin-side local mirror of a vault:
// one encrypted file per vault user ("profile"), holding a working copy
// that `kilovault profiles edit` changes and the last-synced state that
// pull/diff/push compare it against. The network side lives in
// cmd/kilovault/profiles.go.
package profiles

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/thomkin/kilovault-cli/pkg/securestore"
)

// FileExt is the extension of a profile file inside the profiles dir.
const FileExt = ".json.enc"

const formatVersion = 1

// KeyState is one key as of the last successful pull or push.
type KeyState struct {
	// Value is the plaintext value.
	Value string `json:"value"`
	// Remote is RemoteHash of the value exactly as stored on the server
	// (ciphertext for encrypted values, whose random nonce makes every
	// remote write change it) — how push detects remote changes.
	Remote string `json:"remote"`
	// Encrypted is whether the server copy is E2E encrypted; push keeps
	// an existing key's mode.
	Encrypted bool `json:"encrypted"`
}

// Profile is the decrypted content of one profile file.
type Profile struct {
	Version  int                 `json:"v"`
	Endpoint string              `json:"endpoint"`
	User     string              `json:"user"`
	Values   map[string]string   `json:"values"`
	Base     map[string]KeyState `json:"base"`
	SyncedAt string              `json:"synced_at,omitempty"`
}

// New returns an empty, never-synced profile.
func New(endpoint, user string) *Profile {
	return &Profile{
		Version:  formatVersion,
		Endpoint: endpoint,
		User:     user,
		Values:   map[string]string{},
		Base:     map[string]KeyState{},
	}
}

// RemoteHash is the fingerprint of a server-side stored value.
func RemoteHash(stored string) string {
	sum := sha256.Sum256([]byte(stored))
	return hex.EncodeToString(sum[:])
}

// ValidateUser reports whether userID can be used as a profile file name.
func ValidateUser(userID string) error {
	if userID == "" || userID == "." || userID == ".." {
		return fmt.Errorf("invalid user id %q", userID)
	}
	if strings.HasPrefix(userID, ".") || strings.ContainsAny(userID, "/\\\x00") {
		return fmt.Errorf("user id %q can't be used as a profile file name (leading '.', '/', '\\' or NUL)", userID)
	}
	return nil
}

// Path is the profile file for userID inside dir.
func Path(dir, userID string) string {
	return filepath.Join(dir, userID+FileExt)
}

// Exists reports whether a profile file for userID exists in dir.
func Exists(dir, userID string) bool {
	_, err := os.Lstat(Path(dir, userID))
	return err == nil
}

// ListLocal returns the user ids of all profile files in dir, sorted. A
// missing dir yields no profiles.
func ListLocal(dir string) ([]string, error) {
	entries, err := os.ReadDir(dir)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, err
	}
	var users []string
	for _, e := range entries {
		name := e.Name()
		if e.IsDir() || !strings.HasSuffix(name, FileExt) {
			continue
		}
		if user := strings.TrimSuffix(name, FileExt); ValidateUser(user) == nil {
			users = append(users, user)
		}
	}
	sort.Strings(users)
	return users, nil
}

// binding ties a profile file to its endpoint and user, so it can't be
// opened as another user's profile or for another vault.
func binding(endpoint, user string) securestore.Binding {
	return securestore.Binding{Purpose: securestore.PurposeProfile, Name: endpoint + " " + user}
}

func profileKey(dataKey []byte) ([]byte, error) {
	return securestore.DeriveKey(dataKey, securestore.PurposeProfile)
}

// Load decrypts the profile for user on endpoint from dir.
func Load(dir string, dataKey []byte, endpoint, user string) (*Profile, error) {
	if err := ValidateUser(user); err != nil {
		return nil, err
	}
	path := Path(dir, user)
	data, err := securestore.ReadPrivateFile(path)
	if err != nil {
		return nil, err
	}
	key, err := profileKey(dataKey)
	if err != nil {
		return nil, err
	}
	defer securestore.Wipe(key)

	plain, err := securestore.Open(key, binding(endpoint, user), data)
	if err != nil {
		return nil, fmt.Errorf("%s: %v", path, err)
	}
	defer securestore.Wipe(plain)

	var p Profile
	if err := json.Unmarshal(plain, &p); err != nil {
		return nil, fmt.Errorf("%s: corrupt profile: %v", path, err)
	}
	if p.Version != formatVersion {
		return nil, fmt.Errorf("%s: unsupported profile version %d", path, p.Version)
	}
	if p.Values == nil {
		p.Values = map[string]string{}
	}
	if p.Base == nil {
		p.Base = map[string]KeyState{}
	}
	return &p, nil
}

// Save encrypts and atomically writes p into dir.
func Save(dir string, dataKey []byte, p *Profile) error {
	if err := ValidateUser(p.User); err != nil {
		return err
	}
	key, err := profileKey(dataKey)
	if err != nil {
		return err
	}
	defer securestore.Wipe(key)

	plain, err := json.Marshal(p)
	if err != nil {
		return err
	}
	defer securestore.Wipe(plain)
	sealed, err := securestore.Seal(key, binding(p.Endpoint, p.User), nil, plain)
	if err != nil {
		return err
	}
	return securestore.WriteFileAtomic(Path(dir, p.User), sealed)
}

// ChangeKind is what push would do to one key.
type ChangeKind string

const (
	Add    ChangeKind = "add"
	Modify ChangeKind = "modify"
	Delete ChangeKind = "delete"
)

// Symbol is the one-character marker used when listing changes.
func (k ChangeKind) Symbol() string {
	switch k {
	case Add:
		return "+"
	case Modify:
		return "~"
	default:
		return "-"
	}
}

// Change is one pending local edit: Old is the last-synced value (empty
// for Add), New the working-copy value (empty for Delete).
type Change struct {
	Kind ChangeKind
	Key  string
	Old  string
	New  string
}

// Changes lists the working copy's differences from the last-synced
// state, sorted by key.
func (p *Profile) Changes() []Change {
	var changes []Change
	for key, v := range p.Values {
		base, synced := p.Base[key]
		switch {
		case !synced:
			changes = append(changes, Change{Kind: Add, Key: key, New: v})
		case base.Value != v:
			changes = append(changes, Change{Kind: Modify, Key: key, Old: base.Value, New: v})
		}
	}
	for key, base := range p.Base {
		if _, ok := p.Values[key]; !ok {
			changes = append(changes, Change{Kind: Delete, Key: key, Old: base.Value})
		}
	}
	sort.Slice(changes, func(i, j int) bool { return changes[i].Key < changes[j].Key })
	return changes
}
