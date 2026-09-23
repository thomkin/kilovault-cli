package securestore

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/json"
	"errors"
	"fmt"
	"io"
)

// envelopeVersion is the on-disk format version of a sealed file.
const envelopeVersion = 1

// ErrDecrypt is returned when a sealed file can't be opened: wrong key
// (i.e. wrong master password), or the file was modified, swapped for
// another file, or corrupted. These cases are deliberately
// indistinguishable.
var ErrDecrypt = errors.New("decryption failed: wrong master password, or the file was modified or corrupted")

// Binding ties a sealed file to what it is. It's authenticated (but not
// encrypted), so a file sealed as {profile, alice} fails to open as
// {profile, bob} — swapping or renaming encrypted files is detected.
type Binding struct {
	Purpose string `json:"purpose"`
	Name    string `json:"name"`
}

// KDFHeader records how the master key was derived. It's stored in the
// plaintext header of the one file that anchors the master password
// (credentials.enc) and is authenticated along with everything else.
type KDFHeader struct {
	Alg    string    `json:"alg"`
	Salt   []byte    `json:"salt"`
	Params KDFParams `json:"params"`
}

// NewKDFHeader returns a header with a fresh salt and the default cost.
func NewKDFHeader() (*KDFHeader, error) {
	salt, err := NewSalt()
	if err != nil {
		return nil, err
	}
	return &KDFHeader{Alg: "argon2id", Salt: salt, Params: DefaultKDFParams}, nil
}

// Derive runs the header's KDF over password.
func (h *KDFHeader) Derive(password []byte) (*MasterKey, error) {
	if h.Alg != "argon2id" {
		return nil, fmt.Errorf("unsupported KDF %q", h.Alg)
	}
	return DeriveMasterKey(password, h.Salt, h.Params)
}

// envelope is the JSON on-disk form of a sealed file. []byte fields are
// base64 in JSON.
type envelope struct {
	Version    int        `json:"v"`
	Binding    Binding    `json:"binding"`
	KDF        *KDFHeader `json:"kdf,omitempty"`
	Nonce      []byte     `json:"nonce"`
	Ciphertext []byte     `json:"ciphertext"`
}

// additionalData is the AES-GCM associated data: every plaintext header
// field, so none of them can be altered without Open failing.
func (e *envelope) additionalData() ([]byte, error) {
	return json.Marshal(struct {
		Magic   string     `json:"magic"`
		Version int        `json:"v"`
		Binding Binding    `json:"binding"`
		KDF     *KDFHeader `json:"kdf,omitempty"`
	}{"kilovault-sealed", e.Version, e.Binding, e.KDF})
}

func newGCM(key []byte) (cipher.AEAD, error) {
	if len(key) != KeySize {
		return nil, fmt.Errorf("invalid key length %d", len(key))
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	return cipher.NewGCM(block)
}

// Seal encrypts plaintext with key (AES-256-GCM, fresh random nonce),
// bound to binding, and returns the file content. kdf is optional and
// is only set for the file that anchors the master password.
func Seal(key []byte, binding Binding, kdf *KDFHeader, plaintext []byte) ([]byte, error) {
	if binding.Purpose == "" || binding.Name == "" {
		return nil, errors.New("binding purpose and name are required")
	}
	gcm, err := newGCM(key)
	if err != nil {
		return nil, err
	}
	env := envelope{Version: envelopeVersion, Binding: binding, KDF: kdf}
	env.Nonce = make([]byte, gcm.NonceSize())
	if _, err := io.ReadFull(rand.Reader, env.Nonce); err != nil {
		return nil, fmt.Errorf("failed to generate nonce: %v", err)
	}
	ad, err := env.additionalData()
	if err != nil {
		return nil, err
	}
	env.Ciphertext = gcm.Seal(nil, env.Nonce, plaintext, ad)
	return json.MarshalIndent(env, "", "  ")
}

// ReadKDFHeader returns the KDF header of a sealed file without
// decrypting it, so the master key can be derived before calling Open.
// It returns nil if the file carries no KDF header.
func ReadKDFHeader(data []byte) (*KDFHeader, error) {
	env, err := parseEnvelope(data)
	if err != nil {
		return nil, err
	}
	return env.KDF, nil
}

func parseEnvelope(data []byte) (*envelope, error) {
	var env envelope
	if err := json.Unmarshal(data, &env); err != nil {
		return nil, fmt.Errorf("not a kilovault sealed file: %v", err)
	}
	if env.Version != envelopeVersion {
		return nil, fmt.Errorf("unsupported sealed file version %d", env.Version)
	}
	return &env, nil
}

// Open decrypts a file produced by Seal. It fails unless the file is
// bound to exactly want, was sealed with key, and is unmodified. The
// returned plaintext should be wiped by the caller when done.
func Open(key []byte, want Binding, data []byte) ([]byte, error) {
	env, err := parseEnvelope(data)
	if err != nil {
		return nil, err
	}
	if env.Binding != want {
		return nil, fmt.Errorf("file is sealed as %s %q, expected %s %q", env.Binding.Purpose, env.Binding.Name, want.Purpose, want.Name)
	}
	gcm, err := newGCM(key)
	if err != nil {
		return nil, err
	}
	if len(env.Nonce) != gcm.NonceSize() {
		return nil, ErrDecrypt
	}
	ad, err := env.additionalData()
	if err != nil {
		return nil, err
	}
	plaintext, err := gcm.Open(nil, env.Nonce, env.Ciphertext, ad)
	if err != nil {
		return nil, ErrDecrypt
	}
	return plaintext, nil
}
