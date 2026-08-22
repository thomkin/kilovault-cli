package client

import "testing"

func TestEncryptDecrypt_RoundTrip(t *testing.T) {
	secret := "correct-secret"
	plaintext := "hello world"

	encrypted, err := Encrypt(secret, plaintext)
	if err != nil {
		t.Fatalf("Encrypt returned error: %v", err)
	}

	if !IsEncrypted(encrypted) {
		t.Fatalf("expected IsEncrypted(%q) to be true", encrypted)
	}

	decrypted, err := Decrypt(secret, encrypted)
	if err != nil {
		t.Fatalf("Decrypt returned error: %v", err)
	}
	if decrypted != plaintext {
		t.Errorf("decrypted = %q, want %q", decrypted, plaintext)
	}
}

func TestEncrypt_NonDeterministic(t *testing.T) {
	secret := "s"
	a, err := Encrypt(secret, "same-plaintext")
	if err != nil {
		t.Fatalf("Encrypt returned error: %v", err)
	}
	b, err := Encrypt(secret, "same-plaintext")
	if err != nil {
		t.Fatalf("Encrypt returned error: %v", err)
	}
	if a == b {
		t.Errorf("expected different ciphertexts for two calls (random nonce), got identical: %q", a)
	}
}

func TestDecrypt_WrongSecretErrors(t *testing.T) {
	encrypted, err := Encrypt("right-secret", "sensitive-value")
	if err != nil {
		t.Fatalf("Encrypt returned error: %v", err)
	}

	_, err = Decrypt("wrong-secret", encrypted)
	if err == nil {
		t.Fatalf("expected error decrypting with wrong secret, got none")
	}
}

func TestDecrypt_TamperedValueErrors(t *testing.T) {
	encrypted, err := Encrypt("secret", "sensitive-value")
	if err != nil {
		t.Fatalf("Encrypt returned error: %v", err)
	}

	tampered := encrypted[:len(encrypted)-1] + "x"
	_, err = Decrypt("secret", tampered)
	if err == nil {
		t.Fatalf("expected error decrypting tampered value, got none")
	}
}

func TestDecrypt_NotEncryptedErrors(t *testing.T) {
	_, err := Decrypt("secret", "plain-value")
	if err == nil {
		t.Fatalf("expected error decrypting a non-encrypted value, got none")
	}
}

func TestIsEncrypted(t *testing.T) {
	cases := map[string]bool{
		"enc:v1:abcd": true,
		"plain-value": false,
		"":            false,
	}
	for value, want := range cases {
		if got := IsEncrypted(value); got != want {
			t.Errorf("IsEncrypted(%q) = %v, want %v", value, got, want)
		}
	}
}
