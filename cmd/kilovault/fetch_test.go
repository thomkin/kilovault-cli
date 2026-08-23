package main

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// runKV runs the kilovault binary with an explicit HOME (so callers can
// share one config directory across several invocations, e.g. `config set`
// followed by `fetch`) plus any extra env vars.
func runKV(t *testing.T, home string, extraEnv []string, args ...string) (stdout, stderr string, err error) {
	t.Helper()
	cmd := exec.Command(binPath, args...)
	cmd.Env = append(append(os.Environ(), "HOME="+home), extraEnv...)

	var outBuf, errBuf strings.Builder
	cmd.Stdout = &outBuf
	cmd.Stderr = &errBuf
	err = cmd.Run()
	return outBuf.String(), errBuf.String(), err
}

func setupConfig(t *testing.T, home string, args ...string) {
	t.Helper()
	full := append([]string{"config", "set"}, args...)
	if _, stderr, err := runKV(t, home, nil, full...); err != nil {
		t.Fatalf("config set %v failed: %v\n%s", args, err, stderr)
	}
}

func runFetchCmd(t *testing.T, home, runtimeDir string, extraEnv []string) (stdout, stderr string, err error) {
	t.Helper()
	env := append([]string{"RUNTIME_DIRECTORY=" + runtimeDir}, extraEnv...)
	return runKV(t, home, env, "fetch")
}

func TestFetch_NoSyncKeysConfiguredErrors(t *testing.T) {
	home := t.TempDir()
	runtimeDir := t.TempDir()

	_, stderr, err := runFetchCmd(t, home, runtimeDir, nil)
	if err == nil {
		t.Fatalf("expected error when no sync-keys configured, got none")
	}
	if !strings.Contains(stderr, "no sync-keys configured") {
		t.Errorf("stderr = %q, want it to mention 'no sync-keys configured'", stderr)
	}
}

func TestFetch_WritesAllThreeFiles(t *testing.T) {
	store := map[string]string{
		"db_password": "hunter2",
		"api_key":     "abc123",
	}
	server := newFakeVaultServer(store)
	defer server.Close()

	home := t.TempDir()
	runtimeDir := t.TempDir()
	setupConfig(t, home, "endpoint", server.URL)
	setupConfig(t, home, "sync-keys", `[{"key":"db_password","as":"DB_PASSWORD"},{"key":"api_key"}]`)

	stdout, stderr, err := runFetchCmd(t, home, runtimeDir, nil)
	if err != nil {
		t.Fatalf("fetch failed: %v\n%s", err, stderr)
	}
	if !strings.Contains(stdout, "Fetched 2 key(s)") {
		t.Errorf("stdout = %q, want it to mention 2 keys fetched", stdout)
	}

	envData, err := os.ReadFile(filepath.Join(runtimeDir, ".env"))
	if err != nil {
		t.Fatalf("failed to read .env: %v", err)
	}
	if !strings.Contains(string(envData), `DB_PASSWORD="hunter2"`) {
		t.Errorf(".env missing DB_PASSWORD entry, got:\n%s", envData)
	}
	if !strings.Contains(string(envData), `api_key="abc123"`) {
		t.Errorf(".env missing api_key entry, got:\n%s", envData)
	}

	yamlData, err := os.ReadFile(filepath.Join(runtimeDir, "env.yaml"))
	if err != nil {
		t.Fatalf("failed to read env.yaml: %v", err)
	}
	if !strings.Contains(string(yamlData), "DB_PASSWORD: hunter2") {
		t.Errorf("env.yaml missing DB_PASSWORD entry, got:\n%s", yamlData)
	}

	factsData, err := os.ReadFile(filepath.Join(runtimeDir, "kilovault.fact"))
	if err != nil {
		t.Fatalf("failed to read kilovault.fact: %v", err)
	}
	if !strings.Contains(string(factsData), `"DB_PASSWORD": "hunter2"`) {
		t.Errorf("kilovault.fact missing DB_PASSWORD entry, got:\n%s", factsData)
	}

	// output files must not be left world-readable
	info, err := os.Stat(filepath.Join(runtimeDir, ".env"))
	if err != nil {
		t.Fatalf("failed to stat .env: %v", err)
	}
	if info.Mode().Perm() != 0640 {
		t.Errorf(".env mode = %v, want 0640", info.Mode().Perm())
	}
}

func TestFetch_MissingKeyOnServerErrors(t *testing.T) {
	store := map[string]string{"present_key": "value"}
	server := newFakeVaultServer(store)
	defer server.Close()

	home := t.TempDir()
	runtimeDir := t.TempDir()
	setupConfig(t, home, "endpoint", server.URL)
	setupConfig(t, home, "sync-keys", `[{"key":"absent_key"}]`)

	_, stderr, err := runFetchCmd(t, home, runtimeDir, nil)
	if err == nil {
		t.Fatalf("expected error for a key not set on the server, got none")
	}
	if !strings.Contains(stderr, "key not set on server") {
		t.Errorf("stderr = %q, want it to mention 'key not set on server'", stderr)
	}

	// no partial output on failure
	if entries, _ := os.ReadDir(runtimeDir); len(entries) != 0 {
		t.Errorf("expected no output files written on failure, found: %v", entries)
	}
}

func TestFetch_DecryptionFailureErrors(t *testing.T) {
	store := map[string]string{}
	server := newFakeVaultServer(store)
	defer server.Close()

	home := t.TempDir()
	runtimeDir := t.TempDir()
	setupConfig(t, home, "endpoint", server.URL)

	// Encrypt with one secret via `set`, then configure fetch with a
	// different one, so decryption must fail.
	if _, stderr, err := runKV(t, home, nil, "-e", server.URL, "set", "-k", "secret_key", "-v", "topsecret", "-s", "right-secret"); err != nil {
		t.Fatalf("set failed: %v\n%s", err, stderr)
	}
	setupConfig(t, home, "secret", "wrong-secret")
	setupConfig(t, home, "sync-keys", `[{"key":"secret_key"}]`)

	_, stderr, err := runFetchCmd(t, home, runtimeDir, nil)
	if err == nil {
		t.Fatalf("expected error decrypting with the wrong secret, got none")
	}
	if !strings.Contains(stderr, "decrypt") {
		t.Errorf("stderr = %q, want it to mention decryption failure", stderr)
	}
}

func TestFetch_EncryptedValueDecryptsCorrectly(t *testing.T) {
	store := map[string]string{}
	server := newFakeVaultServer(store)
	defer server.Close()

	home := t.TempDir()
	runtimeDir := t.TempDir()
	setupConfig(t, home, "endpoint", server.URL)

	if _, stderr, err := runKV(t, home, nil, "-e", server.URL, "set", "-k", "secret_key", "-v", "topsecret", "-s", "the-secret"); err != nil {
		t.Fatalf("set failed: %v\n%s", err, stderr)
	}
	setupConfig(t, home, "secret", "the-secret")
	setupConfig(t, home, "sync-keys", `[{"key":"secret_key","as":"SECRET_KEY"}]`)

	_, stderr, err := runFetchCmd(t, home, runtimeDir, nil)
	if err != nil {
		t.Fatalf("fetch failed: %v\n%s", err, stderr)
	}

	envData, err := os.ReadFile(filepath.Join(runtimeDir, ".env"))
	if err != nil {
		t.Fatalf("failed to read .env: %v", err)
	}
	if !strings.Contains(string(envData), `SECRET_KEY="topsecret"`) {
		t.Errorf(".env = %q, want decrypted SECRET_KEY=topsecret", envData)
	}
}

func TestFetch_InvalidOutputEnvNameErrors(t *testing.T) {
	store := map[string]string{"some_key": "value"}
	server := newFakeVaultServer(store)
	defer server.Close()

	home := t.TempDir()
	runtimeDir := t.TempDir()
	setupConfig(t, home, "endpoint", server.URL)
	setupConfig(t, home, "sync-keys", `[{"key":"some_key","as":"bad-name!"}]`)

	_, stderr, err := runFetchCmd(t, home, runtimeDir, nil)
	if err == nil {
		t.Fatalf("expected error for invalid output env-var name, got none")
	}
	if !strings.Contains(stderr, "not a valid environment variable name") {
		t.Errorf("stderr = %q, want it to mention the invalid name", stderr)
	}
}

func TestFetch_DefaultsToRunDirWhenRuntimeDirectoryUnset(t *testing.T) {
	// Doesn't assert on the actual default path (would need write access to
	// /run) — just confirms fetch reaches the network call (and fails there,
	// against an address nothing listens on) rather than erroring out
	// earlier for lack of a runtime directory env var.
	home := t.TempDir()
	setupConfig(t, home, "sync-keys", `[{"key":"whatever"}]`)

	_, stderr, err := runKV(t, home, nil, "-e", "http://127.0.0.1:0", "fetch")
	if err == nil {
		t.Fatalf("expected error (connection failure), got none")
	}
	if !strings.Contains(stderr, "request failed") {
		t.Errorf("stderr = %q, want it to mention the request failure", stderr)
	}
}
