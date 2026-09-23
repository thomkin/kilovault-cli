package main

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/thomkin/kilovault-cli/pkg/client"
)

const (
	testMasterPW = "correct horse battery"
	testToken    = "admin.token.value"
)

// runCLIHome runs the CLI with a caller-controlled HOME (so the
// credentials store persists across calls) and stdin (one line per prompt,
// since stdin isn't a terminal in tests).
func runCLIHome(t *testing.T, home string, env []string, stdin string, args ...string) (string, string, error) {
	t.Helper()
	cmd := exec.Command(binPath, args...)
	cmd.Env = append(append(os.Environ(), "HOME="+home), env...)
	cmd.Stdin = strings.NewReader(stdin)
	var outBuf, errBuf strings.Builder
	cmd.Stdout = &outBuf
	cmd.Stderr = &errBuf
	err := cmd.Run()
	return outBuf.String(), errBuf.String(), err
}

func masterEnv(pw string) []string {
	return []string{masterPasswordEnv + "=" + pw}
}

func credsPath(home string) string {
	return filepath.Join(home, ".config", "kilovault", "credentials.enc")
}

// initStore runs `init` against server with the test token and password.
func initStore(t *testing.T, serverURL string) string {
	t.Helper()
	home := t.TempDir()
	stdin := "\n" + testToken + "\n" + testMasterPW + "\n" + testMasterPW + "\n"
	if _, stderr, err := runCLIHome(t, home, nil, stdin, "-e", serverURL, "init"); err != nil {
		t.Fatalf("init failed: %v\n%s", err, stderr)
	}
	return home
}

func TestInit_CreatesEncryptedStore(t *testing.T) {
	server := newFakeBatchServer(map[string]string{})
	defer server.Close()
	home := initStore(t, server.URL)

	data, err := os.ReadFile(credsPath(home))
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(data), testToken) {
		t.Fatal("admin token stored in plaintext")
	}
	if info, _ := os.Stat(credsPath(home)); info.Mode().Perm() != 0600 {
		t.Errorf("credentials.enc mode = %04o", info.Mode().Perm())
	}

	cfgData, _ := os.ReadFile(filepath.Join(home, ".config", "kilovault", "config.json"))
	var cfg client.Config
	json.Unmarshal(cfgData, &cfg)
	if cfg.Endpoint != server.URL || cfg.Token != "" || cfg.Secret != "" {
		t.Errorf("config.json = %s, want only the endpoint", cfgData)
	}

	stdout, stderr, err := runCLIHome(t, home, masterEnv(testMasterPW), "", "credentials", "list")
	if err != nil {
		t.Fatalf("list failed: %v\n%s", err, stderr)
	}
	for _, want := range []string{"Admin token: set", "Profile secrets: none", "Last backup: never"} {
		if !strings.Contains(stdout, want) {
			t.Errorf("list output missing %q:\n%s", want, stdout)
		}
	}
	if strings.Contains(stdout, testToken) {
		t.Error("list printed the admin token")
	}

	if _, _, err := runCLIHome(t, home, nil, "\n"+testToken+"\n"+testMasterPW+"\n"+testMasterPW+"\n", "-e", server.URL, "init"); err == nil {
		t.Error("second init should refuse to overwrite the store")
	}
}

func TestInit_RejectsBadInput(t *testing.T) {
	good := newFakeBatchServer(map[string]string{})
	defer good.Close()
	denying := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		json.NewEncoder(w).Encode(map[string]interface{}{"error": map[string]string{"code": "forbidden"}, "message": "forbidden"})
	}))
	defer denying.Close()

	cases := []struct {
		name, url, stdin, wantErr string
	}{
		{"token rejected by server", denying.URL, "\n" + testToken + "\n" + testMasterPW + "\n" + testMasterPW + "\n", "admin token check"},
		{"passwords differ", good.URL, "\n" + testToken + "\n" + testMasterPW + "\nsomething else entirely\n", "don't match"},
		{"password too short", good.URL, "\n" + testToken + "\nshort\nshort\n", "at least 12"},
	}
	for _, tc := range cases {
		home := t.TempDir()
		_, stderr, err := runCLIHome(t, home, nil, tc.stdin, "-e", tc.url, "init")
		if err == nil || !strings.Contains(stderr, tc.wantErr) {
			t.Errorf("%s: err=%v stderr=%s, want %q", tc.name, err, stderr, tc.wantErr)
		}
		if _, statErr := os.Stat(credsPath(home)); statErr == nil {
			t.Errorf("%s: store created despite failure", tc.name)
		}
	}
}

func TestCredentials_WrongMasterPassword(t *testing.T) {
	server := newFakeBatchServer(map[string]string{})
	defer server.Close()
	home := initStore(t, server.URL)

	_, stderr, err := runCLIHome(t, home, masterEnv("wrong password here"), "", "credentials", "list")
	if err == nil || !strings.Contains(stderr, "wrong master password") {
		t.Errorf("err=%v stderr=%s", err, stderr)
	}
}

func TestCredentials_RefusesLoosePermissions(t *testing.T) {
	server := newFakeBatchServer(map[string]string{})
	defer server.Close()
	home := initStore(t, server.URL)

	os.Chmod(credsPath(home), 0644)
	_, stderr, err := runCLIHome(t, home, masterEnv(testMasterPW), "", "credentials", "list")
	if err == nil || !strings.Contains(stderr, "chmod 600") {
		t.Errorf("err=%v stderr=%s", err, stderr)
	}
}

func TestCredentials_SetSecretVerifiesAgainstVault(t *testing.T) {
	encrypted, err := client.Encrypt("alice-secret", "value")
	if err != nil {
		t.Fatal(err)
	}
	store := map[string]string{"alice/plain": "not encrypted", "alice/K": encrypted}
	server := newFakeBatchServer(store)
	defer server.Close()
	home := initStore(t, server.URL)
	env := masterEnv(testMasterPW)

	_, stderr, err := runCLIHome(t, home, env, "not-the-secret\n", "credentials", "set-secret", "-u", "alice")
	if err == nil || !strings.Contains(stderr, "doesn't decrypt") {
		t.Fatalf("wrong secret: err=%v stderr=%s", err, stderr)
	}

	if _, stderr, err := runCLIHome(t, home, env, "alice-secret\n", "credentials", "set-secret", "-u", "alice"); err != nil {
		t.Fatalf("set-secret failed: %v\n%s", err, stderr)
	}

	stdout, _, _ := runCLIHome(t, home, env, "", "credentials", "list")
	if !strings.Contains(stdout, "Profile secrets: alice") || strings.Contains(stdout, "alice-secret") {
		t.Errorf("list output:\n%s", stdout)
	}

	stdout, stderr, err = runCLIHome(t, home, env, "", "credentials", "show-secret", "-u", "alice")
	if err != nil || strings.TrimSpace(stdout) != "alice-secret" {
		t.Errorf("show-secret = %q, %v\n%s", stdout, err, stderr)
	}

	if _, stderr, err := runCLIHome(t, home, env, "", "credentials", "remove-secret", "-u", "alice"); err != nil {
		t.Fatalf("remove-secret failed: %v\n%s", err, stderr)
	}
	if _, _, err := runCLIHome(t, home, env, "", "credentials", "show-secret", "-u", "alice"); err == nil {
		t.Error("secret still present after remove-secret")
	}
}

func TestCredentials_GenerateSecretForNewProfile(t *testing.T) {
	server := newFakeBatchServer(map[string]string{})
	defer server.Close()
	home := initStore(t, server.URL)
	env := masterEnv(testMasterPW)

	_, stderr, err := runCLIHome(t, home, env, "", "credentials", "set-secret", "-u", "carol", "--generate")
	if err != nil {
		t.Fatalf("set-secret --generate failed: %v\n%s", err, stderr)
	}
	if !strings.Contains(stderr, "no encrypted values") {
		t.Errorf("expected unverified warning, stderr=%s", stderr)
	}
	stdout, _, _ := runCLIHome(t, home, env, "", "credentials", "show-secret", "-u", "carol")
	if len(strings.TrimSpace(stdout)) != 43 { // 32 bytes, unpadded base64url
		t.Errorf("generated secret = %q", stdout)
	}
}

func TestCredentials_Passwd(t *testing.T) {
	server := newFakeBatchServer(map[string]string{})
	defer server.Close()
	home := initStore(t, server.URL)
	newPW := "a brand new master password"

	if _, stderr, err := runCLIHome(t, home, masterEnv(testMasterPW), newPW+"\n"+newPW+"\n", "credentials", "passwd"); err != nil {
		t.Fatalf("passwd failed: %v\n%s", err, stderr)
	}
	if _, _, err := runCLIHome(t, home, masterEnv(testMasterPW), "", "credentials", "list"); err == nil {
		t.Error("old password still works")
	}
	if stdout, stderr, err := runCLIHome(t, home, masterEnv(newPW), "", "credentials", "list"); err != nil || !strings.Contains(stdout, "Admin token: set") {
		t.Errorf("new password: %v\n%s%s", err, stdout, stderr)
	}
}

func TestCredentials_BackupAndRestore(t *testing.T) {
	server := newFakeBatchServer(map[string]string{})
	defer server.Close()
	home := initStore(t, server.URL)
	env := masterEnv(testMasterPW)
	recovery := "offline recovery passphrase"
	backup := filepath.Join(t.TempDir(), "creds.backup")

	if _, stderr, err := runCLIHome(t, home, env, "", "credentials", "set-secret", "-u", "carol", "--generate"); err != nil {
		t.Fatalf("set-secret: %v\n%s", err, stderr)
	}
	secretBefore, _, _ := runCLIHome(t, home, env, "", "credentials", "show-secret", "-u", "carol")

	if _, stderr, err := runCLIHome(t, home, env, recovery+"\n"+recovery+"\n", "credentials", "backup", "-o", backup); err != nil {
		t.Fatalf("backup failed: %v\n%s", err, stderr)
	}
	if _, _, err := runCLIHome(t, home, env, recovery+"\n"+recovery+"\n", "credentials", "backup", "-o", backup); err == nil {
		t.Error("backup overwrote an existing file")
	}
	if stdout, _, _ := runCLIHome(t, home, env, "", "credentials", "list"); strings.Contains(stdout, "Last backup: never") {
		t.Errorf("backup time not recorded:\n%s", stdout)
	}

	// Lose the store, then restore it under a new master password.
	os.Remove(credsPath(home))

	_, stderr, err := runCLIHome(t, home, nil, "wrong recovery passphrase\n", "credentials", "restore", "-i", backup)
	if err == nil || !strings.Contains(stderr, "wrong recovery passphrase") {
		t.Fatalf("wrong recovery passphrase: err=%v stderr=%s", err, stderr)
	}

	newPW := "restored master password"
	if _, stderr, err := runCLIHome(t, home, nil, recovery+"\n"+newPW+"\n"+newPW+"\n", "credentials", "restore", "-i", backup); err != nil {
		t.Fatalf("restore failed: %v\n%s", err, stderr)
	}
	secretAfter, stderr, err := runCLIHome(t, home, masterEnv(newPW), "", "credentials", "show-secret", "-u", "carol")
	if err != nil || secretAfter != secretBefore {
		t.Errorf("secret after restore = %q (want %q), %v\n%s", secretAfter, secretBefore, err, stderr)
	}
	if _, _, err := runCLIHome(t, home, nil, recovery+"\n"+newPW+"\n"+newPW+"\n", "credentials", "restore", "-i", backup); err == nil {
		t.Error("restore overwrote an existing store")
	}
}

func TestCredentials_NotInitialized(t *testing.T) {
	_, stderr, err := runCLIHome(t, t.TempDir(), masterEnv(testMasterPW), "", "credentials", "list")
	if err == nil || !strings.Contains(stderr, "kilovault init") {
		t.Errorf("err=%v stderr=%s", err, stderr)
	}
}
