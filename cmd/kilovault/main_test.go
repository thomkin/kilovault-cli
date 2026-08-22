package main

import (
	"encoding/base64"
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// binPath is set by TestMain to a freshly-built kilovault binary.
var binPath string

func TestMain(m *testing.M) {
	dir, err := os.MkdirTemp("", "kilovault-cli-test-bin")
	if err != nil {
		panic(err)
	}

	binPath = filepath.Join(dir, "kilovault")
	build := exec.Command("go", "build", "-o", binPath, ".")
	build.Dir = "."
	if out, err := build.CombinedOutput(); err != nil {
		os.RemoveAll(dir)
		panic("failed to build kilovault binary: " + err.Error() + "\n" + string(out))
	}

	code := m.Run()
	os.RemoveAll(dir)
	os.Exit(code)
}

// runTokenLocal runs `kilovault token local <args...>` with JWT_SECRET set
// and HOME pointed at a fresh temp dir, so --save never touches the real
// user config.
func runTokenLocal(t *testing.T, args ...string) (stdout string, stderr string, err error) {
	t.Helper()

	home := t.TempDir()
	cmdArgs := append([]string{"token", "local"}, args...)
	cmd := exec.Command(binPath, cmdArgs...)
	cmd.Env = append(os.Environ(), "HOME="+home, "JWT_SECRET=test-secret")

	var outBuf, errBuf strings.Builder
	cmd.Stdout = &outBuf
	cmd.Stderr = &errBuf
	err = cmd.Run()

	return outBuf.String(), errBuf.String(), err
}

type jwtPayload struct {
	Sub         string          `json:"sub"`
	Permissions map[string]bool `json:"permissions"`
}

func decodeToken(t *testing.T, token string) jwtPayload {
	t.Helper()
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		t.Fatalf("malformed token, expected 3 parts, got %d: %q", len(parts), token)
	}
	raw, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		t.Fatalf("failed to base64-decode payload: %v", err)
	}
	var p jwtPayload
	if err := json.Unmarshal(raw, &p); err != nil {
		t.Fatalf("failed to unmarshal payload: %v", err)
	}
	return p
}

func TestTokenLocal_FlagOrderIndependence(t *testing.T) {
	cases := []struct {
		name string
		args []string
	}{
		{
			name: "user first, then permissions/save/expires",
			args: []string{"-u", "admin-user", "-p", `{"admin":true,"history.get":true}`, "-S", "-e", "3600"},
		},
		{
			name: "save/expires/permissions first, user last",
			args: []string{"-S", "-e", "3600", "-p", `{"admin":true,"history.get":true}`, "-u", "admin-user"},
		},
		{
			name: "permissions, save, user, expires interleaved",
			args: []string{"-p", `{"admin":true,"history.get":true}`, "-S", "-u", "admin-user", "-e", "3600"},
		},
		{
			name: "long-form flags",
			args: []string{"--permissions", `{"admin":true,"history.get":true}`, "--save", "--user", "admin-user", "--expires", "3600"},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			stdout, stderr, err := runTokenLocal(t, tc.args...)
			if err != nil {
				t.Fatalf("unexpected error: %v\nstdout: %s\nstderr: %s", err, stdout, stderr)
			}

			token := strings.TrimSpace(stdout)
			payload := decodeToken(t, token)

			if payload.Sub != "admin-user" {
				t.Errorf("sub = %q, want %q", payload.Sub, "admin-user")
			}
			if !payload.Permissions["admin"] || !payload.Permissions["history.get"] {
				t.Errorf("permissions = %v, want admin=true, history.get=true", payload.Permissions)
			}
			if !strings.Contains(stderr, "Token saved") {
				t.Errorf("expected save confirmation on stderr, got: %q", stderr)
			}
		})
	}
}

func TestTokenLocal_MissingUserFlag(t *testing.T) {
	_, stderr, err := runTokenLocal(t, "-p", `{"admin":true}`)
	if err == nil {
		t.Fatalf("expected error when -u/--user is omitted, got none")
	}
	if !strings.Contains(stderr, "user id required") {
		t.Errorf("stderr = %q, want it to mention 'user id required'", stderr)
	}
}

func TestTokenLocal_StrayPositionalArgErrors(t *testing.T) {
	_, stderr, err := runTokenLocal(t, "-u", "admin-user", "-p", `{"admin":true}`, "extra-arg")
	if err == nil {
		t.Fatalf("expected error on stray positional argument, got none")
	}
	if !strings.Contains(stderr, "unexpected argument") {
		t.Errorf("stderr = %q, want it to mention 'unexpected argument'", stderr)
	}
}

func TestTokenLocal_OldPositionalStyleNowErrors(t *testing.T) {
	// Pre-fix usage: `token local <userId> -p ...`. The positional userId
	// is gone, so this must fail loudly instead of silently minting a
	// token with an empty/wrong sub and dropped permissions.
	_, stderr, err := runTokenLocal(t, "admin-user", "-p", `{"admin":true}`)
	if err == nil {
		t.Fatalf("expected error for old positional-only usage, got none")
	}
	if stderr == "" {
		t.Errorf("expected a non-empty error message")
	}
}

func TestTokenLocal_NoPermissionsGivenDefaultsEmpty(t *testing.T) {
	stdout, _, err := runTokenLocal(t, "-u", "plain-user")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	payload := decodeToken(t, strings.TrimSpace(stdout))
	if payload.Sub != "plain-user" {
		t.Errorf("sub = %q, want %q", payload.Sub, "plain-user")
	}
	if len(payload.Permissions) != 0 {
		t.Errorf("permissions = %v, want empty", payload.Permissions)
	}
}

func TestTokenLocal_InvalidPermissionsJSON(t *testing.T) {
	_, stderr, err := runTokenLocal(t, "-u", "admin-user", "-p", "not-json")
	if err == nil {
		t.Fatalf("expected error for invalid permissions JSON, got none")
	}
	if !strings.Contains(stderr, "invalid permissions JSON") {
		t.Errorf("stderr = %q, want it to mention 'invalid permissions JSON'", stderr)
	}
}
